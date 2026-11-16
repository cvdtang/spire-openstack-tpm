// Command openstack-tpm-swtpm is swtpm_setup's create_certs_tool, which has the issuer certify a vTPM's ECC P-384 EK.
// Any failure exits non-zero, so the vTPM and the build fail closed.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/token"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/issuerapi"
)

// defaultConfig is where the Kolla bind mount puts the config in nova_libvirt.
const defaultConfig = "/etc/openstack-tpm/openstack-tpm-swtpm.conf"

// args are the options of swtpm_setup's call that the hook uses.
type args struct{ typ, ek, dir, vmid, configfile, logfile string }

// parseArgs reads the options swtpm_setup passes to its create_certs_tool and refuses any other argument.
func parseArgs(argv []string) (*args, error) {
	fs := flag.NewFlagSet("openstack-tpm-swtpm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	a := &args{}
	fs.StringVar(&a.typ, "type", "", "")
	fs.StringVar(&a.ek, "ek", "", "")
	fs.StringVar(&a.dir, "dir", "", "")
	fs.StringVar(&a.vmid, "vmid", "", "")
	fs.StringVar(&a.configfile, "configfile", defaultConfig, "")
	fs.StringVar(&a.logfile, "logfile", "", "")
	// Passed by swtpm_setup and not needed here.
	for _, name := range []string{"optsfile", "tpm-spec-family", "tpm-spec-level", "tpm-spec-revision", "tpm-manufacturer", "tpm-model", "tpm-version"} {
		fs.String(name, "", "")
	}
	for _, name := range []string{"tpm2", "allow-signing", "decryption"} {
		fs.Bool(name, false, "")
	}
	if err := fs.Parse(argv); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return a, nil
}

type config struct {
	url, cert, key, ca string
}

func readConfig(file string) (*config, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var f struct {
		URL     string                 `hcl:"url"`
		Cert    string                 `hcl:"cert"`
		Key     string                 `hcl:"key"`
		CA      string                 `hcl:"ca"`
		Unknown map[string][]token.Pos `hcl:",unusedKeyPositions"`
	}
	if err := hcl.Decode(&f, string(b)); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if len(f.Unknown) > 0 {
		return nil, fmt.Errorf("%s: unknown keys %v", file, slices.Sorted(maps.Keys(f.Unknown)))
	}
	c := &config{url: f.URL, cert: f.Cert, key: f.Key, ca: f.CA}
	for _, v := range []struct{ key, value string }{{"url", c.url}, {"cert", c.cert}, {"key", c.key}, {"ca", c.ca}} {
		if v.value == "" {
			return nil, fmt.Errorf("%s: %s is required", file, v.key)
		}
	}
	if !strings.HasPrefix(c.url, "https://") {
		return nil, fmt.Errorf("%s: url must be https", file)
	}
	return c, nil
}

// logger writes to stderr (swtpm_setup's log) and the --logfile, if any.
type logger struct{ w io.Writer }

func (l *logger) printf(format string, a ...any) {
	fmt.Fprintf(l.w, "openstack-tpm-swtpm: "+format+"\n", a...)
}

func main() {
	log := &logger{os.Stderr}
	if err := run(os.Args[1:], log); err != nil {
		log.printf("error: %v", err)
		os.Exit(1)
	}
}

func run(argv []string, log *logger) error {
	a, err := parseArgs(argv)
	if err != nil {
		return err
	}
	if a.logfile != "" {
		f, err := os.OpenFile(a.logfile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			return fmt.Errorf("--logfile: %w", err)
		}
		defer f.Close()
		log.w = io.MultiWriter(os.Stderr, f)
	}
	cfg, err := readConfig(a.configfile)
	if err != nil {
		return err
	}
	switch {
	case a.typ == "platform":
		return writeLocal(a, "platform.cert", log)
	case a.typ != "ek":
		return fmt.Errorf("--type %q", a.typ)
	case !isECC(a.ek):
		return writeLocal(a, "ek.cert", log)
	}
	return issue(a, cfg, log)
}

// issue has the issuer certify the ECC P-384 EK and writes the certificate to <dir>/ek.cert.
func issue(a *args, cfg *config, log *logger) error {
	req, err := request(a)
	if err != nil {
		return err
	}
	client, err := httpClient(cfg)
	if err != nil {
		return err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	der, err := post(client, cfg.url, body)
	if err != nil {
		return fmt.Errorf("%s: %w", req.InstanceUUID, err)
	}
	if err := writeAtomic(filepath.Join(a.dir, "ek.cert"), der); err != nil {
		return err
	}
	log.printf("%s (%s): certificate issued for the ECC P-384 EK (%d bytes)", req.InstanceUUID, a.vmid, len(der))
	return nil
}

// request builds the issuer request from swtpm_setup's arguments.
func request(a *args) (*issuerapi.VMCertificateRequest, error) {
	if a.vmid == "" || a.dir == "" || a.ek == "" {
		return nil, errors.New("--vmid, --dir and --ek are required")
	}
	id := a.vmid[strings.LastIndex(a.vmid, ":")+1:]
	if !contract.ValidUUID(id) {
		return nil, fmt.Errorf("--vmid %q does not end in an instance UUID", a.vmid)
	}
	if _, err := contract.ParsePoint(a.ek); err != nil {
		return nil, fmt.Errorf("--ek: %w", err)
	}
	return &issuerapi.VMCertificateRequest{InstanceUUID: id, Key: a.ek}, nil
}

// writeLocal makes an untrusted local certificate and writes it to <dir>/<name>.
func writeLocal(a *args, name string, log *logger) error {
	if a.dir == "" {
		return errors.New("--dir is required")
	}
	der, err := localCert(a)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := writeAtomic(filepath.Join(a.dir, name), der); err != nil {
		return err
	}
	log.printf("%s: %s created locally, untrusted (%d bytes)", a.vmid, name, len(der))
	return nil
}

// writeAtomic writes file via a temp file in the same directory, so swtpm never reads a partial certificate.
func writeAtomic(file string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(file), "."+filepath.Base(file)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after the rename
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), file)
}

// isECC reports whether swtpm's --ek argument is an ECC point rather than an RSA modulus.
func isECC(ek string) bool {
	return strings.HasPrefix(ek, "x=") || strings.Contains(ek, ",x=")
}

func httpClient(cfg *config) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(cfg.cert, cfg.key)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(cfg.ca)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("%s: no certificates", cfg.ca)
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13},
	}}, nil
}

func post(c *http.Client, url string, body []byte) ([]byte, error) {
	resp, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if _, err := x509.ParseCertificate(b); err != nil {
		return nil, fmt.Errorf("issuer returned an invalid certificate: %w", err)
	}
	return b, nil
}
