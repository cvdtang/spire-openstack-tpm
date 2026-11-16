// Command openstack-tpm-ipa does the TPM work of a bare-metal node's inspection, deploy and clean steps in the IPA ramdisk.
// It prints one JSON object and exits non-zero on any failure, which fails the step.
package main

import (
	"bytes"
	"context"
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
	"slices"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/token"

	"github.com/cvdtang/openstack-tpm/internal/issuerapi"
	"github.com/cvdtang/openstack-tpm/internal/tpmprov"
)

// defaultConfig is where the ramdisk overlay puts the config.
const defaultConfig = "/etc/openstack-tpm/ipa.conf"

type config struct {
	url, ca, tpm string
	timeout      time.Duration
}

func readConfig(file string) (*config, error) {
	c := &config{timeout: 60 * time.Second}
	b, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil // enough for `ek`
	} else if err != nil {
		return nil, err
	}
	var f struct {
		URL     string                 `hcl:"url"`
		CA      string                 `hcl:"ca"`
		TPM     string                 `hcl:"tpm"`
		Timeout string                 `hcl:"timeout"`
		Unknown map[string][]token.Pos `hcl:",unusedKeyPositions"`
	}
	if err := hcl.Decode(&f, string(b)); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if len(f.Unknown) > 0 {
		return nil, fmt.Errorf("%s: unknown keys %v", file, slices.Sorted(maps.Keys(f.Unknown)))
	}
	c.url, c.ca, c.tpm = strings.TrimRight(f.URL, "/"), f.CA, f.TPM
	if f.Timeout != "" {
		if c.timeout, err = time.ParseDuration(f.Timeout); err != nil || c.timeout <= 0 {
			return nil, fmt.Errorf("%s: timeout %q", file, f.Timeout)
		}
	}
	return c, nil
}

func openTPM(dev string) (transport.TPMCloser, error) {
	paths := []string{"/dev/tpmrm0", "/dev/tpm0"}
	if dev != "" {
		paths = []string{dev}
	}
	var last error
	for _, p := range paths {
		t, err := linuxtpm.Open(p)
		if err == nil {
			return t, nil
		}
		last = err
	}
	return nil, fmt.Errorf("open the TPM: %w", last)
}

// client is the issuer as the steps use it.
type client struct {
	base string
	http *http.Client
}

func newClient(c *config) (*client, error) {
	if c.url == "" || c.ca == "" {
		return nil, errors.New("the config needs url and ca")
	}
	if !strings.HasPrefix(c.url, "https://") {
		return nil, errors.New("url must be https")
	}
	ca, err := os.ReadFile(c.ca)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("%s: no certificates", c.ca)
	}
	return &client{base: c.url, http: &http.Client{Timeout: c.timeout, Transport: &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
	}}}, nil
}

func (c *client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rsp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(rsp.Body, 1<<20))
	if err != nil {
		return err
	}
	if rsp.StatusCode != http.StatusOK {
		var e issuerapi.Error
		if json.Unmarshal(b, &e) == nil && e.Code != "" {
			return fmt.Errorf("issuer refused (%s): %s", e.Code, e.Message)
		}
		return fmt.Errorf("issuer: %s: %s", rsp.Status, bytes.TrimSpace(b))
	}
	return json.Unmarshal(b, out)
}

func (c *client) ClearKey(ctx context.Context) (*issuerapi.ClearKey, error) {
	var out issuerapi.ClearKey
	return &out, c.do(ctx, http.MethodGet, issuerapi.PathBaremetalClearKey, nil, &out)
}

func (c *client) Clear(ctx context.Context, req *issuerapi.ClearRequest) (*issuerapi.ClearResponse, error) {
	var out issuerapi.ClearResponse
	return &out, c.do(ctx, http.MethodPost, issuerapi.PathBaremetalClear, req, &out)
}

func (c *client) Certificate(ctx context.Context, req *issuerapi.BaremetalCertificateRequest) (*issuerapi.BaremetalCertificateResponse, error) {
	var out issuerapi.BaremetalCertificateResponse
	return &out, c.do(ctx, http.MethodPost, issuerapi.PathBaremetalCertificate, req, &out)
}

const usage = "usage: openstack-tpm-ipa ek|deploy|clean [flags]"

func run(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errors.New(usage)
	}
	cmd := args[0]
	switch cmd {
	case "ek", "deploy", "clean":
	default:
		return nil, fmt.Errorf("unknown command %q; %s", cmd, usage)
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgFile := fs.String("config", defaultConfig, "config file")
	node := fs.String("node", "", "Ironic node UUID")
	instance := fs.String("instance", "", "Nova instance UUID")
	if err := fs.Parse(args[1:]); err != nil {
		return nil, err
	}
	switch {
	case cmd == "deploy" && (*node == "" || *instance == ""):
		return nil, errors.New("deploy needs -node and -instance")
	case cmd == "clean" && *node == "":
		return nil, errors.New("clean needs -node")
	}
	cfg, err := readConfig(*cfgFile)
	if err != nil {
		return nil, err
	}
	var is *client
	if cmd != "ek" {
		if is, err = newClient(cfg); err != nil {
			return nil, err
		}
	}
	tpm, err := openTPM(cfg.tpm)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	switch cmd {
	case "deploy":
		return tpmprov.Deploy(ctx, tpm, is, *node, *instance)
	case "clean":
		return tpmprov.Clean(ctx, tpm, is, *node)
	}
	hash, err := tpmprov.EK(tpm)
	if err != nil {
		return nil, err
	}
	return map[string]string{"tpm_ek_sha256": hash}, nil
}

func main() {
	out, err := run(os.Args[1:])
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
		fmt.Fprintln(os.Stderr, "openstack-tpm-ipa:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "openstack-tpm-ipa:", err)
		os.Exit(1)
	}
}
