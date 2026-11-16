//go:build e2e

// Package e2e runs the end-to-end scenarios against the Kolla lab, with `just e2e`.
// It drives the lab as an operator and a tenant would, through the openstack CLI, SSH and local docker.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/labenv"
)

var keep = flag.Bool("e2e.keep", false, "keep the instances the tests boot")

// labConfig is the lab's constants, from lab/lab.env by their env tags, plus what the tests look up when they start.
type labConfig struct {
	Region          string `env:"REGION"`
	DomainID        string `env:"DOMAIN_ID"`
	Tenant          string `env:"TENANT"`
	KeystoneURL     string `env:"KEYSTONE_URL"`
	NovaURL         string `env:"NOVA_URL"`
	NeutronURL      string `env:"NEUTRON_URL"`
	IronicURL       string `env:"IRONIC_URL"`
	IssuerURL       string `env:"ISSUER_URL"`
	IssuerHealthURL string `env:"ISSUER_HEALTH_URL"`
	HostIP          string `env:"HOST_IP"`
	CirrosImage     string `env:"CIRROS_IMAGE"`
	PlainFlavor     string `env:"PLAIN_FLAVOR"`
	Keypair         string `env:"KEYPAIR"`
	Network         string `env:"NETWORK"`
	SecurityGroup   string `env:"SECURITY_GROUP"`
	OtherProject    string `env:"OTHER_PROJECT"`
	OtherNetwork    string `env:"OTHER_NETWORK"`
	ExternalNetwork string `env:"EXTERNAL_NETWORK"`
	FIPPrefix       string `env:"FIP_PREFIX"`
	SpireImage      string `env:"SPIRE_SERVER_IMAGE"`
	CentralUser     string `env:"CENTRAL_USER"`
	NoroleUser      string `env:"NOROLE_USER"`
	TestPort        int    `env:"TEST_SPIRE_PORT"` // for SPIRE servers the tests start

	TenantServer spireServer     `envPrefix:"SPIRE_"`   // the tenant's SPIRE server
	Central      spireServer     `envPrefix:"CENTRAL_"` // the central one (every project of the Default domain)
	Baremetal    baremetalConfig `envPrefix:"BM_"`
	Linux        guestOS         `envPrefix:"LINUX_"`
	Windows      guestOS         `envPrefix:"WINDOWS_"`

	Controller                                 string
	TenantProjectID, AdminProjectID, AppCredID string
}

// spireServer is a SPIRE server container on this host.
type spireServer struct {
	Container   string `env:"CONTAINER"`
	TrustDomain string `env:"TRUST_DOMAIN"`
	Port        int    `env:"PORT"`
	Conf        string // SPIRE server config it runs
	Dir         string // .state dir mounted at /etc/spire/openstack-tpm
	EnvFile     string
}

type baremetalConfig struct {
	NodeName string `env:"NODE"`
	Flavor   string `env:"FLAVOR"`
	Network  string `env:"NETWORK"`
	Node     string
	EKSHA256 string // the EK record of the node's inspection data
}

var (
	lab      labConfig
	repoRoot string
	probeBin string // the probe, built for the guests
)

// path resolves a repo-relative path.
func path(p string) string { return filepath.Join(repoRoot, p) }

// Files the lab scripts write.
const (
	adminPasswordFile = ".state/admin.password"
	sshConfig         = ".state/ssh_config"
	guestKey          = ".state/openstack-tpm"
	caBundle          = ".state/issuer/ca.pem" // the provider's bundle
	hostCA            = ".state/pki/ca.crt"    // CA of the issuer's server and the hosts' client certificates
	hostCAKey         = ".state/pki/ca.key"    // for a client certificate of a host that is not compute-1
	appCredSecretFile = ".state/provision/appcred-secret"
	appCredIDFile     = ".state/provision/appcred-id"
)

func loadLab() error {
	lab = labConfig{Controller: "compute-1"}
	if err := labenv.Load(path("lab/lab.env"), &lab); err != nil {
		return err
	}
	t, c := &lab.TenantServer, &lab.Central
	t.Conf, t.Dir, t.EnvFile = "deploy/spire/server.conf", ".state/spire/tenant", ".state/spire/tenant.env"
	c.Conf, c.Dir, c.EnvFile = "deploy/spire/server-central.conf", ".state/spire/central", ".state/spire/central.env"
	initGuests()
	b, err := os.ReadFile(path(appCredIDFile))
	if err != nil {
		return fmt.Errorf("%w (run `just provision` first)", err)
	}
	lab.AppCredID = strings.TrimSpace(string(b))
	return nil
}

func TestMain(m *testing.M) {
	flag.Parse()
	code, err := setupAndRun(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

func setupAndRun(m *testing.M) (int, error) {
	wd, err := os.Getwd()
	if err != nil {
		return 0, err
	}
	repoRoot = filepath.Clean(filepath.Join(wd, "../.."))
	if err := loadLab(); err != nil {
		return 0, err
	}
	// IDs the lab scripts created, by name.
	var p struct {
		ID string `json:"id"`
	}
	if err := cliJSON(&p, adminScope, "project", "show", lab.Tenant); err != nil {
		return 0, err
	}
	lab.TenantProjectID = p.ID
	if err := cliJSON(&p, adminScope, "project", "show", lab.OtherProject); err != nil {
		return 0, err
	}
	lab.AdminProjectID = p.ID
	var n struct {
		UUID string `json:"uuid"`
	}
	if err := cliJSON(&n, systemScope, "baremetal", "node", "show", lab.Baremetal.NodeName); err != nil {
		return 0, err
	}
	lab.Baremetal.Node = n.UUID
	out, err := cli(systemScope, "baremetal", "node", "inventory", "save", lab.Baremetal.NodeName)
	if err != nil {
		return 0, err
	}
	var inv struct {
		PluginData struct {
			OpenStackTPM struct {
				EK string `json:"tpm_ek_sha256"`
			} `json:"openstack_tpm"`
		} `json:"plugin_data"`
	}
	if err := json.Unmarshal(out, &inv); err != nil || inv.PluginData.OpenStackTPM.EK == "" {
		return 0, fmt.Errorf("node %s has no EK record (%v)", lab.Baremetal.NodeName, err)
	}
	lab.Baremetal.EKSHA256 = inv.PluginData.OpenStackTPM.EK

	tmp, err := os.MkdirTemp("", "e2e-probe-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	probeBin = filepath.Join(tmp, "probe")
	build := exec.Command("go", "build", "-trimpath", "-o", probeBin, "./probe")
	build.Dir, build.Env = filepath.Join(repoRoot, "test/e2e"), append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := build.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("build probe: %v\n%s", err, out)
	}
	return m.Run(), nil
}

var safeArg = regexp.MustCompile(`^[A-Za-z0-9_./:=@%+,-]+$`)

// quote makes s one word for a POSIX shell.
func quote(s string) string {
	if safeArg.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellJoin(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = quote(a)
	}
	return strings.Join(q, " ")
}

// cmdTimeout bounds one command.
const cmdTimeout = 10 * time.Minute

// runEnv runs a local command with extra environment and returns its stdout; the error carries stderr.
func runEnv(env []string, stdin io.Reader, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s: %w: %s", shellJoin(append([]string{name}, args...)), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func run(stdin io.Reader, name string, args ...string) (string, error) {
	return runEnv(nil, stdin, name, args...)
}

// local runs a command on this host and fails the test on an error.
func local(t testing.TB, name string, args ...string) string {
	t.Helper()
	out, err := run(nil, name, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// nodeRun runs argv as root on a lab VM.
func nodeRun(host string, argv ...string) (string, error) {
	return run(nil, "ssh", "-F", path(sshConfig), "-o", "ConnectTimeout=10", host, shellJoin(argv))
}

// sshRun runs a shell script as root in a Linux instance, on its address.
func sshRun(ip string, stdin io.Reader, script string) (string, error) {
	return run(stdin, "ssh", "-q", "-i", path(guestKey),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
		lab.Linux.User+"@"+ip, "sudo bash -c "+quote(script))
}

// eventually polls cond until it holds or timeout passes.
func eventually(t testing.TB, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s: %s", timeout, what)
		}
		time.Sleep(3 * time.Second)
	}
}

func must(t testing.TB, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// spireRunAt runs the spire-server CLI in a SPIRE server container.
func spireRunAt(container string, args ...string) (string, error) {
	argv := append([]string{"exec", container, "/opt/spire/bin/spire-server"}, args...)
	return run(nil, "docker", append(argv, "-socketPath", "/run/spire-server/api.sock")...)
}

// bundle is a SPIRE server's trust bundle, the agents' bootstrap bundle.
func bundle(t testing.TB, container string) string {
	t.Helper()
	out, err := spireRunAt(container, "bundle", "show")
	must(t, err, "bundle of "+container)
	return out
}

// agentID is the agent ID of an instance on the tenant server.
func agentID(projectID, uuid string) string {
	return agentIDIn(lab.TenantServer.TrustDomain, projectID, uuid)
}

// agentIDIn is the agent ID of an instance in a trust domain.
func agentIDIn(trustDomain, projectID, uuid string) string {
	return fmt.Sprintf("spiffe://%s/spire/agent/openstack_tpm/%s/%s/%s", trustDomain, lab.Region, projectID, uuid)
}

// agentAttested reports whether the tenant server has a current agent with this ID.
func agentAttested(id string) bool { return agentAttestedAt(lab.TenantServer.Container, id) }

func agentAttestedAt(container, id string) bool {
	out, err := spireRunAt(container, "agent", "show", "-spiffeID", id)
	return err == nil && regexp.MustCompile(`Attestation type\s*:\s*openstack_tpm`).MatchString(out)
}

// selectors returns the agent's selectors on the tenant server.
func selectors(t testing.TB, id string) []string {
	t.Helper()
	return selectorsAt(t, lab.TenantServer.Container, id)
}

func selectorsAt(t testing.TB, container, id string) []string {
	t.Helper()
	out, err := spireRunAt(container, "agent", "show", "-spiffeID", id)
	must(t, err, "agent show "+id)
	var sel []string
	for line := range strings.SplitSeq(out, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "Selectors" {
			sel = append(sel, strings.TrimSpace(v))
		}
	}
	return sel
}

// now is a timestamp for `docker logs --since`; the containers share this host's clock.
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// serverLogSince returns the tenant SPIRE server's log lines since ts.
func serverLogSince(ts string) string {
	out, _ := run(nil, "sh", "-c", "docker logs --since "+quote(ts)+" "+quote(lab.TenantServer.Container)+" 2>&1")
	return out
}

// attestedSince reports a completed attestation of id since ts.
func attestedSince(ts, id string) bool {
	for line := range strings.SplitSeq(serverLogSince(ts), "\n") {
		if strings.Contains(line, "Agent attestation request completed") && strings.Contains(line, `agent_id="`+id+`"`) {
			return true
		}
	}
	return false
}

// decision is one line of the issuer's log, an issued certificate, an authorized clear or a refusal.
type decision struct {
	Msg          string `json:"msg"`
	Request      string `json:"request"` // vm, baremetal, clear
	Host         string `json:"host"`    // compute host of a vm request
	Node         string `json:"node"`    // Ironic node of a baremetal or clear request
	InstanceUUID string `json:"instance_uuid"`
	Serial       string `json:"serial"`
	KeySHA256    string `json:"key_sha256"`
	EKSHA256     string `json:"ek_sha256"`
	Claims       string `json:"claims"`
	Event        string `json:"event"`           // why Nova creates a vTPM: build, resize, first-start-after-resize
	State        string `json:"provision_state"` // of the node, in a clear request
	Reason       string `json:"reason"`
}

// decisions returns the issuer's log lines that match.
func decisions(t testing.TB, match func(decision) bool) []decision {
	t.Helper()
	out := local(t, "sh", "-c", "docker logs issuer 2>&1")
	var res []decision
	for line := range strings.SplitSeq(out, "\n") {
		var d decision
		if json.Unmarshal([]byte(line), &d) == nil && d.Msg != "" && match(d) {
			res = append(res, d)
		}
	}
	return res
}

// issuances returns the issuer's records of certificates for an instance.
func issuances(t testing.TB, uuid string) []decision {
	t.Helper()
	return decisions(t, func(d decision) bool { return d.Msg == "issued" && d.InstanceUUID == uuid })
}

// clears returns the issuer's records of authorized clears of a node.
func clears(t testing.TB, node string) []decision {
	t.Helper()
	return decisions(t, func(d decision) bool { return d.Msg == "authorized" && d.Node == node })
}

// swtpmState reports whether compute-1 still holds swtpm state for uuid.
func swtpmState(t testing.TB, uuid string) bool {
	t.Helper()
	_, err := nodeRun(lab.Controller, "docker", "exec", "nova_libvirt", "test", "-e", "/var/lib/libvirt/swtpm/"+uuid)
	var ee *exec.ExitError
	switch {
	case err == nil:
		return true
	case errors.As(err, &ee) && ee.ExitCode() == 1:
		return false
	}
	t.Fatalf("swtpm state of %s: %v", uuid, err)
	return false
}
