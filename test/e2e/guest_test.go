//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
)

type guestOS struct {
	Image  string `env:"IMAGE"`
	Flavor string `env:"FLAVOR"`
	User   string `env:"USER"`

	name      string
	firstBoot time.Duration // added to the timeouts of a build and the first attestation
	tpmTools  bool          // the image has tpm2-tools, for reading NV and for attacks from inside
	ansible   map[string]any
	run       func(addr, script string) (string, error)
	// Scripts that check the first boot installed the agent service, restart the agent and run its health check.
	bootstrapped, restartAgent, healthcheck string
}

func initGuests() {
	l := &lab.Linux
	l.name, l.tpmTools = "linux", true
	l.ansible = map[string]any{"ansible_user": l.User, "ansible_become": true}
	l.run = func(addr, script string) (string, error) { return sshRun(addr, nil, script) }
	l.bootstrapped = "systemctl is-enabled spire-agent"
	l.restartAgent = "systemctl restart spire-agent"
	l.healthcheck = "/opt/spire/spire-agent healthcheck -socketPath /run/spire/agent/public/api.sock"

	w := &lab.Windows
	w.name, w.firstBoot, w.run = "windows", 10*time.Minute, psRun
	w.ansible = map[string]any{"ansible_user": w.User, "ansible_shell_type": "cmd"}
	w.bootstrapped = "if ((Get-Service spire-agent).StartType -ne 'Automatic') { exit 1 }"
	w.restartAgent = "Restart-Service spire-agent"
	w.healthcheck = `& 'C:\Program Files\spire\spire-agent.exe' healthcheck`
}

// forEachGuest runs f in a subtest per guest OS, skipping one whose image is not in Glance.
func forEachGuest(t *testing.T, f func(t *testing.T, g *guestOS)) {
	t.Helper()
	for _, g := range []*guestOS{&lab.Linux, &lab.Windows} {
		t.Run(g.name, func(t *testing.T) {
			if _, err := cli(adminScope, "image", "show", g.Image); err != nil {
				t.Skipf("the %s image %s is not in Glance", g.name, g.Image)
			}
			f(t, g)
		})
	}
}

// attested boots a tenant virtual machine of this OS with an agent for the tenant's server and waits until it has attested and SSH works.
func (g *guestOS) attested(t testing.TB, name string) *instance {
	t.Helper()
	inst := boot(t, name, bootSpec{os: g, agent: lab.TenantServer.Container, fip: true, wait: true})
	inst.waitAttested(t, 10*time.Minute+g.firstBoot)
	inst.waitSSH(t, 5*time.Minute)
	return inst
}

// attested is guestOS.attested on Linux, for the scenarios that do not depend on the guest OS.
func attested(t testing.TB, name string) *instance {
	t.Helper()
	return lab.Linux.attested(t, name)
}

func (i *instance) installAgent(t testing.TB, container string) {
	t.Helper()
	srv := lab.TenantServer
	if container == lab.Central.Container {
		srv = lab.Central
	}
	host := map[string]any{
		"ansible_ssh_private_key_file": path(guestKey),
		"ansible_ssh_common_args":      "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
	}
	maps.Copy(host, i.OS.ansible)
	inventory := map[string]any{"all": map[string]any{"hosts": map[string]any{i.Addr: host}}}
	vars := map[string]any{
		"spire_agent_server_address": lab.HostIP,
		"spire_agent_server_port":    srv.Port,
		"spire_agent_trust_domain":   srv.TrustDomain,
		"spire_agent_bundle":         bundle(t, container),
	}
	dir := t.TempDir()
	for f, v := range map[string]any{"inventory.json": inventory, "vars.json": vars} {
		b, err := json.Marshal(v)
		must(t, err, f)
		must(t, os.WriteFile(filepath.Join(dir, f), b, 0o600), f)
	}
	out, err := runEnv([]string{"ANSIBLE_NOCOLOR=1"}, nil, "ansible-playbook", "-i", filepath.Join(dir, "inventory.json"),
		"-e", "@"+filepath.Join(dir, "vars.json"), path("lab/agent.yml"))
	if err != nil {
		t.Fatalf("install the agent in %s: %v\n%s", i.Name, err, out)
	}
}

// psRun runs a PowerShell script in a Windows instance as lab.Windows.User, an administrator, over SSH.
func psRun(ip, script string) (string, error) {
	u := utf16.Encode([]rune("$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'\n" + script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return run(nil, "ssh", "-q", "-i", path(guestKey),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
		lab.Windows.User+"@"+ip, "powershell -NoProfile -NonInteractive -EncodedCommand "+base64.StdEncoding.EncodeToString(b))
}
