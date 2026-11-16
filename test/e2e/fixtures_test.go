//go:build e2e

package e2e

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/contract"
)

// instance is a server booted by a test, named e2e-* so that `just clean` finds leftovers.
type instance struct {
	Name, ID  string
	Scope     scope    // its project, for actions Nova must take in it
	ProjectID string   // part of the agent ID
	Kind      string   // contract.KindVM or contract.KindBaremetal
	Addr      string   // reachable from the host: a floating IP, or a bare-metal instance's address on the provider network
	FIPID     string   // the floating IP, if it has one
	OS        *guestOS // how to reach and drive it
}

func (i *instance) agentID() string { return agentID(i.ProjectID, i.ID) }

func (i *instance) guestRun(script string) (string, error) { return i.OS.run(i.Addr, script) }

// guest is guestRun that fails the test on an error.
func (i *instance) guest(t testing.TB, script string) string {
	t.Helper()
	out, err := i.guestRun(script)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (i *instance) waitSSH(t testing.TB, timeout time.Duration) {
	t.Helper()
	eventually(t, timeout, i.Name+" reachable over SSH", func() bool { _, err := i.guestRun("exit 0"); return err == nil })
}

func (i *instance) waitAttested(t testing.TB, timeout time.Duration) {
	t.Helper()
	eventually(t, timeout, i.agentID()+" attested", func() bool { return agentAttested(i.agentID()) })
}

// bootstrapped waits until the instance answers SSH with the agent service installed.
func (i *instance) bootstrapped(t testing.TB) {
	t.Helper()
	i.waitSSH(t, 3*time.Minute)
	eventually(t, 10*time.Minute, i.Name+" bootstrapped", func() bool {
		_, err := i.guestRun(i.OS.bootstrapped)
		return err == nil
	})
}

// reattest restarts the agent and waits for a new completed attestation.
func (i *instance) reattest(t testing.TB, timeout time.Duration) {
	t.Helper()
	ts := now()
	i.guest(t, i.OS.restartAgent)
	eventually(t, timeout, i.agentID()+" re-attested", func() bool { return attestedSince(ts, i.agentID()) })
}

// agentHealthy requires the agent's Workload API to answer its health check.
func (i *instance) agentHealthy(t testing.TB) {
	t.Helper()
	if out, err := i.guestRun(i.OS.healthcheck); err != nil || !strings.Contains(out, "Agent is healthy") {
		t.Errorf("%s: spire-agent healthcheck: %v: %s", i.Name, err, out)
	}
}

// NV indices of the certificate of each kind.
var (
	nvVM        = fmt.Sprintf("%#x", uint32(contract.NVIndexVM))
	nvBaremetal = fmt.Sprintf("%#x", uint32(contract.NVIndexBaremetal))
)

// NV indices of the untrusted RSA EK and platform certificates that openstack-tpm-swtpm makes.
const (
	nvRSA      = "0x1c00002"
	nvPlatform = "0x1c08000"
)

// nvCert reads a certificate from an NV index of the instance's TPM.
func (i *instance) nvCert(t testing.TB, index string) []byte {
	t.Helper()
	if !i.OS.tpmTools {
		t.Fatalf("the %s image has no tpm2-tools to read NV", i.OS.name)
	}
	out := i.guest(t, "tpm2_nvread "+index+" | base64 -w0")
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil {
		t.Fatal(err)
	}
	var raw asn1.RawValue // the index may be larger than the certificate
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		t.Fatalf("NV %s is not DER: %v", index, err)
	}
	return raw.FullBytes
}

// cert reads the instance's certificate from its TPM.
func (i *instance) cert(t testing.TB) []byte {
	t.Helper()
	if i.Kind == contract.KindBaremetal {
		return i.nvCert(t, nvBaremetal)
	}
	return i.nvCert(t, nvVM)
}

// nvFingerprint identifies the certificates in NV.
func (i *instance) nvFingerprint(t testing.TB) string {
	t.Helper()
	indices := []string{nvRSA, nvVM}
	if i.Kind == contract.KindBaremetal {
		indices = []string{nvBaremetal}
	}
	var s []string
	for _, idx := range indices {
		sum := sha256.Sum256(i.nvCert(t, idx))
		s = append(s, hex.EncodeToString(sum[:8]))
	}
	return strings.Join(s, "/")
}

// verifiedClaims checks that the instance's certificate chains to the bundle and carries the claims Nova and Keystone give.
func (i *instance) verifiedClaims(t testing.TB) (contract.Claims, *contract.Verified) {
	t.Helper()
	b, err := contract.LoadBundle(path(caBundle))
	must(t, err, "bundle")
	v, err := b.Verify(i.cert(t))
	must(t, err, i.Name+" certificate")
	s, p := showServer(t, i.ID), showProject(t, i.ProjectID)
	want := contract.Claims{Region: lab.Region, DomainID: p.DomainID, ProjectID: i.ProjectID, InstanceID: i.ID,
		Kind: i.Kind, Ancestors: ancestors(t, i.ProjectID), UserID: s.UserID}
	if !v.Claims.Equal(want) {
		t.Fatalf("%s claims %+v, want %+v", i.Name, v.Claims, want)
	}
	return want, v
}

type bootSpec struct {
	scope     scope // default the tenant project
	flavor    string
	image     string
	network   string
	os        *guestOS // default Linux; its image and flavor unless set
	baremetal bool     // on the lab's Ironic node: its flavor and network, a config drive, no floating IP
	agent     string   // the SPIRE server container the agent attests to; "" boots without one
	fip       bool
	wait      bool // fail the test unless the build reaches ACTIVE
	// securityGroup defaults to lab.SecurityGroup in the tenant project
	securityGroup string
}

// boot creates a server named e2e-<name> and deletes it when the test ends, unless -e2e.keep.
func boot(t testing.TB, name string, spec bootSpec) *instance {
	t.Helper()
	name = "e2e-" + name
	if spec.scope == (scope{}) {
		spec.scope = tenantScope()
	}
	g := cmp.Or(spec.os, &lab.Linux)
	kind, buildTimeout := contract.KindVM, 10*time.Minute+g.firstBoot
	if spec.baremetal {
		// Ironic boots the ramdisk, runs the deploy steps, writes the image and boots the node from disk.
		kind, buildTimeout = contract.KindBaremetal, 25*time.Minute
		spec.flavor, spec.network, spec.fip = lab.Baremetal.Flavor, lab.Baremetal.Network, false
	}
	if spec.flavor == "" {
		spec.flavor = g.Flavor
	}
	if spec.image == "" {
		spec.image = g.Image
	}
	if spec.network == "" {
		spec.network = lab.Network
	}
	if id := serverID(t, name); id != "" { // a leftover from an aborted run
		must(t, deleteServer(id), "delete leftover "+name)
	}
	ss := serverSpec{name: name, scope: spec.scope, flavor: spec.flavor, image: spec.image, network: spec.network, configDrive: spec.baremetal}
	if spec.securityGroup != "" {
		ss.securityGroup = spec.securityGroup
	} else if spec.scope == tenantScope() && !spec.baremetal {
		ss.securityGroup = lab.SecurityGroup
	}
	if spec.baremetal {
		waitNodeAvailable(t, 20*time.Minute)
	}
	inst := &instance{Name: name, Scope: spec.scope, Kind: kind, OS: g}
	inst.ID = createServer(t, ss)
	t.Cleanup(func() {
		if *keep {
			t.Logf("keeping %s (%s)", inst.Name, inst.ID)
			return
		}
		if err := inst.delete(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	inst.ProjectID = showServer(t, inst.ID).ProjectID
	status := waitServer(t, inst.ID, buildTimeout)
	if status != "ACTIVE" {
		if spec.wait {
			t.Fatalf("boot %s: %s: %s", name, status, showServer(t, inst.ID).fault())
		}
		return inst // the caller expects a failed build
	}
	switch {
	case spec.baremetal || spec.network == lab.ExternalNetwork:
		inst.Addr = providerAddress(t, inst.ID)
	case spec.fip:
		inst.FIPID, inst.Addr = addFloatingIP(t, inst.ID, spec.scope)
	}
	t.Logf("booted %s (%s, %s) %s", name, inst.ID, kind, inst.Addr)
	if spec.agent != "" {
		inst.waitSSH(t, 10*time.Minute+g.firstBoot)
		inst.installAgent(t, spec.agent)
	}
	return inst
}

// delete deletes the server and its floating IP.
// Ironic cleans a bare-metal node afterwards, which the next bare-metal boot waits for.
func (i *instance) delete() error {
	if i.ID != "" {
		if err := deleteServer(i.ID); err != nil {
			return err
		}
		i.ID = ""
	}
	if i.FIPID != "" {
		if err := deleteFloatingIP(i.FIPID); err != nil {
			return err
		}
		i.FIPID, i.Addr = "", ""
	}
	return nil
}

// hasSelectors requires each of want among an agent's openstack_tpm selectors.
func hasSelectors(t testing.TB, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, "openstack_tpm:"+w) {
			t.Errorf("missing selector %s in %v", w, got)
		}
	}
}

// selectorValue returns the value of the agent's selector with this prefix, or "".
func selectorValue(sel []string, prefix string) string {
	for _, s := range sel {
		if v, ok := strings.CutPrefix(s, "openstack_tpm:"+prefix); ok {
			return v
		}
	}
	return ""
}

// keySelector returns the value of the agent's tpm:key:sha256 selector on the tenant server.
func keySelector(t testing.TB, id string) string {
	t.Helper()
	return selectorValue(selectors(t, id), "tpm:key:sha256:")
}

func sorted(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }

// probeResult is the probe's output.
type probeResult struct {
	Accepted bool   `json:"accepted"`
	SPIFFEID string `json:"spiffe_id"`
	Error    string `json:"error"`
}

const guestProbe = "/usr/local/bin/e2e-probe"

// probe runs the attacker client in the instance against the tenant SPIRE server.
func (i *instance) probe(t testing.TB, args ...string) probeResult {
	t.Helper()
	return i.probeAt(t, lab.TenantServer.Port, args...)
}

// probeAt runs the attacker client in the instance against the SPIRE server on port of this host.
func (i *instance) probeAt(t testing.TB, port int, args ...string) probeResult {
	t.Helper()
	if _, err := i.guestRun("test -x " + guestProbe); err != nil {
		bin, err := os.Open(probeBin)
		if err != nil {
			t.Fatal(err)
		}
		defer bin.Close()
		if _, err := sshRun(i.Addr, bin, "cat > "+guestProbe+" && chmod 0755 "+guestProbe); err != nil {
			t.Fatal(err)
		}
	}
	argv := append([]string{guestProbe, "-server", fmt.Sprintf("%s:%d", lab.HostIP, port)}, args...)
	out := i.guest(t, shellJoin(argv)+" 2>/dev/null")
	var r probeResult
	if err := json.Unmarshal(bytes.TrimSpace([]byte(out)), &r); err != nil {
		t.Fatalf("probe output %q: %v", out, err)
	}
	t.Logf("probe %s: %+v", strings.Join(args, " "), r)
	return r
}

// upload writes a file as root in the instance.
func (i *instance) upload(t testing.TB, file string, content []byte) {
	t.Helper()
	if _, err := sshRun(i.Addr, bytes.NewReader(content), "cat > "+quote(file)); err != nil {
		t.Fatal(err)
	}
}
