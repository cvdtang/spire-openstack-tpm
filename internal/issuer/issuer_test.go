package issuer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/issuerapi"
	"github.com/cvdtang/openstack-tpm/internal/openstack"
	"github.com/cvdtang/openstack-tpm/internal/pkitest"
)

const (
	vmID      = "11111111-1111-4111-8111-111111111111"
	projectID = "0123456789abcdef0123456789abcdef"
	userID    = "fedcba9876543210fedcba9876543210"
)

// fakeCloud is the control plane as the issuer reads it.
type fakeCloud struct {
	mu       sync.Mutex
	allocs   map[string]*openstack.Allocations
	servers  map[string]*openstack.Server
	projects map[string]*openstack.Project
	nodes    map[string]*openstack.Node
	eks      map[string]string
	actions  map[string][]openstack.InstanceAction // newest first
	fail     map[string]error                      // by lookup: allocations, server, project, node, ek
	calls    []string                              // "lookup scope/id"
}

func newFakeCloud() *fakeCloud {
	return &fakeCloud{
		allocs: map[string]*openstack.Allocations{}, servers: map[string]*openstack.Server{},
		projects: map[string]*openstack.Project{}, nodes: map[string]*openstack.Node{},
		eks: map[string]string{}, actions: map[string][]openstack.InstanceAction{}, fail: map[string]error{},
	}
}

func lookup[T any](f *fakeCloud, what, call string, m map[string]*T, id string) (*T, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	if err := f.fail[what]; err != nil {
		return nil, err
	}
	v, ok := m[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s %s", openstack.ErrNotFound, what, id)
	}
	c := *v // the issuer gets a copy, as from an API
	return &c, nil
}

func (f *fakeCloud) Allocations(_ context.Context, instance string) (*openstack.Allocations, error) {
	return lookup(f, "allocations", "allocations "+instance, f.allocs, instance)
}

func (f *fakeCloud) Server(_ context.Context, project, instance string) (*openstack.Server, error) {
	return lookup(f, "server", "server "+project+"/"+instance, f.servers, instance)
}

func (f *fakeCloud) Actions(_ context.Context, project, instance string) ([]openstack.InstanceAction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "actions "+project+"/"+instance)
	if err := f.fail["actions"]; err != nil {
		return nil, err
	}
	return slices.Clone(f.actions[instance]), nil
}

func (f *fakeCloud) Project(_ context.Context, project string) (*openstack.Project, error) {
	return lookup(f, "project", "project "+project, f.projects, project)
}

func (f *fakeCloud) Node(_ context.Context, node string) (*openstack.Node, error) {
	return lookup(f, "node", "node "+node, f.nodes, node)
}

func (f *fakeCloud) NodeEK(_ context.Context, node string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ek "+node)
	return f.eks[node], f.fail["ek"]
}

func (f *fakeCloud) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// fixture is an issuer with a fake control plane and software keys.
type fixture struct {
	*Service
	cloud         *fakeCloud
	root, issuing *pkitest.CA
	clearKey      *ecdsa.PrivateKey
	now           time.Time
	log           *bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := pkitest.NewCA(t, "root", nil)
	issuing := pkitest.NewIssuing(t, "issuing", root)
	clearKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{cloud: newFakeCloud(), root: root, issuing: issuing, clearKey: clearKey, now: time.Now(), log: &bytes.Buffer{}}
	f.Service = &Service{
		Region: "RegionOne", Cloud: f.cloud,
		IssuingCert: issuing.Cert, Issuing: issuing.Key, ClearSigner: clearKey,
		Log: slog.New(slog.NewJSONHandler(f.log, nil)), Now: func() time.Time { return f.now },
	}
	f.cloud.projects[projectID] = &openstack.Project{ID: projectID, Name: "tenant-a", DomainID: "default", ParentID: "default"}
	return f
}

// addVM adds an instance that Nova is building on host.
func (f *fixture) addVM(id, host string) *openstack.Server {
	s := &openstack.Server{
		ID: id, Name: "vm", Status: "BUILD", TenantID: projectID, UserID: userID, Created: f.now.Add(-time.Minute),
		Host: host, Node: host, VMState: "building", TaskState: new("spawning"),
	}
	s.Flavor.OriginalName = "m1.tpm"
	s.Flavor.ExtraSpecs = map[string]string{"hw:tpm_version": "2.0", "hw:tpm_secret_security": "host"}
	f.cloud.servers[id] = s
	f.cloud.allocs[id] = &openstack.Allocations{ProjectID: projectID, Providers: []string{"rp-" + host}}
	return s
}

func (f *fixture) verify(t *testing.T, der []byte) *contract.Verified {
	t.Helper()
	v, err := contract.NewBundle([]*x509.Certificate{f.root.Cert, f.issuing.Cert}).Verify(der)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// call sends a request to the handler as the listener would after verifying host's client certificate ("" for none).
func (f *fixture) call(method, path, host string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if host != "" {
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{DNSNames: []string{host}}}}}
	}
	rec := httptest.NewRecorder()
	f.Handler().ServeHTTP(rec, req)
	return rec
}

// wantError checks an error answer.
func wantError(t *testing.T, what string, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var e issuerapi.Error
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Errorf("%s: status %d, body %q: %v", what, rec.Code, rec.Body, err)
		return
	}
	if rec.Code != status || e.Code != code || e.Message == "" || rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("%s: status %d, code %q (%s); want %d %q", what, rec.Code, e.Code, e.Message, status, code)
	}
}

func p384(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// swtpmKey is a key as swtpm_setup passes it in --ek.
func swtpmKey(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	b, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return "x=" + hex.EncodeToString(b[1:49]) + ",y=" + hex.EncodeToString(b[49:]) + ",id=secp384r1"
}

func vmRequest(t *testing.T, id string, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	b, err := json.Marshal(issuerapi.VMCertificateRequest{InstanceUUID: id, Key: swtpmKey(t, pub)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Ensures a compute host gets a certificate for a building instance, with Nova and Keystone read from inside its project, and the issuer keeps no records.
func TestVMCertificate(t *testing.T) {
	f := newFixture(t)
	f.addVM(vmID, "compute-1")
	key := p384(t)
	issue := func() *contract.Verified {
		t.Helper()
		rec := f.call(http.MethodPost, issuerapi.PathVMCertificate, "compute-1", vmRequest(t, vmID, &key.PublicKey))
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/pkix-cert" {
			t.Fatalf("status %d, type %q: %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
		}
		return f.verify(t, rec.Body.Bytes())
	}

	v := issue()
	if v.Claims.InstanceID != vmID || !v.Key.Equal(&key.PublicKey) {
		t.Errorf("certificate for %s, key %v", v.Claims.InstanceID, v.Key)
	}
	if !v.Cert.NotBefore.Equal(f.now.UTC().Truncate(time.Second)) || !v.Cert.NotAfter.Equal(contract.NotAfter()) {
		t.Errorf("validity %s to %s", v.Cert.NotBefore, v.Cert.NotAfter)
	}
	// Placement names the project; Nova and Keystone are read from inside it.
	if got, want := f.cloud.called(), []string{"allocations " + vmID, "server " + projectID + "/" + vmID, "project " + projectID}; !slices.Equal(got, want) {
		t.Errorf("lookups %q, want %q", got, want)
	}
	// The issuer keeps no records, so a second request gets a second certificate.
	if again := issue(); again.Cert.SerialNumber.Cmp(v.Cert.SerialNumber) == 0 {
		t.Error("two certificates with one serial")
	}
}

// Ensures only the instance's own host, named by its client certificate, gets a certificate.
func TestVMCertificateHost(t *testing.T) {
	f := newFixture(t)
	f.addVM(vmID, "compute-1")
	body := vmRequest(t, vmID, &p384(t).PublicKey)

	// Without a client certificate the request is refused before anything is read or looked up.
	wantError(t, "no host", f.call(http.MethodPost, issuerapi.PathVMCertificate, "", body), http.StatusForbidden, issuerapi.CodeRefused)
	if calls := f.cloud.called(); len(calls) != 0 {
		t.Errorf("lookups without a host: %q", calls)
	}
	// A certificate with two DNS names names no host.
	req := httptest.NewRequest(http.MethodPost, issuerapi.PathVMCertificate, bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{DNSNames: []string{"compute-1", "compute-2"}}}}}
	rec := httptest.NewRecorder()
	f.Handler().ServeHTTP(rec, req)
	wantError(t, "two DNS names", rec, http.StatusForbidden, issuerapi.CodeRefused)

	// A host name matches exactly.
	for _, host := range []string{"COMPUTE-1", "compute-1.example"} {
		wantError(t, "host "+host, f.call(http.MethodPost, issuerapi.PathVMCertificate, host, body), http.StatusForbidden, issuerapi.CodeRefused)
	}
}

type failingSigner struct {
	crypto.Signer
	sig []byte
}

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	if s.sig != nil {
		return s.sig, nil
	}
	return nil, errors.New("transit: 503 sealed")
}

// Ensures a certificate is refused unless OpenStack shows the requesting host building the instance with a vTPM, and outages answer 503.
func TestVMCertificateRefusals(t *testing.T) {
	down := errors.New("connection refused")
	for name, c := range map[string]struct {
		mod    func(f *fixture, s *openstack.Server)
		status int
		code   string
	}{
		"no allocation":          {func(f *fixture, _ *openstack.Server) { delete(f.cloud.allocs, vmID) }, 403, issuerapi.CodeRefused},
		"no instance":            {func(f *fixture, _ *openstack.Server) { delete(f.cloud.servers, vmID) }, 403, issuerapi.CodeRefused},
		"no project":             {func(f *fixture, _ *openstack.Server) { delete(f.cloud.projects, projectID) }, 403, issuerapi.CodeRefused},
		"on another host":        {func(_ *fixture, s *openstack.Server) { s.Host = "compute-2" }, 403, issuerapi.CodeRefused},
		"no host yet":            {func(_ *fixture, s *openstack.Server) { s.Host = "" }, 403, issuerapi.CodeRefused},
		"active":                 {func(_ *fixture, s *openstack.Server) { s.VMState, s.TaskState = "active", nil }, 403, issuerapi.CodeRefused},
		"networking":             {func(_ *fixture, s *openstack.Server) { s.TaskState = new("networking") }, 403, issuerapi.CodeRefused},
		"rebuild":                {func(_ *fixture, s *openstack.Server) { s.VMState, s.TaskState = "active", new("rebuild_spawning") }, 403, issuerapi.CodeRefused},
		"migrating":              {func(_ *fixture, s *openstack.Server) { s.VMState, s.TaskState = "active", new("migrating") }, 403, issuerapi.CodeRefused},
		"error":                  {func(_ *fixture, s *openstack.Server) { s.VMState, s.TaskState = "error", nil }, 403, issuerapi.CodeRefused},
		"no vTPM":                {func(_ *fixture, s *openstack.Server) { s.Flavor.ExtraSpecs = nil }, 403, issuerapi.CodeRefused},
		"TPM 1.2":                {func(_ *fixture, s *openstack.Server) { s.Flavor.ExtraSpecs["hw:tpm_version"] = "1.2" }, 403, issuerapi.CodeRefused},
		"user secret":            {func(_ *fixture, s *openstack.Server) { s.Flavor.ExtraSpecs["hw:tpm_secret_security"] = "user" }, 403, issuerapi.CodeRefused},
		"no secret policy":       {func(_ *fixture, s *openstack.Server) { delete(s.Flavor.ExtraSpecs, "hw:tpm_secret_security") }, 403, issuerapi.CodeRefused},
		"Nova's project":         {func(_ *fixture, s *openstack.Server) { s.TenantID = "another-project" }, 403, issuerapi.CodeRefused},
		"no user":                {func(_ *fixture, s *openstack.Server) { s.UserID = "" }, 403, issuerapi.CodeRefused},
		"user not spellable":     {func(_ *fixture, s *openstack.Server) { s.UserID = "a/b" }, 403, issuerapi.CodeRefused},
		"ancestor not spellable": {func(f *fixture, _ *openstack.Server) { f.cloud.projects[projectID].Ancestors = []string{"a/b"} }, 403, issuerapi.CodeRefused},
		"no region":              {func(f *fixture, _ *openstack.Server) { f.Region = "" }, 403, issuerapi.CodeRefused},
		"placement down":         {func(f *fixture, _ *openstack.Server) { f.cloud.fail["allocations"] = down }, 503, issuerapi.CodeUnavailable},
		"nova down":              {func(f *fixture, _ *openstack.Server) { f.cloud.fail["server"] = down }, 503, issuerapi.CodeUnavailable},
		"keystone down":          {func(f *fixture, _ *openstack.Server) { f.cloud.fail["project"] = down }, 503, issuerapi.CodeUnavailable},
		"placement forbids": {func(f *fixture, _ *openstack.Server) {
			f.cloud.fail["allocations"] = fmt.Errorf("%w: GET", openstack.ErrForbidden)
		}, 503, issuerapi.CodeForbidden},
		"nova forbids": {func(f *fixture, _ *openstack.Server) {
			f.cloud.fail["server"] = fmt.Errorf("%w: GET", openstack.ErrForbidden)
		}, 503, issuerapi.CodeForbidden},
		"no token for project": {func(f *fixture, _ *openstack.Server) {
			f.cloud.fail["server"] = fmt.Errorf("%w: 401", openstack.ErrAuth)
		}, 503, issuerapi.CodeForbidden},
		"signer fails": {func(f *fixture, _ *openstack.Server) {
			f.Issuing = failingSigner{Signer: f.issuing.Key}
		}, 503, issuerapi.CodeUnavailable},
	} {
		f := newFixture(t)
		c.mod(f, f.addVM(vmID, "compute-1"))
		rec := f.call(http.MethodPost, issuerapi.PathVMCertificate, "compute-1", vmRequest(t, vmID, &p384(t).PublicKey))
		wantError(t, name, rec, c.status, c.code)
	}
}

// act is an instance action that started ago before the fixture's now, with an error message if failed.
func (f *fixture) act(action string, ago time.Duration, failed bool) openstack.InstanceAction {
	a := openstack.InstanceAction{Action: action, RequestID: "req-" + action, UserID: userID,
		StartTime: f.now.UTC().Add(-ago)}
	if failed {
		a.Message = "Error"
	}
	return a
}

// Ensures a vTPM added by resize is certified once, and no other later operation gets a certificate.
func TestVMCertificateResize(t *testing.T) {
	ok := func(t *testing.T, f *fixture, event string) {
		t.Helper()
		rec := f.call(http.MethodPost, issuerapi.PathVMCertificate, "compute-1", vmRequest(t, vmID, &p384(t).PublicKey))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		if want := `"event":"` + event + `"`; !strings.Contains(f.log.String(), want) {
			t.Errorf("log has no %s: %s", want, f.log)
		}
		f.verify(t, rec.Body.Bytes())
	}
	running := func(t *testing.T) *fixture {
		f := newFixture(t)
		s := f.addVM(vmID, "compute-1")
		s.Status, s.VMState, s.TaskState, s.Created = "RESIZE", "active", new("resize_finish"), f.now.Add(-48*time.Hour)
		f.cloud.actions[vmID] = []openstack.InstanceAction{f.act("resize", 2*time.Minute, false), f.act("create", 48*time.Hour, false)}
		return f
	}
	stopped := func(t *testing.T, taskState string, acts ...openstack.InstanceAction) *fixture {
		f := newFixture(t)
		s := f.addVM(vmID, "compute-1")
		s.Status, s.VMState, s.TaskState, s.Created = "SHUTOFF", "stopped", new(taskState), f.now.Add(-48*time.Hour)
		f.cloud.actions[vmID] = acts
		return f
	}

	// Ensures a running instance is certified when it finishes a resize.
	t.Run("running", func(t *testing.T) {
		f := running(t)
		ok(t, f, "resize")
		want := []string{"allocations " + vmID, "server " + projectID + "/" + vmID, "project " + projectID, "actions " + projectID + "/" + vmID}
		if got := f.cloud.called(); !slices.Equal(got, want) {
			t.Errorf("lookups %q, want %q", got, want)
		}
		// A build reads no actions.
		b := newFixture(t)
		b.addVM(vmID, "compute-1")
		ok(t, b, "build")
		if got := b.cloud.called(); slices.Contains(got, "actions "+projectID+"/"+vmID) {
			t.Errorf("a build read the actions: %q", got)
		}
	})
	// Ensures a stopped instance is certified at its first start after a resize.
	t.Run("stopped", func(t *testing.T) {
		f := newFixture(t)
		// Failed starts before it, and a resize that is not confirmed yet.
		ok(t, stopped(t, "powering-on", f.act("start", 0, false), f.act("start", time.Minute, true), f.act("start", 2*time.Minute, true),
			f.act("confirmResize", 3*time.Minute, false), f.act("resize", time.Hour, false)), "first-start-after-resize")
		// Long after the resize still counts, since the window is the first start, not a time.
		ok(t, stopped(t, "powering-on", f.act("start", 0, false), f.act("confirmResize", 24*time.Hour, false),
			f.act("resize", 25*time.Hour, false)), "first-start-after-resize")
		ok(t, stopped(t, "reboot_started_hard", f.act("reboot", 0, false), f.act("confirmResize", time.Minute, false),
			f.act("resize", 2*time.Minute, false)), "first-start-after-resize")
	})

	for name, c := range map[string]struct {
		f      func(t *testing.T) *fixture
		status int
		code   string
	}{
		"cold migration": {func(t *testing.T) *fixture {
			f := running(t)
			f.cloud.actions[vmID][0].Action = "migrate"
			return f
		}, 403, issuerapi.CodeRefused},
		"no actions": {func(t *testing.T) *fixture {
			f := running(t)
			f.cloud.actions[vmID] = nil
			return f
		}, 403, issuerapi.CodeRefused},
		"actions forbidden": {func(t *testing.T) *fixture {
			f := running(t)
			f.cloud.fail["actions"] = fmt.Errorf("%w: 403", openstack.ErrForbidden)
			return f
		}, 503, issuerapi.CodeForbidden},
		"actions down": {func(t *testing.T) *fixture {
			f := running(t)
			f.cloud.fail["actions"] = errors.New("connection refused")
			return f
		}, 503, issuerapi.CodeUnavailable},
		"resize to no vTPM": {func(t *testing.T) *fixture {
			f := running(t)
			f.cloud.servers[vmID].Flavor.ExtraSpecs = nil
			return f
		}, 403, issuerapi.CodeRefused},
		"resize on another host": {func(t *testing.T) *fixture {
			f := running(t)
			f.cloud.servers[vmID].Host = "compute-2"
			return f
		}, 403, issuerapi.CodeRefused},
		"resized, not finishing": {func(t *testing.T) *fixture {
			f := running(t)
			f.cloud.servers[vmID].VMState, f.cloud.servers[vmID].TaskState = "resized", nil
			return f
		}, 403, issuerapi.CodeRefused},
		"started since the resize": {func(t *testing.T) *fixture {
			f := newFixture(t)
			return stopped(t, "powering-on", f.act("start", 0, false), f.act("stop", time.Minute, false),
				f.act("start", 2*time.Minute, false), f.act("confirmResize", 3*time.Minute, false), f.act("resize", 4*time.Minute, false))
		}, 403, issuerapi.CodeRefused},
		"rebooted since the resize": {func(t *testing.T) *fixture {
			f := newFixture(t)
			return stopped(t, "powering-on", f.act("start", 0, false), f.act("reboot", time.Minute, false), f.act("resize", 4*time.Minute, false))
		}, 403, issuerapi.CodeRefused},
		"migrated since the resize": {func(t *testing.T) *fixture {
			f := newFixture(t)
			return stopped(t, "powering-on", f.act("start", 0, false), f.act("migrate", time.Minute, false), f.act("resize", 4*time.Minute, false))
		}, 403, issuerapi.CodeRefused},
		"never resized": {func(t *testing.T) *fixture {
			f := newFixture(t)
			return stopped(t, "powering-on", f.act("start", 0, false), f.act("stop", time.Minute, false), f.act("create", time.Hour, false))
		}, 403, issuerapi.CodeRefused},
		"only a failed resize": {func(t *testing.T) *fixture {
			f := newFixture(t)
			return stopped(t, "powering-on", f.act("start", 0, false), f.act("resize", time.Minute, true))
		}, 403, issuerapi.CodeRefused},
		"powering on for a reboot": {func(t *testing.T) *fixture {
			f := newFixture(t)
			return stopped(t, "powering-on", f.act("reboot", 0, false), f.act("resize", time.Minute, false))
		}, 403, issuerapi.CodeRefused},
		"hard reboot for a start": {func(t *testing.T) *fixture {
			f := newFixture(t)
			return stopped(t, "reboot_started_hard", f.act("start", 0, false), f.act("resize", time.Minute, false))
		}, 403, issuerapi.CodeRefused},
		"running instance powering on": {func(t *testing.T) *fixture {
			f := newFixture(t)
			f2 := stopped(t, "powering-on", f.act("start", 0, false), f.act("resize", time.Minute, false))
			f2.cloud.servers[vmID].VMState = "active"
			return f2
		}, 403, issuerapi.CodeRefused},
		"soft reboot": {func(t *testing.T) *fixture {
			f := newFixture(t)
			return stopped(t, "reboot_started", f.act("reboot", 0, false), f.act("resize", time.Minute, false))
		}, 403, issuerapi.CodeRefused},
	} {
		t.Run(name, func(t *testing.T) {
			f := c.f(t)
			wantError(t, name, f.call(http.MethodPost, issuerapi.PathVMCertificate, "compute-1", vmRequest(t, vmID, &p384(t).PublicKey)), c.status, c.code)
			if strings.Contains(f.log.String(), `"msg":"issued"`) {
				t.Errorf("issued: %s", f.log)
			}
		})
	}
}

// Ensures a malformed request answers 400 without any lookup.
func TestVMCertificateInvalid(t *testing.T) {
	f := newFixture(t)
	f.addVM(vmID, "compute-1")
	key := swtpmKey(t, &p384(t).PublicKey)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := p256.PublicKey.Bytes()
	q := func(format string, a ...any) string { return fmt.Sprintf(format, a...) }

	for name, body := range map[string]string{
		"empty":          "",
		"not JSON":       "instance_uuid=" + vmID,
		"array":          `[]`,
		"unknown member": q(`{"instance_uuid":%q,"key":%q,"host":"compute-2"}`, vmID, key),
		"v4 member":      q(`{"instance_uuid":%q,"key":%q,"key_type":"ecc-p384"}`, vmID, key),
		"wrong type":     q(`{"instance_uuid":1,"key":%q}`, key),
		"no instance":    q(`{"key":%q}`, key),
		"uppercase UUID": q(`{"instance_uuid":%q,"key":%q}`, "AAAAAAAA-1111-4111-8111-111111111111", key),
		"UUID with name": q(`{"instance_uuid":%q,"key":%q}`, "instance-00000001:"+vmID, key),
		"no key":         q(`{"instance_uuid":%q}`, vmID),
		"RSA modulus":    q(`{"instance_uuid":%q,"key":"c0ffee"}`, vmID),
		"off the curve":  q(`{"instance_uuid":%q,"key":"x=01,y=02,id=secp384r1"}`, vmID),
		"P-256 key":      q(`{"instance_uuid":%q,"key":"x=%x,y=%x"}`, vmID, b[1:33], b[33:]),
		"another curve":  q(`{"instance_uuid":%q,"key":%q}`, vmID, strings.Replace(key, "secp384r1", "prime256v1", 1)),
	} {
		wantError(t, name, f.call(http.MethodPost, issuerapi.PathVMCertificate, "compute-1", []byte(body)), http.StatusBadRequest, issuerapi.CodeInvalid)
	}
	if calls := f.cloud.called(); len(calls) != 0 {
		t.Errorf("lookups for invalid requests: %q", calls)
	}

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if rec := f.call(method, issuerapi.PathVMCertificate, "compute-1", nil); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", method, rec.Code)
		}
	}
	if rec := f.call(http.MethodPost, "/v1/ek-certs", "compute-1", nil); rec.Code != http.StatusNotFound {
		t.Errorf("the v4 path: %d", rec.Code)
	}
}

// Ensures every refusal is logged as one JSON line with its reason.
func TestAuditLog(t *testing.T) {
	f := newFixture(t)
	f.addVM(vmID, "compute-1")
	body := vmRequest(t, vmID, &p384(t).PublicKey)
	f.call(http.MethodPost, issuerapi.PathVMCertificate, "compute-2", body)
	f.call(http.MethodPost, issuerapi.PathVMCertificate, "", body)

	var lines []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(f.log.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		lines = append(lines, m)
	}
	if len(lines) != 2 {
		t.Fatalf("%d log lines, want 2:\n%s", len(lines), f.log)
	}
	for i, want := range []map[string]any{
		{"msg": "refused", "level": "WARN", "request": "vm", "host": "compute-2", "instance_uuid": vmID, "reason": issuerapi.CodeRefused},
		{"msg": "refused", "level": "WARN", "request": "vm", "reason": issuerapi.CodeRefused},
	} {
		for k, w := range want {
			if lines[i][k] != w {
				t.Errorf("line %d: %s = %v, want %v", i, k, lines[i][k], w)
			}
		}
	}
	if _, ok := lines[0]["detail"]; !ok {
		t.Error("a refusal without a detail")
	}
	if _, ok := lines[1]["host"]; ok {
		t.Error("a host logged for a request without a client certificate")
	}
}
