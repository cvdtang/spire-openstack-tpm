package nodeattestor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/openstack"
	"github.com/cvdtang/openstack-tpm/internal/pkitest"
)

const (
	instanceID = "11111111-1111-4111-8111-111111111111"
	projectID  = "0123456789abcdef0123456789abcdef"
	userID     = "fedcba9876543210fedcba9876543210"
)

// pki is the provider's EK root and issuing intermediate, and the bundle a server is configured with.
type pki struct {
	root, issuing *pkitest.CA
	bundle        string
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	root := pkitest.NewCA(t, "root", nil)
	issuing := pkitest.NewIssuing(t, "issuing", root)
	return &pki{root, issuing, pkitest.WriteBundle(t, root, issuing)}
}

func testClaims() contract.Claims {
	return contract.Claims{
		Region: "RegionOne", DomainID: "domain-a", ProjectID: projectID, InstanceID: instanceID,
		Kind: contract.KindVM, UserID: userID,
	}
}

// cert issues a certificate for the claims and a fresh key.
func (p *pki) cert(t *testing.T, c contract.Claims) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := contract.Build(c, &key.PublicKey, time.Now(), p.issuing.Cert, p.issuing.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// attestor builds an Attestor from the bundle and more HCL.
func (p *pki) attestor(t *testing.T, hcl string, clouds Clouds) *Attestor {
	t.Helper()
	cfg, err := ParseConfig(fmt.Sprintf("ca_bundle = %q\n%s", p.bundle, hcl))
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, clouds)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func secretFile(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// Ensures the server plugin's config needs a bundle, an allowlist and consistent OpenStack settings.
func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig(`
		ca_bundle = "/etc/spire/ek-bundle.pem"
		projects  = ["p1", "p2"]
	`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NovaSelectors || cfg.KeystoneSelectors || cfg.OpenStack != nil ||
		!slices.Equal(cfg.Projects, []string{"p1", "p2"}) || len(cfg.Domains) != 0 {
		t.Errorf("defaults: %+v", cfg)
	}

	cfg, err = ParseConfig(`
		ca_bundle          = "/etc/spire/ek-bundle.pem"
		projects           = ["p1"]
		domains            = ["d1", "*"]
		nova_selectors     = true
		keystone_selectors = true
		openstack {
			auth_url    = "https://keystone.example:5000/v3"
			credentials = [
				{ application_credential_id = "abc", application_credential_secret_file = "/etc/spire/app.secret" },
				{ username = "spire", password_file = "/etc/spire/password" },
				{ username = "spire2", user_domain_name = "infra", password_file = "/etc/spire/password2" },
			]
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NovaSelectors || !cfg.KeystoneSelectors ||
		!slices.Equal(cfg.Domains, []string{"d1", "*"}) {
		t.Errorf("config: %+v", cfg)
	}
	os := cfg.OpenStack
	if os == nil || os.AuthURL != "https://keystone.example:5000/v3" || len(os.Credentials) != 3 {
		t.Fatalf("openstack: %+v", os)
	}
	if c := os.Credentials[0]; c.AppCredID != "abc" || c.AppCredSecretFile != "/etc/spire/app.secret" || c.UserDomainName != "" {
		t.Errorf("application credential: %+v", c)
	}
	if c := os.Credentials[1]; c.Username != "spire" || c.PasswordFile != "/etc/spire/password" || c.UserDomainName != "Default" {
		t.Errorf("user: %+v", c)
	}
	if c := os.Credentials[2]; c.UserDomainName != "infra" {
		t.Errorf("user in a domain: %+v", c)
	}

	openstackBlock := func(body string) string {
		return `
			ca_bundle      = "b"
			projects       = ["p"]
			nova_selectors = true
			openstack {
				auth_url = "u"
				` + body + `
			}`
	}
	for name, hcl := range map[string]string{
		"empty":        ``,
		"syntax":       `ca_bundle = `,
		"no bundle":    `projects = ["p"]`,
		"no allowlist": `ca_bundle = "b"`,
		"empty allowlists": `
			ca_bundle = "b"
			projects  = []
			domains   = []`,
		"wildcard project": `
			ca_bundle = "b"
			projects  = ["*"]`,
		"empty project": `
			ca_bundle = "b"
			projects  = ["p", ""]`,
		"empty domain": `
			ca_bundle = "b"
			domains   = [""]`,
		"nova without openstack": `
			ca_bundle      = "b"
			projects       = ["p"]
			nova_selectors = true`,
		"keystone without openstack": `
			ca_bundle          = "b"
			projects           = ["p"]
			keystone_selectors = true`,
		"openstack without a reader": `
			ca_bundle = "b"
			projects  = ["p"]
			openstack {
				auth_url    = "u"
				credentials = [{ application_credential_id = "a", application_credential_secret_file = "f" }]
			}`,
		"no auth_url": `
			ca_bundle      = "b"
			projects       = ["p"]
			nova_selectors = true
			openstack {
				credentials = [{ application_credential_id = "a", application_credential_secret_file = "f" }]
			}`,
		"no credentials":                openstackBlock(``),
		"empty credentials":             openstackBlock(`credentials = []`),
		"empty credential":              openstackBlock(`credentials = [{}]`),
		"app credential and user":       openstackBlock(`credentials = [{ application_credential_id = "a", application_credential_secret_file = "f", username = "u", password_file = "p" }]`),
		"app credential without secret": openstackBlock(`credentials = [{ application_credential_id = "a" }]`),
		"secret without app credential": openstackBlock(`credentials = [{ application_credential_secret_file = "f" }]`),
		"user without password":         openstackBlock(`credentials = [{ username = "u" }]`),
		"password without user":         openstackBlock(`credentials = [{ password_file = "p" }]`),
		"domain without user":           openstackBlock(`credentials = [{ user_domain_name = "d" }]`),
		"second credential":             openstackBlock(`credentials = [{ username = "u", password_file = "p" }, { username = "v" }]`),
		"wrong type": `
			ca_bundle      = "b"
			projects       = "p"
			nova_selectors = "yes"`,
	} {
		if cfg, err := ParseConfig(hcl); err == nil {
			t.Errorf("%s: accepted as %+v", name, cfg)
		}
	}

}

// Ensures Check and New fail when a configured file is unusable.
func TestCheck(t *testing.T) {
	p := newPKI(t)
	secret := secretFile(t, "s3cret\n")
	config := func(bundle, secretFile string) *Config {
		cfg, err := ParseConfig(fmt.Sprintf(`
			ca_bundle      = %q
			domains        = ["*"]
			nova_selectors = true
			openstack {
				auth_url    = "http://127.0.0.1:1/v3"
				credentials = [{ username = "spire", password_file = %q }]
			}`, bundle, secretFile))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	if err := config(p.bundle, secret).Check(); err != nil {
		t.Error(err)
	}
	if _, err := New(config(p.bundle, secret), nil); err != nil {
		t.Error(err)
	}
	for name, cfg := range map[string]*Config{
		"missing bundle":   config(filepath.Join(t.TempDir(), "missing"), secret),
		"bundle is no PEM": config(secret, secret),
		"missing secret":   config(p.bundle, filepath.Join(t.TempDir(), "missing")),
		"empty secret":     config(p.bundle, secretFile(t, " \n")),
	} {
		if err := cfg.Check(); err == nil {
			t.Errorf("%s: Check passed", name)
		}
		if _, err := New(cfg, nil); err == nil {
			t.Errorf("%s: New passed", name)
		}
	}
	// A server that reads nothing from OpenStack needs only the bundle.
	cfg, err := ParseConfig(fmt.Sprintf("ca_bundle = %q\nprojects = [%q]", p.bundle, projectID))
	if err != nil || cfg.Check() != nil {
		t.Errorf("certificate-only config: %v", err)
	}
}

// Ensures a certificate is accepted only if it chains, has the profile and is on the allowlist.
func TestVerify(t *testing.T) {
	p := newPKI(t)
	der := p.cert(t, testClaims())
	sub := testClaims()
	sub.ProjectID, sub.Ancestors = "sub-project", []string{projectID}
	subDER := p.cert(t, sub)

	for name, c := range map[string]struct {
		hcl     string
		allowed bool
	}{
		"project":                 {fmt.Sprintf(`projects = ["other", %q]`, projectID), true},
		"domain":                  {`domains = ["domain-a"]`, true},
		"all domains":             {`domains = ["*"]`, true},
		"all domains and more":    {`domains = ["domain-b", "*"]` + "\n" + `projects = ["other"]`, true},
		"project or domain":       {`projects = ["other"]` + "\n" + `domains = ["domain-a"]`, true},
		"another project":         {`projects = ["other"]`, false},
		"another domain":          {`domains = ["domain-b"]`, false},
		"neither":                 {`projects = ["other"]` + "\n" + `domains = ["domain-b"]`, false},
		"project ID as a domain":  {fmt.Sprintf(`domains = [%q]`, projectID), false},
		"domain ID as a project":  {`projects = ["domain-a"]`, false},
		"prefix of the project":   {fmt.Sprintf(`projects = [%q]`, projectID[:16]), false},
		"uppercase project":       {fmt.Sprintf(`projects = [%q]`, strings.ToUpper(projectID)), false},
		"the instance as project": {fmt.Sprintf(`projects = [%q]`, instanceID), false},
	} {
		a := p.attestor(t, c.hcl, nil)
		v, err := a.Verify(der)
		switch {
		case c.allowed && (err != nil || !v.Claims.Equal(testClaims())):
			t.Errorf("%s: %v", name, err)
		case !c.allowed && !errors.Is(err, ErrRefused):
			t.Errorf("%s: %v, want ErrRefused", name, err)
		case !c.allowed && (errors.Is(err, contract.ErrChainInvalid) || errors.Is(err, ErrMismatch) || errors.Is(err, ErrUnavailable)):
			t.Errorf("%s: %v wraps another kind", name, err)
		}
	}

	// A parent on the allowlist does not cover its sub-projects, but the domain does.
	if _, err := p.attestor(t, fmt.Sprintf(`projects = [%q]`, projectID), nil).Verify(subDER); !errors.Is(err, ErrRefused) {
		t.Errorf("sub-project of an allowed project: %v", err)
	}
	if _, err := p.attestor(t, `domains = ["domain-a"]`, nil).Verify(subDER); err != nil {
		t.Errorf("sub-project in an allowed domain: %v", err)
	}

	// The chain comes first, so another PKI's certificate is refused even for an allowed project.
	a := p.attestor(t, `domains = ["*"]`, nil)
	forged := newPKI(t).cert(t, testClaims())
	if _, err := a.Verify(forged); !errors.Is(err, ErrRefused) || !errors.Is(err, contract.ErrChainInvalid) {
		t.Errorf("certificate of another PKI: %v", err)
	}
	for _, junk := range [][]byte{nil, []byte("junk"), der[:len(der)-1]} {
		if _, err := a.Verify(junk); !errors.Is(err, ErrRefused) {
			t.Errorf("junk: %v", err)
		}
	}
	// A chain that is good and a profile that is not.
	if _, err := a.Verify(p.issuing.Cert.Raw); !errors.Is(err, ErrRefused) || !errors.Is(err, contract.ErrProfile) {
		t.Errorf("the issuing certificate as an instance's: %v", err)
	}
}

// Ensures the agent path is derived from the certificate's region, project and instance.
func TestAgentPath(t *testing.T) {
	p := newPKI(t)
	v, err := p.attestor(t, `domains = ["*"]`, nil).Verify(p.cert(t, testClaims()))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := AgentPath(v), "RegionOne/"+projectID+"/"+instanceID; got != want {
		t.Errorf("AgentPath %q, want %q", got, want)
	}
}

// fakeAPI is Nova and Keystone as one credential sees them.
type fakeAPI struct {
	mu          sync.Mutex
	server      *openstack.Server
	project     *openstack.Project
	serverErr   error
	projectErr  error
	serverCalls int
	projCalls   int
}

func (f *fakeAPI) GetServer(_ context.Context, id string) (*openstack.Server, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.serverCalls++
	if f.serverErr != nil {
		return nil, f.serverErr
	}
	if f.server == nil || f.server.ID != id {
		return nil, fmt.Errorf("%w: server %s", openstack.ErrNotFound, id)
	}
	s := *f.server
	return &s, nil
}

func (f *fakeAPI) GetProject(_ context.Context, id string) (*openstack.Project, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.projCalls++
	if f.projectErr != nil {
		return nil, f.projectErr
	}
	if f.project == nil || f.project.ID != id {
		return nil, fmt.Errorf("%w: project %s", openstack.ErrNotFound, id)
	}
	p := *f.project
	return &p, nil
}

// fakeClouds hands out one fakeAPI and notes for which project and region.
type fakeClouds struct {
	api   *fakeAPI
	err   error
	asked []string
}

func (f *fakeClouds) For(_ context.Context, project, region string) (openstack.API, error) {
	f.asked = append(f.asked, project+"@"+region)
	if f.err != nil {
		return nil, f.err
	}
	return f.api, nil
}

// noClouds fails the test if the attestor asks for OpenStack at all.
type noClouds struct{ t *testing.T }

func (n noClouds) For(context.Context, string, string) (openstack.API, error) {
	n.t.Error("a server without nova_selectors and keystone_selectors asked for an OpenStack client")
	return nil, errors.New("unexpected")
}

func newFakeClouds() *fakeClouds {
	s := &openstack.Server{
		ID: instanceID, Name: "web-1", Status: "ACTIVE", TenantID: projectID, UserID: userID, AZ: "nova",
		Image: json.RawMessage(`{"id":"image-1","links":[]}`), Tags: []string{"web", "blue"},
	}
	s.Flavor.OriginalName = "m1.tpm"
	return &fakeClouds{api: &fakeAPI{
		server:  s,
		project: &openstack.Project{ID: projectID, Name: "tenant-a", DomainID: "domain-a", ParentID: "domain-a", Tags: []string{"prod", "eu"}},
	}}
}

const openstackHCL = `
	openstack {
		auth_url    = "http://127.0.0.1:1/v3"
		credentials = [{ username = "spire", password_file = "/dev/null" }]
	}
`

func mustSelectors(t *testing.T, a *Attestor, der []byte) []string {
	t.Helper()
	v, err := a.Verify(der)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := a.Selectors(t.Context(), v)
	if err != nil {
		t.Fatal(err)
	}
	return sel
}

// Ensures the certificate alone yields its selectors without any OpenStack client.
func TestSelectorsFromCertificate(t *testing.T) {
	p := newPKI(t)
	a := p.attestor(t, `domains = ["*"]`, noClouds{t})
	der := p.cert(t, testClaims())
	v, err := a.Verify(der)
	if err != nil {
		t.Fatal(err)
	}
	keyHash, _ := contract.KeyHash(v.Key)
	want := []string{
		"region:RegionOne",
		"domain:id:domain-a",
		"project:id:" + projectID,
		"project:parent:id:domain-a",
		"instance:id:" + instanceID,
		"instance:kind:vm",
		"instance:user:id:" + userID,
		"tpm:key:sha256:" + keyHash,
	}
	if got := mustSelectors(t, a, der); !slices.Equal(got, want) {
		t.Errorf("selectors\n got %q\nwant %q", got, want)
	}

	// A sub-project's parent is its nearest ancestor, and each ancestor project but not the domain is a selector.
	c := testClaims()
	c.Kind, c.Ancestors = contract.KindBaremetal, []string{"root-project", "parent-project"}
	got := mustSelectors(t, a, p.cert(t, c))
	for _, s := range []string{
		"instance:kind:baremetal", "project:parent:id:parent-project",
		"project:ancestor:id:root-project", "project:ancestor:id:parent-project",
	} {
		if !slices.Contains(got, s) {
			t.Errorf("no selector %q in %q", s, got)
		}
	}
	if len(got) != len(want)+2 {
		t.Errorf("%d selectors, want %d: %q", len(got), len(want)+2, got)
	}
}

// Ensures nova_selectors and keystone_selectors each read only their service and add sorted live selectors after the certificate's.
func TestSelectorsFromNovaAndKeystone(t *testing.T) {
	p := newPKI(t)
	der := p.cert(t, testClaims())

	for name, c := range map[string]struct {
		hcl                       string
		serverCalls, projectCalls int
	}{
		"nova":     {`nova_selectors = true`, 1, 0},
		"keystone": {`keystone_selectors = true`, 0, 1},
		"both":     {`nova_selectors = true` + "\n" + `keystone_selectors = true`, 1, 1},
	} {
		clouds := newFakeClouds()
		a := p.attestor(t, `domains = ["*"]`+"\n"+c.hcl+openstackHCL, clouds)
		got := mustSelectors(t, a, der)
		// The certificate's selectors come first, then the live ones, sorted.
		if len(got) <= 8 || got[0] != "region:RegionOne" || !strings.HasPrefix(got[7], "tpm:key:sha256:") || !slices.IsSorted(got[8:]) {
			t.Errorf("%s: selectors %q", name, got)
		}
		if clouds.api.serverCalls != c.serverCalls || clouds.api.projCalls != c.projectCalls {
			t.Errorf("%s: %d Nova and %d Keystone reads", name, clouds.api.serverCalls, clouds.api.projCalls)
		}
	}

	// Values that are absent or cannot be a selector are left out.
	clouds := newFakeClouds()
	s := clouds.api.server
	s.Image = json.RawMessage(`""`) // boot from volume
	s.AZ = ""
	s.Name = "two\nlines"
	s.Tags = []string{"ok", "", "bell\a", strings.Repeat("x", 256), "zero\u200bwidth", "ünï", string([]byte{0xff})}
	clouds.api.project.Name = "tenant\x00"
	clouds.api.project.Tags = nil
	a := p.attestor(t, `
		domains            = ["*"]
		nova_selectors     = true
		keystone_selectors = true`+openstackHCL, clouds)
	got := mustSelectors(t, a, der)
	if want := []string{"instance:flavor:m1.tpm", "instance:tag:ok", "instance:tag:ünï"}; !slices.Equal(got[8:], want) {
		t.Errorf("selectors %q, want %q", got[8:], want)
	}
}

// Ensures live selectors fail with exactly one error kind for a contradiction, a refusal or an outage.
func TestSelectorsRefusals(t *testing.T) {
	p := newPKI(t)
	down := errors.New("connection refused")
	withAncestors := testClaims()
	withAncestors.Ancestors = []string{"root-project", "parent-project"}

	for name, c := range map[string]struct {
		claims contract.Claims
		mod    func(f *fakeClouds)
		want   error
	}{
		// Nova or Keystone contradicts the certificate.
		"project":         {testClaims(), func(f *fakeClouds) { f.api.server.TenantID = "another" }, ErrMismatch},
		"user":            {testClaims(), func(f *fakeClouds) { f.api.server.UserID = "another" }, ErrMismatch},
		"domain":          {testClaims(), func(f *fakeClouds) { f.api.project.DomainID = "domain-b" }, ErrMismatch},
		"ancestors":       {testClaims(), func(f *fakeClouds) { f.api.project.Ancestors = []string{"another"} }, ErrMismatch},
		"fewer ancestors": {withAncestors, func(f *fakeClouds) { f.api.project.Ancestors = []string{"parent-project"} }, ErrMismatch},
		// The instance or the project is gone.
		"instance deleted": {testClaims(), func(f *fakeClouds) { f.api.server = nil }, ErrRefused},
		"instance hidden":  {testClaims(), func(f *fakeClouds) { f.api.serverErr = fmt.Errorf("%w: GET", openstack.ErrForbidden) }, ErrRefused},
		"project deleted":  {testClaims(), func(f *fakeClouds) { f.api.project = nil }, ErrRefused},
		"project hidden":   {testClaims(), func(f *fakeClouds) { f.api.projectErr = fmt.Errorf("%w: GET", openstack.ErrForbidden) }, ErrRefused},
		"no credential":    {testClaims(), func(f *fakeClouds) { f.err = fmt.Errorf("%w: no configured credential serves project", ErrRefused) }, ErrRefused},
		// Nova or Keystone cannot be asked, so the agent retries.
		"nova down":            {testClaims(), func(f *fakeClouds) { f.api.serverErr = down }, ErrUnavailable},
		"keystone down":        {testClaims(), func(f *fakeClouds) { f.api.projectErr = down }, ErrUnavailable},
		"no token":             {testClaims(), func(f *fakeClouds) { f.api.serverErr = fmt.Errorf("%w: 401", openstack.ErrAuth) }, ErrUnavailable},
		"no token for project": {testClaims(), func(f *fakeClouds) { f.api.projectErr = fmt.Errorf("%w: 401", openstack.ErrAuth) }, ErrUnavailable},
		"no endpoint":          {testClaims(), func(f *fakeClouds) { f.api.serverErr = fmt.Errorf("%w: compute", openstack.ErrNoEndpoint) }, ErrUnavailable},
		"credential down":      {testClaims(), func(f *fakeClouds) { f.err = fmt.Errorf("%w: keystone did not answer", ErrUnavailable) }, ErrUnavailable},
	} {
		clouds := newFakeClouds()
		c.mod(clouds)
		a := p.attestor(t, `
		domains            = ["*"]
		nova_selectors     = true
		keystone_selectors = true`+openstackHCL, clouds)
		v, err := a.Verify(p.cert(t, c.claims))
		if err != nil {
			t.Fatal(err)
		}
		sel, err := a.Selectors(t.Context(), v)
		if !errors.Is(err, c.want) || sel != nil {
			t.Errorf("%s: selectors %q, %v; want %v", name, sel, err, c.want)
		}
		for _, other := range []error{ErrRefused, ErrMismatch, ErrUnavailable} {
			if other != c.want && errors.Is(err, other) {
				t.Errorf("%s: %v also wraps %v", name, err, other)
			}
		}
	}

	// A missing role assignment is named, so it is not mistaken for Nova being down.
	clouds := newFakeClouds()
	clouds.api.serverErr = fmt.Errorf("%w: 401", openstack.ErrAuth)
	a := p.attestor(t, `
		domains        = ["*"]
		nova_selectors = true`+openstackHCL, clouds)
	v, _ := a.Verify(p.cert(t, testClaims()))
	if _, err := a.Selectors(t.Context(), v); err == nil || !strings.Contains(err.Error(), "lacks reader") || !strings.Contains(err.Error(), projectID) {
		t.Errorf("refused token: %v", err)
	}

}

// keystone is a fake Keystone with application credentials, a user with reader on every project and, if given, nova in its catalog.
// A project's name is the token it was read with.
type keystone struct {
	*httptest.Server
	mu    sync.Mutex
	auths int
	down  bool
}

var appCredProjects = map[string]string{"app": projectID, "app-p1": "p1", "app-p3": "p3"}

func newKeystone(t *testing.T, nova string) *keystone {
	t.Helper()
	k := &keystone{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Auth struct {
				Identity struct {
					AppCred struct {
						ID     string `json:"id"`
						Secret string `json:"secret"`
					} `json:"application_credential"`
					Password struct {
						User struct {
							Name     string `json:"name"`
							Password string `json:"password"`
							Domain   struct {
								Name string `json:"name"`
							} `json:"domain"`
						} `json:"user"`
					} `json:"password"`
				} `json:"identity"`
				Scope struct {
					Project struct {
						ID string `json:"id"`
					} `json:"project"`
				} `json:"scope"`
			} `json:"auth"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		k.mu.Lock()
		k.auths++
		down := k.down
		k.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		var token, project string
		id, user := body.Auth.Identity.AppCred, body.Auth.Identity.Password.User
		switch {
		case appCredProjects[id.ID] != "" && id.Secret == "app-secret":
			token, project = id.ID, appCredProjects[id.ID]
		case user.Name == "spire" && user.Password == "user-secret" && user.Domain.Name == "Default":
			project = body.Auth.Scope.Project.ID
			token = "spire-in-" + project
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		catalog := []any{}
		if nova != "" {
			catalog = append(catalog, map[string]any{"type": "compute", "endpoints": []any{
				map[string]string{"interface": "public", "region_id": "RegionOne", "url": nova + "/v2.1"},
			}})
		}
		w.Header().Set("X-Subject-Token", token)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": map[string]any{
			"expires_at": time.Now().Add(time.Hour), "project": map[string]string{"id": project}, "catalog": catalog,
		}})
	})
	mux.HandleFunc("GET /v3/projects/{id}", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Auth-Token")
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"project": map[string]any{
			"id": r.PathValue("id"), "name": token, "domain_id": "domain-a", "parent_id": "domain-a",
			"parents": map[string]any{"domain-a": nil},
		}})
	})
	k.Server = httptest.NewServer(mux)
	t.Cleanup(k.Close)
	return k
}

func (k *keystone) authCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.auths
}

// newNova is a fake Nova that serves the test instance to the application credential "app".
func newNova(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2.1/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") != "app" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"server": map[string]any{
			"id": r.PathValue("id"), "name": "web-1", "status": "ACTIVE", "tenant_id": projectID, "user_id": userID,
			"image": "", "flavor": map[string]any{"original_name": "m1.tpm"},
		}})
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// Ensures each project is served by the right configured credential, with one cached client per project and region.
func TestConfiguredCredentials(t *testing.T) {
	p := newPKI(t)
	k := newKeystone(t, "")
	ctx := t.Context()
	app, user := secretFile(t, "app-secret\n"), secretFile(t, "user-secret\n")
	clouds := func(credentials string) *configClouds {
		t.Helper()
		cfg, err := ParseConfig(fmt.Sprintf(`
			ca_bundle          = %q
			domains            = ["*"]
			keystone_selectors = true
			openstack {
				auth_url    = %q
				credentials = [%s]
			}`, p.bundle, k.URL+"/v3", credentials))
		if err != nil {
			t.Fatal(err)
		}
		c, err := newClouds(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	appCred := func(id string) string {
		return fmt.Sprintf(`{ application_credential_id = %q, application_credential_secret_file = %q }`, id, app)
	}
	userCred := fmt.Sprintf(`{ username = "spire", password_file = %q }`, user)
	// readAs is the token a project is read with.
	readAs := func(c *configClouds, project string) (string, error) {
		api, err := c.For(ctx, project, "RegionOne")
		if err != nil {
			return "", err
		}
		proj, err := api.GetProject(ctx, project)
		if err != nil {
			return "", err
		}
		return proj.Name, nil
	}

	// With both kinds, the application credential serves its project and the user the rest.
	both := clouds(userCred + ", " + appCred("app-p1") + ", " + appCred("app-p3"))
	for project, want := range map[string]string{"p1": "app-p1", "p3": "app-p3", "p2": "spire-in-p2", "p9": "spire-in-p9"} {
		if got, err := readAs(both, project); err != nil || got != want {
			t.Errorf("project %s read with %q, %v; want %q", project, got, err, want)
		}
	}
	// A client and its token are reused for a project and region.
	before := k.authCount()
	first, _ := both.For(ctx, "p2", "RegionOne")
	second, _ := both.For(ctx, "p2", "RegionOne")
	other, _ := both.For(ctx, "p2", "RegionTwo")
	if first != second || first == other {
		t.Error("clients are not kept per project and region")
	}
	if _, err := readAs(both, "p2"); err != nil || k.authCount() != before {
		t.Errorf("%d authentications for a project that was read before", k.authCount()-before)
	}

	// With only an application credential, another project has no credential.
	only := clouds(appCred("app-p1"))
	if got, err := readAs(only, "p1"); err != nil || got != "app-p1" {
		t.Errorf("own project: %q, %v", got, err)
	}
	if _, err := only.For(ctx, "p2", "RegionOne"); !errors.Is(err, ErrRefused) || errors.Is(err, ErrUnavailable) {
		t.Errorf("project without a credential: %v", err)
	}

	// A refused application credential is unavailable, not refused, because its project is not known.
	gone := clouds(appCred("deleted"))
	if _, err := gone.For(ctx, "p1", "RegionOne"); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRefused) {
		t.Errorf("deleted application credential: %v", err)
	}
	// With a user next to it, the user serves the project.
	if got, err := readAs(clouds(appCred("deleted")+", "+userCred), "p1"); err != nil || got != "spire-in-p1" {
		t.Errorf("user next to a deleted application credential: %q, %v", got, err)
	}

	// Keystone down.
	k.mu.Lock()
	k.down = true
	k.mu.Unlock()
	if _, err := clouds(appCred("app-p1")).For(ctx, "p1", "RegionOne"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Keystone down: %v", err)
	}

	// No credentials at all (a certificate-only server never asks).
	cfg, err := ParseConfig(fmt.Sprintf(`
		ca_bundle = %q
		domains   = ["*"]
	`, p.bundle))
	if err != nil {
		t.Fatal(err)
	}
	none, err := newClouds(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := none.For(ctx, "p1", "RegionOne"); !errors.Is(err, ErrRefused) {
		t.Errorf("no credentials: %v", err)
	}
}

// Ensures a user's refused password makes live selectors unavailable, and the right one works.
func TestSelectorsWithRefusedCredential(t *testing.T) {
	p := newPKI(t)
	k := newKeystone(t, "")
	a := p.attestor(t, fmt.Sprintf(`
		domains            = ["*"]
		keystone_selectors = true
		openstack {
			auth_url    = %q
			credentials = [{ username = "spire", password_file = %q }]
		}`, k.URL+"/v3", secretFile(t, "wrong")), nil)
	v, err := a.Verify(p.cert(t, testClaims()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Selectors(t.Context(), v); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "keystone refused a token") {
		t.Errorf("wrong password: %v", err)
	}

	// With the right one the project's name is a selector.
	a = p.attestor(t, fmt.Sprintf(`
		domains            = ["*"]
		keystone_selectors = true
		openstack {
			auth_url    = %q
			credentials = [{ username = "spire", password_file = %q }]
		}`, k.URL+"/v3", secretFile(t, "user-secret")), nil)
	if got := mustSelectors(t, a, p.cert(t, testClaims())); !slices.Contains(got, "project:name:spire-in-"+projectID) {
		t.Errorf("selectors %q", got)
	}
}

// Ensures only bounded, printable UTF-8 values become selectors.
func TestValidValue(t *testing.T) {
	for v, want := range map[string]bool{
		"web": true, "a b": true, "ünï": true, strings.Repeat("x", 255): true,
		"": false, strings.Repeat("x", 256): false, "a\nb": false, "a\x00": false, "a\u200bb": false, "\xff": false,
	} {
		if got := validValue(v); got != want {
			t.Errorf("validValue(%q) = %v", v, got)
		}
	}
}
