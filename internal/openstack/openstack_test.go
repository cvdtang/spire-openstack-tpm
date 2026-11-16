package openstack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCloud serves Keystone, Nova, Placement and Ironic for RegionOne and Nova and Ironic for RegionTwo; its tokens name their project.
type fakeCloud struct {
	*httptest.Server
	auths    atomic.Int32
	revoked  atomic.Bool // next Nova call answers 401 once
	noToken  bool        // Keystone answers without X-Subject-Token
	novaPath string      // RegionOne's Nova URL path in the catalog (default /nova/v2.1)
	scoped   atomic.Bool // the last token request asked for a scope

	mu      sync.Mutex
	headers map[string]http.Header // last request headers by path
}

func newFakeCloud(t *testing.T) *fakeCloud {
	f := &fakeCloud{novaPath: "/nova/v2.1", headers: map[string]http.Header{}}
	mux := http.NewServeMux()
	handle := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.headers[r.URL.Path] = r.Header.Clone()
			f.mu.Unlock()
			h(w, r)
		})
	}
	handle("POST /v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Auth struct {
				Identity struct {
					Methods []string `json:"methods"`
				} `json:"identity"`
				Scope *struct {
					Project struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"project"`
				} `json:"scope"`
			} `json:"auth"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.scoped.Store(body.Auth.Scope != nil)
		f.auths.Add(1)
		// An application credential is fixed to its project.
		project := "app-project"
		if slices.Contains(body.Auth.Identity.Methods, "password") && body.Auth.Scope != nil {
			if project = body.Auth.Scope.Project.ID; project == "" {
				project = "id-of-" + body.Auth.Scope.Project.Name
			}
		}
		if !f.noToken {
			w.Header().Set("X-Subject-Token", "token-for-"+project)
		}
		ep := func(iface, region, path string) map[string]string {
			return map[string]string{"interface": iface, "region_id": region, "url": f.URL + path}
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": map[string]any{
			"expires_at": time.Now().Add(time.Hour),
			"project":    map[string]string{"id": project},
			"catalog": []map[string]any{
				{"type": "identity", "endpoints": []any{ep("public", "RegionOne", "/v3")}},
				{"type": "compute", "endpoints": []any{
					ep("internal", "RegionTwo", "/two/v2.1"), ep("internal", "RegionOne", f.novaPath), ep("public", "RegionOne", f.novaPath),
				}},
				{"type": "placement", "endpoints": []any{ep("internal", "RegionOne", "/placement/")}},
				// Ironic's endpoint with and without the version, as deployments have it.
				{"type": "baremetal", "endpoints": []any{ep("internal", "RegionOne", "/baremetal"), ep("internal", "RegionTwo", "/baremetal-two/v1")}},
			},
		}})
	})
	server := func(region string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if f.revoked.CompareAndSwap(true, false) {
				http.Error(w, "revoked", http.StatusUnauthorized)
				return
			}
			if r.Header.Get("OpenStack-API-Version") != "compute 2.47" {
				http.Error(w, "microversion", http.StatusBadRequest)
				return
			}
			switch id := r.PathValue("id"); id {
			case "s1":
				_ = json.NewEncoder(w).Encode(map[string]any{"server": map[string]any{
					"id": id, "name": "in " + region, "status": "ACTIVE", "tenant_id": "p1", "image": map[string]string{"id": "img"},
					"flavor": map[string]any{"original_name": "m1.vtpm", "extra_specs": map[string]string{"hw:tpm_version": "2.0", "hw:tpm_secret_security": "host"}},
				}})
			case "bm":
				_ = json.NewEncoder(w).Encode(map[string]any{"server": map[string]any{
					"id": id, "name": "in " + region, "status": "BUILD", "tenant_id": "p1", "user_id": "u1",
					"OS-EXT-SRV-ATTR:host": "ironic-host", "OS-EXT-SRV-ATTR:hypervisor_hostname": "node-1",
					"OS-EXT-STS:vm_state": "building", "OS-EXT-STS:task_state": "spawning", "image": "",
				}})
			case "gone":
				_ = json.NewEncoder(w).Encode(map[string]any{"server": map[string]any{"id": id, "status": "DELETED"}})
			case "hidden":
				http.Error(w, "forbidden", http.StatusForbidden)
			default:
				http.Error(w, "not found", http.StatusNotFound)
			}
		}
	}
	handle("GET /nova/v2.1/servers/{id}", server("RegionOne"))
	handle("GET /nova/v2.1/p1/servers/{id}", server("RegionOne")) // an endpoint that ends in the project ID
	handle("GET /two/v2.1/servers/{id}", server("RegionTwo"))
	handle("GET /nova/v2.1/servers/{id}/os-instance-actions", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("OpenStack-API-Version") != "compute 2.47" || r.PathValue("id") != "s1" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json") // as Nova; gophercloud's pager parses only JSON
		_, _ = io.WriteString(w, `{"instanceActions": [
			{"action": "create", "request_id": "req-1", "user_id": "u1", "message": null, "start_time": "2026-11-13T12:17:13.000000"},
			{"action": "resize", "request_id": "req-3", "user_id": "u1", "message": null, "start_time": "2026-11-13T12:19:15.000000"},
			{"action": "resize", "request_id": "req-2", "user_id": "u1", "message": "Error", "start_time": "2026-11-13T12:17:26.000000"}]}`)
	})
	handle("GET /v3/projects/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.Query().Has("parents_as_ids") {
			http.Error(w, "want parents_as_ids", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"project": map[string]any{
			"id": r.PathValue("id"), "domain_id": "default", "parent_id": "p0", "tags": []string{"a"},
			"parents": map[string]any{"p0": map[string]any{"default": nil}},
		}})
	})
	handle("GET /placement/allocations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "bm" {
			_ = json.NewEncoder(w).Encode(map[string]any{"allocations": map[string]any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p1", "user_id": "u1", "allocations": map[string]any{
			"node-1": map[string]any{"resources": map[string]int{"CUSTOM_BAREMETAL": 1}},
		}})
	})
	node := func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("id") {
		case "node-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uuid": "node-1", "name": "bm-1", "provision_state": "wait call-back", "instance_uuid": "bm",
				"maintenance": false, "lessee": "p1", "driver_info": map[string]string{"redfish_password": "******"},
			})
		case "hidden":
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}
	handle("GET /baremetal/v1/nodes/{id}", node)
	handle("GET /baremetal-two/v1/nodes/{id}", node)
	handle("GET /baremetal/v1/nodes/{id}/inventory", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("id") {
		case "node-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"inventory":   map[string]any{"cpu": map[string]int{"count": 4}},
				"plugin_data": map[string]any{"openstack_tpm": map[string]string{"tpm_ek_sha256": "abc"}, "other": 1},
			})
		case "bare":
			_ = json.NewEncoder(w).Encode(map[string]any{"inventory": map[string]any{}})
		default:
			http.Error(w, "not found", http.StatusNotFound) // never inspected
		}
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeCloud) client(creds Credentials) *Client {
	return f.clientAt(creds, Endpoints{Region: "RegionOne", Interface: "internal"})
}

func (f *fakeCloud) clientAt(creds Credentials, ep Endpoints) *Client {
	creds.AuthURL = f.URL + "/v3"
	return New(creds, ep, 5*time.Second)
}

func (f *fakeCloud) header(path, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.headers[path].Get(name)
}

// Ensures a server is read with its project, image and flavor, and the token is reused.
func TestGetServerAndCache(t *testing.T) {
	f := newFakeCloud(t)
	c := f.client(Credentials{AppCredID: "id", AppCredSecret: "s"})
	ctx := context.Background()
	s, err := c.GetServer(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if s.TenantID != "p1" || s.ImageID() != "img" || s.VTPMFlavor() != nil {
		t.Fatalf("%+v", s)
	}
	if _, err := c.GetServer(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if n := f.auths.Load(); n != 1 {
		t.Fatalf("authenticated %d times, want 1 (cached token)", n)
	}
	if f.scoped.Load() {
		t.Fatal("application credential auth must not request a scope")
	}
}

// Ensures instance actions come newest first with failures marked.
func TestGetInstanceActions(t *testing.T) {
	f := newFakeCloud(t)
	c := f.client(Credentials{AppCredID: "id", AppCredSecret: "s"})
	acts, err := c.GetInstanceActions(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range acts {
		got = append(got, fmt.Sprintf("%s/%s/%t", a.Action, a.RequestID, a.Failed()))
	}
	if want := []string{"resize/req-3/false", "resize/req-2/true", "create/req-1/false"}; !slices.Equal(got, want) {
		t.Fatalf("actions %q, want %q", got, want)
	}
	if _, err := c.GetInstanceActions(context.Background(), "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown instance: %v", err)
	}
}

// Ensures Nova is found in the catalog by region and interface, whatever the form of its URL.
func TestCatalog(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, path string }{
		{"versioned", "/nova/v2.1"}, {"trailing slash", "/nova/v2.1/"}, {"project ID", "/nova/v2.1/p1"}, {"unversioned", "/nova"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeCloud(t)
			f.novaPath = tc.path
			for _, iface := range []string{"public", "internal"} {
				c := f.clientAt(Credentials{AppCredID: "id", AppCredSecret: "s"}, Endpoints{Region: "RegionOne", Interface: iface})
				for range 2 {
					if s, err := c.GetServer(ctx, "s1"); err != nil || s.Name != "in RegionOne" {
						t.Fatalf("%s: %+v, %v", iface, s, err)
					}
				}
			}
		})
	}

	f := newFakeCloud(t)
	for name, ep := range map[string]Endpoints{
		"unknown region":       {Region: "RegionThree", Interface: "public"},
		"unknown interface":    {Region: "RegionOne", Interface: "admin"},
		"region ID":            {Region: "regionone", Interface: "public"},
		"region only internal": {Region: "RegionTwo", Interface: "public"},
	} {
		c := f.clientAt(Credentials{AppCredID: "id", AppCredSecret: "s"}, ep)
		if _, err := c.GetServer(ctx, "s1"); !errors.Is(err, ErrNoEndpoint) {
			t.Errorf("%s: got %v, want ErrNoEndpoint", name, err)
		}
	}
	// Placement has only an internal endpoint.
	c := f.clientAt(Credentials{Username: "u", Password: "p", ProjectName: "service"}, Endpoints{Region: "RegionOne", Interface: "public"})
	if _, err := c.GetAllocations(ctx, "bm"); !errors.Is(err, ErrNoEndpoint) {
		t.Errorf("placement: got %v, want ErrNoEndpoint", err)
	}
}

// Ensures missing and forbidden resources map to their own error kinds.
func TestNotFoundAndForbidden(t *testing.T) {
	f := newFakeCloud(t)
	c := f.client(Credentials{AppCredID: "id", AppCredSecret: "s"})
	for id, want := range map[string]error{"missing": ErrNotFound, "gone": ErrNotFound, "hidden": ErrForbidden} {
		_, err := c.GetServer(context.Background(), id)
		if !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", id, err, want)
		}
		if want == ErrForbidden && errors.Is(err, ErrNotFound) {
			t.Errorf("%s: a 403 is also ErrNotFound", id)
		}
	}
}

// Ensures an expired token is replaced once and the request retried.
func TestReauthenticatesOnceOn401(t *testing.T) {
	f := newFakeCloud(t)
	c := f.client(Credentials{AppCredID: "id", AppCredSecret: "s"})
	ctx := context.Background()
	if _, err := c.GetServer(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	f.revoked.Store(true)
	if _, err := c.GetServer(ctx, "s1"); err != nil {
		t.Fatalf("after revocation: %v", err)
	}
	if n := f.auths.Load(); n != 2 {
		t.Fatalf("authenticated %d times, want 2", n)
	}
}

// Ensures authentication fails without a subject token.
func TestEmptySubjectTokenRefused(t *testing.T) {
	f := newFakeCloud(t)
	f.noToken = true
	c := f.client(Credentials{Username: "u", Password: "p", ProjectName: "service"})
	if _, err := c.ProjectID(context.Background()); err == nil {
		t.Fatal("accepted a Keystone response without X-Subject-Token")
	}
}

// Ensures Scoped keeps one client and token per project.
func TestScopedTokenPerProject(t *testing.T) {
	f := newFakeCloud(t)
	s := NewScoped(f.client(Credentials{Username: "u", Password: "p", UserDomainName: "Default"}))
	ctx := context.Background()
	for _, pid := range []string{"p1", "p2", "p1", "p2"} {
		p, err := s.Project(pid).GetProject(ctx, pid)
		if err != nil || p.DomainID != "default" || !slices.Equal(p.Ancestors, []string{"p0"}) {
			t.Fatalf("project %+v, %v", p, err)
		}
		if got := f.header("/v3/projects/"+pid, "X-Auth-Token"); got != "token-for-"+pid {
			t.Fatalf("%s read with token %q", pid, got)
		}
	}
	if n := f.auths.Load(); n != 2 {
		t.Fatalf("authenticated %d times, want one token per project", n)
	}
	if first, second := s.Project("p1"), s.Project("p1"); first != second {
		t.Fatal("a second client for the same project")
	}
}

// Ensures a project's ancestors come from Keystone's chain top down, and inconsistent chains are rejected.
func TestProjectAncestors(t *testing.T) {
	for name, c := range map[string]struct {
		parent, parents string
		want            []string
	}{
		"top-level": {"d", `{"d": null}`, nil},
		"one up":    {"b", `{"b": {"d": null}}`, []string{"b"}},
		"two up":    {"b", `{"b": {"a": {"d": null}}}`, []string{"a", "b"}},
	} {
		p := &Project{ID: "p", DomainID: "d", ParentID: c.parent, Parents: json.RawMessage(c.parents)}
		if got, err := ancestors(p); err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, %v; want %q", name, got, err, c.want)
		}
	}
	for name, c := range map[string]struct{ parent, parents string }{
		"no parents":       {"d", ``},
		"null":             {"d", `null`},
		"empty":            {"d", `{}`},
		"not an object":    {"d", `["d"]`},
		"two at a level":   {"b", `{"b": {"d": null}, "c": {"d": null}}`},
		"another parent":   {"c", `{"b": {"d": null}}`},
		"another domain":   {"b", `{"b": {"e": null}}`},
		"repeats":          {"b", `{"b": {"b": {"d": null}}}`},
		"level not object": {"b", `{"b": 1}`},
	} {
		p := &Project{ID: "p", DomainID: "d", ParentID: c.parent, Parents: json.RawMessage(c.parents)}
		if got, err := ancestors(p); err == nil {
			t.Errorf("%s: accepted as %q", name, got)
		}
	}
}
