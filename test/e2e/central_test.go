//go:build e2e

package e2e

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/nodeattestor"
)

// replaceIn replaces old with new in a config; old must occur.
func replaceIn(t testing.TB, conf, old, new string) string {
	t.Helper()
	if !strings.Contains(conf, old) {
		t.Fatalf("config has no %q", old)
	}
	return strings.ReplaceAll(conf, old, new)
}

// serverArgs are the docker run arguments of a SPIRE server.
func serverArgs(t testing.TB, srv spireServer, conf string) []string {
	t.Helper()
	f := t.TempDir() + "/server.conf"
	must(t, os.WriteFile(f, []byte(conf), 0o644), "server.conf")
	return []string{"--network", "host", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--env-file", path(srv.EnvFile), "-e", fmt.Sprintf("BIND_PORT=%d", lab.TestPort),
		"-v", f + ":/etc/spire/server.conf:ro", "-v", path(srv.Dir) + ":/etc/spire/openstack-tpm:ro",
		"-v", path("bin/openstack-tpm-spire-server") + ":/opt/openstack-tpm/openstack-tpm-spire-server:ro",
		"--tmpfs", "/var/lib/spire/server:mode=1777", "--tmpfs", "/run/spire-server:mode=1777"}
}

// testServer runs a SPIRE server like srv with conf on the test port until the test ends.
func testServer(t testing.TB, name string, srv spireServer, conf string, docker ...string) string {
	t.Helper()
	c := "e2e-spire-" + name
	_, _ = run(nil, "docker", "rm", "-f", c) // a leftover from an aborted run
	args := append(append([]string{"run", "-d", "--name", c}, serverArgs(t, srv, conf)...), docker...)
	local(t, "docker", append(args, lab.SpireImage, "-config", "/etc/spire/server.conf", "-expandEnv")...)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := run(nil, "sh", "-c", "docker logs --tail 30 "+c+" 2>&1")
			t.Logf("%s:\n%s", c, out)
		}
		_, _ = run(nil, "docker", "rm", "-f", c)
	})
	eventually(t, time.Minute, c+" healthy", func() bool {
		_, err := spireRunAt(c, "healthcheck")
		return err == nil
	})
	return c
}

// Ensures a central SPIRE server attests instances of any project in its domains.
func TestCentralServer(t *testing.T) {
	c := lab.Central
	a := attested(t, "central")
	id := agentIDIn(c.TrustDomain, a.ProjectID, a.ID)

	// Ensures the central server attests the tenant's instance.
	t.Run("tenant-project", func(t *testing.T) {
		if r := a.probeAt(t, c.Port); !r.Accepted || r.SPIFFEID != id {
			t.Fatalf("got %+v, want %s", r, id)
		}
		sel := selectorsAt(t, c.Container, id)
		hasSelectors(t, sel, "region:"+lab.Region, "domain:id:"+lab.DomainID, "project:id:"+lab.TenantProjectID,
			"project:parent:id:"+lab.DomainID, "instance:id:"+a.ID, "instance:kind:vm")
		if selectorValue(sel, "tpm:key:sha256:") == "" || selectorValue(sel, "instance:user:id:") == "" {
			t.Errorf("no key or user selector in %v", sel)
		}
		// A top-level project's parent is the domain, and it has no ancestors.
		if a := selectorValue(sel, "project:ancestor:id:"); a != "" {
			t.Errorf("ancestor %s of a top-level project", a)
		}
	})

	// Ensures another project's instance attests to the central server but not to the tenant's.
	t.Run("other-project", func(t *testing.T) {
		o := boot(t, "central-other", bootSpec{scope: adminScope, network: lab.OtherNetwork, agent: c.Container, fip: true, wait: true})
		if n := len(issuances(t, o.ID)); n != 1 {
			t.Fatalf("%d issuances, want 1", n)
		}
		oid := agentIDIn(c.TrustDomain, o.ProjectID, o.ID)
		eventually(t, 10*time.Minute, oid+" attested", func() bool { return agentAttestedAt(c.Container, oid) })
		hasSelectors(t, selectorsAt(t, c.Container, oid), "domain:id:"+lab.DomainID, "project:id:"+lab.AdminProjectID)
		o.waitSSH(t, 3*time.Minute)
		notAllowed := fmt.Sprintf("project %s (domain %s) is not on the allowlists of this server", lab.AdminProjectID, lab.DomainID)
		refused(t, o.probe(t), errors.New(notAllowed))
	})

	b, err := os.ReadFile(path(c.Conf))
	must(t, err, "central server config")
	conf := string(b)
	const domains = `domains = ["${DOMAIN_ID}"]`

	// withUser is the central server's config with selectors from Nova and Keystone, read as user.
	withUser := func(user string) string {
		return replaceIn(t, conf, domains, domains+fmt.Sprintf(`
            nova_selectors = true
            keystone_selectors = true
            openstack {
                auth_url = %q
                credentials = [
                    { username = %q, user_domain_name = "Default", password_file = "/etc/spire/openstack-tpm/os-password-%s" },
                ]
            }`, lab.KeystoneURL, user, user))
	}

	// Ensures a central server with a reader credential adds selectors from Nova and Keystone.
	t.Run("user-credential", func(t *testing.T) {
		srv := testServer(t, "user", c, withUser(lab.CentralUser))
		if r := a.probeAt(t, lab.TestPort); !r.Accepted || r.SPIFFEID != id {
			t.Fatalf("got %+v, want %s", r, id)
		}
		hasSelectors(t, selectorsAt(t, srv, id), "project:id:"+lab.TenantProjectID,
			"instance:name:"+a.Name, "instance:flavor:"+lab.Linux.Flavor, "project:name:"+lab.Tenant)
	})

	// Ensures a nested project's ancestors become claims and selectors.
	t.Run("nested-project", func(t *testing.T) {
		chain := nestedProjects(t, "nested", 3)
		leaf := "e2e-nested-3"
		if got := ancestors(t, chain[2]); !slices.Equal(got, chain[:2]) {
			t.Fatalf("keystone ancestors %q, want %q", got, chain[:2])
		}
		n := boot(t, "nested", bootSpec{scope: scope{projectID: chain[2]}, network: lab.ExternalNetwork,
			securityGroup: leaf + "-ssh", agent: c.Container, wait: true})
		want := contract.Claims{Region: lab.Region, DomainID: lab.DomainID, Ancestors: chain[:2], ProjectID: chain[2],
			InstanceID: n.ID, Kind: contract.KindVM, UserID: showServer(t, n.ID).UserID}
		if got := issuances(t, n.ID)[0].Claims; got != want.URI() {
			t.Fatalf("the issuer certified %s, want %s", got, want.URI())
		}
		nid := agentIDIn(c.TrustDomain, chain[2], n.ID)
		eventually(t, 10*time.Minute, nid+" attested", func() bool { return agentAttestedAt(c.Container, nid) })
		sel := selectorsAt(t, c.Container, nid)
		t.Logf("selectors:\n%s", strings.Join(sel, "\n"))
		hasSelectors(t, sel, "domain:id:"+lab.DomainID, "project:id:"+chain[2], "project:parent:id:"+chain[1],
			"project:ancestor:id:"+chain[0], "project:ancestor:id:"+chain[1])
		var anc []string
		for _, s := range sel {
			if v, ok := strings.CutPrefix(s, "openstack_tpm:project:ancestor:id:"); ok {
				anc = append(anc, v)
			}
		}
		if !slices.Equal(sorted(anc), sorted(chain[:2])) {
			t.Errorf("ancestor selectors %q, want %q", anc, chain[:2])
		}

		srv := testServer(t, "nested", c, withUser(lab.CentralUser))
		n.waitSSH(t, 5*time.Minute)
		if r := n.probeAt(t, lab.TestPort); !r.Accepted || r.SPIFFEID != nid {
			t.Fatalf("got %+v, want %s", r, nid)
		}
		hasSelectors(t, selectorsAt(t, srv, nid), "project:parent:id:"+chain[1], "project:ancestor:id:"+chain[0],
			"project:ancestor:id:"+chain[1], "project:name:"+leaf, "instance:name:"+n.Name)
	})

	// Ensures a changed allowlist in plugin_data_file applies on SIGUSR1 without a restart.
	t.Run("reload", func(t *testing.T) {
		dir := t.TempDir()
		data := dir + "/openstack_tpm.hcl"
		write := func(allowlist string) {
			must(t, os.WriteFile(data, []byte(`ca_bundle = "/etc/spire/openstack-tpm/ca.pem"`+"\n"+allowlist+"\n"), 0o644), "plugin data")
		}
		write(fmt.Sprintf("projects = [%q]", lab.AdminProjectID))
		reload := replaceIn(t, conf, `plugin_data {
            ca_bundle = "/etc/spire/openstack-tpm/ca.pem"
            `+domains+`
        }`, `plugin_data_file = "/etc/spire/plugin-data/openstack_tpm.hcl"`)
		srv := testServer(t, "reload", c, reload, "-v", dir+":/etc/spire/plugin-data:ro")
		notAllowed := fmt.Sprintf("project %s (domain %s) is not on the allowlists of this server", lab.TenantProjectID, lab.DomainID)
		refused(t, a.probeAt(t, lab.TestPort), errors.New(notAllowed))

		since := time.Now()
		write(fmt.Sprintf("domains = [%q]", lab.DomainID))
		local(t, "docker", "kill", "--signal", "USR1", srv)
		eventually(t, 30*time.Second, srv+" reconfigured", func() bool {
			out, _ := run(nil, "sh", "-c", "docker logs --since "+since.Format(time.RFC3339Nano)+" "+srv+" 2>&1")
			return strings.Contains(out, "Plugin reconfigured")
		})
		if r := a.probeAt(t, lab.TestPort); !r.Accepted || r.SPIFFEID != id {
			t.Fatalf("after reload: got %+v, want %s", r, id)
		}
	})

	// Ensures a credential without the reader role reports an outage, not a refusal.
	t.Run("no-reader", func(t *testing.T) {
		testServer(t, "no-reader", c, withUser(lab.NoroleUser))
		r := a.probeAt(t, lab.TestPort)
		if r.Accepted || !strings.Contains(r.Error, nodeattestor.ErrUnavailable.Error()) ||
			!strings.Contains(r.Error, "its user lacks reader there") {
			t.Fatalf("got %+v", r)
		}
	})
}
