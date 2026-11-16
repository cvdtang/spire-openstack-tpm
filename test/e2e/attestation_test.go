//go:build e2e

package e2e

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/contract"
)

// Ensures a tenant VM of each guest OS is certified once at build and attests with selectors that follow its tags.
func TestAttestation(t *testing.T) {
	forEachGuest(t, func(t *testing.T, g *guestOS) {
		a := g.attested(t, "attest-"+g.name)

		// Ensures the building host requested exactly one certificate for the instance.
		t.Run("issuance", func(t *testing.T) {
			is := issuances(t, a.ID)
			if len(is) != 1 || is[0].Request != contract.KindVM || is[0].KeySHA256 == "" {
				t.Fatalf("issuances for %s: %+v, want one for a vm", a.ID, is)
			}
			if is[0].Host != lab.Controller {
				t.Errorf("certificate requested by %s, instance built on %s", is[0].Host, lab.Controller)
			}
		})

		// Ensures the certificate in NV chains to the bundle with the claims OpenStack reports, and swtpm's own certificates do not.
		t.Run("nv-certificates", func(t *testing.T) {
			if !g.tpmTools {
				t.Skipf("the %s image has no tpm2-tools to read NV", g.name)
			}
			want, v := a.verifiedClaims(t)
			if got := issuances(t, a.ID)[0].Claims; got != want.URI() {
				t.Errorf("the issuer logged %s, the certificate says %s", got, want.URI())
			}
			t.Logf("NV %s: %s, issuer %q", nvVM, v.Cert.URIs[0], v.Cert.Issuer)
			// The RSA EK's certificate does not chain to the provider's bundle.
			b, err := contract.LoadBundle(path(caBundle))
			must(t, err, "bundle")
			if _, err := b.Verify(a.nvCert(t, nvRSA)); !errors.Is(err, contract.ErrChainInvalid) {
				t.Fatalf("NV %s: got %v, want a certificate outside the provider bundle", nvRSA, err)
			}
			// It and the platform certificate name an untrusted issuer.
			for _, idx := range []string{nvRSA, nvPlatform} {
				c, err := x509.ParseCertificate(a.nvCert(t, idx))
				must(t, err, "NV "+idx)
				if c.Issuer.CommonName != "openstack-tpm-swtpm (untrusted)" || !strings.HasSuffix(c.Subject.CommonName, ":"+a.ID) {
					t.Errorf("NV %s: issuer %q, subject %q", idx, c.Issuer, c.Subject)
				}
			}
		})

		// Ensures re-attestation reflects the current instance and project tags.
		t.Run("selectors", func(t *testing.T) {
			// Selectors come from the certificate and, with nova_selectors and keystone_selectors, from Nova and Keystone at each attestation.
			// Tags follow changes at the next attestation; metadata never becomes a selector.
			os_(t, adminScope, "server", "set", "--tag", "web", "--property", "role=db", a.ID)
			tagProject(t, lab.TenantProjectID, "env-prod")
			s := showServer(t, a.ID)
			a.reattest(t, 2*time.Minute)
			sel := selectors(t, a.agentID())
			t.Logf("selectors:\n%s", strings.Join(sel, "\n"))
			hasSelectors(t, sel,
				"region:"+lab.Region, "domain:id:"+lab.DomainID, "project:id:"+lab.TenantProjectID, "project:parent:id:"+lab.DomainID,
				"instance:id:"+a.ID, "instance:kind:vm", "instance:user:id:"+s.UserID,
				"instance:name:"+a.Name, "instance:flavor:"+g.Flavor, "instance:az:"+s.AZ, "instance:image:id:"+s.imageID(),
				"instance:tag:web", "project:name:"+lab.Tenant, "project:tag:env-lab", "project:tag:env-prod")
			if key := selectorValue(sel, "tpm:key:sha256:"); key != issuances(t, a.ID)[0].KeySHA256 {
				t.Errorf("tpm:key:sha256 is %q, the issuer certified %q", key, issuances(t, a.ID)[0].KeySHA256)
			}
			if joined := strings.Join(sel, "\n"); strings.Contains(joined, "role") || strings.Contains(joined, ":db") {
				t.Error("instance metadata became a selector")
			}

			os_(t, adminScope, "server", "unset", "--tag", "web", a.ID)
			os_(t, adminScope, "project", "set", "--remove-tag", "env-prod", lab.TenantProjectID)
			a.reattest(t, 2*time.Minute)
			sel = selectors(t, a.agentID())
			hasSelectors(t, sel, "project:tag:env-lab", "instance:name:"+a.Name)
			if joined := strings.Join(sel, "\n"); strings.Contains(joined, "instance:tag:web") || strings.Contains(joined, "project:tag:env-prod") {
				t.Errorf("a removed tag is still a selector:\n%s", joined)
			}
		})

		// Ensures the agent runs as a service with a healthy Workload API.
		t.Run("agent", func(t *testing.T) { a.agentHealthy(t) })
	})
}

// Ensures deleting an instance removes its vTPM state.
func TestDelete(t *testing.T) {
	d := attested(t, "delete")
	id := d.ID
	must(t, d.delete(), "delete")
	if swtpmState(t, id) {
		t.Fatal("swtpm state left on compute-1")
	}
	if getServer(t, id) != nil {
		t.Fatal("Nova still shows the deleted instance")
	}
}
