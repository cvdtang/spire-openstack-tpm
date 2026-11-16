//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/cvdtang/openstack-tpm/internal/activation"
	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/issuerapi"
	"github.com/cvdtang/openstack-tpm/internal/tpmprov"
)

// bmCertRequest is a certificate request like the IPA deploy step's, with a fresh instance key.
func bmCertRequest(t *testing.T, node, instance string, ek tpm2.TPMTPublic) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	must(t, err, "key")
	key, err := contract.KeyPublic(contract.KindBaremetal, &k.PublicKey)
	must(t, err, "key template")
	b, err := json.Marshal(issuerapi.BaremetalCertificateRequest{Node: node, Instance: instance,
		EKPublic: tpm2.Marshal(ek), KeyPublic: tpm2.Marshal(key)})
	must(t, err, "request")
	return b
}

// guestEK reads the RSA EK's public area, which the deploy step sends, from inside a bare-metal instance.
func guestEK(t *testing.T, i *instance) tpm2.TPMTPublic {
	t.Helper()
	out := i.guest(t, "(tpm2_readpublic -c 0x81010001 -f tpmt -o /tmp/ek.tpmt || "+
		"tpm2_createek -c /tmp/ek.ctx -G rsa -f tpmt -u /tmp/ek.tpmt) >/dev/null 2>&1; base64 -w0 /tmp/ek.tpmt")
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	must(t, err, "EK public area")
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](b)
	must(t, err, "EK public area")
	return *pub
}

// Ensures a bare-metal instance is certified against the node's recorded EK, and each tenant gets a new key the previous one cannot use.
func TestBaremetal(t *testing.T) {
	bmc := lab.Baremetal
	bundle, err := contract.LoadBundle(path(caBundle))
	must(t, err, "bundle")
	persisted := fmt.Sprintf("%#x", uint32(contract.HandleBaremetal))
	client := issuerClient(t, "") // IPA has no client certificate

	// The first tenant deploys an instance in its project.
	bm := boot(t, "bm", bootSpec{baremetal: true, agent: lab.TenantServer.Container, wait: true})
	bm.waitAttested(t, 15*time.Minute)
	bm.waitSSH(t, 5*time.Minute)

	var key string // hash of the first tenant's instance key

	// Ensures the deploy step certifies the instance and the agent attests without node selectors.
	t.Run("deploy", func(t *testing.T) {
		// The deploy step got one certificate for the instance key, for the node's recorded EK.
		is := issuances(t, bm.ID)
		if len(is) != 1 || is[0].Request != contract.KindBaremetal || is[0].Node != bmc.Node || is[0].EKSHA256 != bmc.EKSHA256 {
			t.Fatalf("issuances for %s: %+v, want one for node %s with EK %s", bm.ID, is, bmc.Node, bmc.EKSHA256)
		}
		key = is[0].KeySHA256
		// The certificate in NV chains to the provider's bundle and carries Nova's and Keystone's values.
		v, err := bundle.Verify(bm.cert(t))
		must(t, err, "NV "+nvBaremetal)
		s, p := showServer(t, bm.ID), showProject(t, lab.TenantProjectID)
		want := contract.Claims{Region: lab.Region, DomainID: p.DomainID, ProjectID: lab.TenantProjectID, InstanceID: bm.ID,
			Kind: contract.KindBaremetal, Ancestors: ancestors(t, lab.TenantProjectID), UserID: s.UserID}
		if !v.Claims.Equal(want) {
			t.Fatalf("claims %+v, want %+v", v.Claims, want)
		}
		if h, _ := contract.KeyHash(v.Key); h != key {
			t.Fatalf("the certificate's key is %s, the issuer logged %s", h, key)
		}
		if out := bm.guest(t, "tpm2_getcap handles-persistent"); !strings.Contains(out, persisted) {
			t.Fatalf("no instance key at %s:\n%s", persisted, out)
		}
		// The same agent config as a virtual machine, and the same exchange.
		sel := selectors(t, bm.agentID())
		t.Logf("selectors:\n%s", strings.Join(sel, "\n"))
		hasSelectors(t, sel, "instance:id:"+bm.ID, "instance:kind:baremetal", "project:id:"+lab.TenantProjectID,
			"instance:user:id:"+s.UserID, "tpm:key:sha256:"+key, "instance:name:"+bm.Name, "instance:flavor:"+bmc.Flavor)
		// No selector names the node.
		if joined := strings.Join(sel, "\n"); strings.Contains(joined, bmc.Node) || strings.Contains(joined, bmc.NodeName) {
			t.Errorf("a selector names the node:\n%s", joined)
		}
	})

	// Ensures the issuer refuses what anyone on the provisioning network could ask while a tenant runs.
	t.Run("issuer-refusals", func(t *testing.T) {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		post := func(endpoint string, body any) (int, issuerapi.Error) {
			b, ok := body.([]byte)
			if !ok {
				b, _ = json.Marshal(body)
			}
			code, e, _ := issuerDo(t, client, http.MethodPost, endpoint, b)
			return code, e
		}
		// Ensures no clear authorization is given for an active node.
		t.Run("clear-of-an-active-node", func(t *testing.T) {
			code, e := post(issuerapi.PathBaremetalClear, issuerapi.ClearRequest{Node: bmc.Node, Nonce: nonce})
			if code != 403 || e.Code != issuerapi.CodeRefused || !strings.Contains(e.Message, "not cleaning or deploying") {
				t.Fatalf("got %d %s %s", code, e.Code, e.Message)
			}
		})
		// Ensures a certificate request with another EK is refused.
		t.Run("certificate-for-another-ek", func(t *testing.T) {
			ek := tpm2.RSAEKTemplate
			n := make([]byte, 256)
			rand.Read(n)
			n[0] |= 0x80
			ek.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: n})
			if code, e := post(issuerapi.PathBaremetalCertificate, bmCertRequest(t, bmc.Node, bm.ID, ek)); code != 403 || e.Code != issuerapi.CodeRefused {
				t.Fatalf("got %d %s %s", code, e.Code, e.Message)
			}
		})
		// Ensures a certificate request with the node's real EK is refused once the node is deployed.
		t.Run("certificate-for-a-deployed-node", func(t *testing.T) {
			ek := guestEK(t, bm)
			if h, err := tpmprov.EKHash(&ek); err != nil || h != bmc.EKSHA256 {
				t.Fatalf("the EK read in the instance is %s (%v), inspection recorded %s", h, err, bmc.EKSHA256)
			}
			code, e := post(issuerapi.PathBaremetalCertificate, bmCertRequest(t, bmc.Node, bm.ID, ek))
			if code != 403 || e.Code != issuerapi.CodeRefused || !strings.Contains(e.Message, "not deploying") {
				t.Fatalf("got %d %s %s", code, e.Code, e.Message)
			}
		})
	})

	// Ensures guest root cannot clear the TPM or take over its lockout authorization.
	t.Run("tenant-cannot-clear", func(t *testing.T) {
		for _, cmd := range []string{"tpm2_clear", "tpm2_clear -c p", "tpm2_changeauth -c l e2e-lockout",
			"tpm2_clearcontrol -C l c", "tpm2_dictionarylockout -c"} {
			if out, err := bm.guestRun(cmd + " 2>&1"); err == nil {
				t.Errorf("%s succeeded in the instance: %s", cmd, out)
			}
		}
		if out := bm.guest(t, "tpm2_getcap properties-variable | grep lockoutAuthSet"); !strings.Contains(out, "1") {
			t.Errorf("lockoutAuthSet is not set: %s", out)
		}
		bm.reattest(t, 3*time.Minute)
		if got := keySelector(t, bm.agentID()); got != key {
			t.Fatalf("key selector %q, want %q", got, key)
		}
	})

	// Ensures the agent re-creates the instance key after guest root evicts it.
	t.Run("evicted-key", func(t *testing.T) {
		bm.guest(t, "tpm2_evictcontrol -C o -c "+persisted)
		bm.reattest(t, 3*time.Minute)
		if got := keySelector(t, bm.agentID()); got != key {
			t.Fatalf("key selector %q after the eviction, want %q", got, key)
		}
	})

	if t.Failed() {
		return
	}

	// Deleting the instance runs the clean step, which clears the TPM with the provider's authorization.
	oldCert, cleared := bm.cert(t), len(clears(t, bmc.Node))
	must(t, bm.delete(), "delete "+bm.Name)
	waitNodeAvailable(t, 20*time.Minute)
	// Ensures deleting the instance gets exactly one authorized clear during cleaning.
	t.Run("clean", func(t *testing.T) {
		cl := clears(t, bmc.Node)
		if len(cl) != cleared+1 {
			t.Fatalf("%d clears of the node after cleaning, want %d", len(cl), cleared+1)
		}
		if st := cl[len(cl)-1].State; st != "clean wait" && st != "cleaning" {
			t.Fatalf("the clear was authorized in state %q", st)
		}
	})

	// A second tenant deploys in another project.
	c := lab.Central
	other := boot(t, "bm-other", bootSpec{baremetal: true, scope: adminScope, agent: c.Container, wait: true})
	otherID := agentIDIn(c.TrustDomain, other.ProjectID, other.ID)
	eventually(t, 15*time.Minute, otherID+" attested", func() bool { return agentAttestedAt(c.Container, otherID) })
	other.waitSSH(t, 5*time.Minute)

	// Ensures the next tenant gets a new key and the previous certificate fails on the node.
	t.Run("re-tenancy", func(t *testing.T) {
		is := issuances(t, other.ID)
		if len(is) != 1 || is[0].KeySHA256 == "" || is[0].KeySHA256 == key {
			t.Fatalf("issuances for %s: %+v, want one for a key other than %s", other.ID, is, key)
		}
		v, err := bundle.Verify(other.cert(t))
		must(t, err, "NV "+nvBaremetal)
		if v.Claims.ProjectID != lab.AdminProjectID || v.Claims.InstanceID != other.ID {
			t.Fatalf("claims %+v", v.Claims)
		}
		hasSelectors(t, selectorsAt(t, c.Container, otherID), "instance:kind:baremetal", "project:id:"+lab.AdminProjectID,
			"tpm:key:sha256:"+is[0].KeySHA256)
		// The first tenant's certificate still chains, but this TPM no longer has its key.
		other.upload(t, "/tmp/old-cert.der", oldCert)
		refused(t, other.probe(t, "-cert", "/tmp/old-cert.der"), activation.ErrKeyMismatch)
		// And its own certificate names a project that server does not list.
		if r := other.probe(t); r.Accepted || !strings.Contains(r.Error, "is not on the allowlists of this server") {
			t.Fatalf("got %+v", r)
		}
	})

	// Ensures without cleaning, the next deploy clears the TPM and certifies a new key.
	t.Run("deploy-without-cleaning", func(t *testing.T) {
		if testing.Short() {
			t.Skip("deploys the node again")
		}
		setAutomatedClean(t, false)
		t.Cleanup(func() { setAutomatedClean(t, true) })
		cleared, last := len(clears(t, bmc.Node)), issuances(t, other.ID)[0].KeySHA256
		must(t, other.delete(), "delete "+other.Name)
		next := boot(t, "bm-noclean", bootSpec{baremetal: true, agent: lab.TenantServer.Container, wait: true})
		next.waitAttested(t, 15*time.Minute)
		cl := clears(t, bmc.Node)
		if len(cl) != cleared+1 {
			t.Fatalf("%d clears of the node, want %d", len(cl), cleared+1)
		}
		if st := cl[len(cl)-1].State; st != "wait call-back" && st != "deploying" {
			t.Fatalf("the clear was authorized in state %q, want during the deploy", st)
		}
		is := issuances(t, next.ID)
		if len(is) != 1 || is[0].KeySHA256 == last || is[0].KeySHA256 == key {
			t.Fatalf("issuances for %s: %+v, want one for a new key", next.ID, is)
		}
		// Back to cleaning for the delete of this instance.
		setAutomatedClean(t, true)
	})
}
