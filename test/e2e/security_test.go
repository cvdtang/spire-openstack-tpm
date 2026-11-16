//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/activation"
	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/openstack"
)

// refused asserts that the probe was refused for reason (an error code).
func refused(t *testing.T, r probeResult, reason error) {
	t.Helper()
	if r.Accepted {
		t.Fatalf("accepted as %s", r.SPIFFEID)
	}
	if !strings.Contains(r.Error, reason.Error()) {
		t.Fatalf("refused with %q, want %s", r.Error, reason)
	}
}

// Ensures guest root cannot attest with a certificate other than its TPM's, nor disturb its own attestation.
func TestSecurity(t *testing.T) {
	a, b := attested(t, "security-a"), attested(t, "security-b")

	// Ensures a certificate from a look-alike CA is refused.
	t.Run("forged-certificate", func(t *testing.T) {
		refused(t, a.probe(t, "-forge"), contract.ErrChainInvalid)
	})

	// Ensures another instance's certificate fails the TPM challenge.
	t.Run("foreign-certificate", func(t *testing.T) {
		b.upload(t, "/tmp/a-cert.der", a.cert(t))
		refused(t, b.probe(t, "-cert", "/tmp/a-cert.der"), activation.ErrKeyMismatch)
		if !agentAttested(a.agentID()) {
			t.Fatal("A lost its identity")
		}
	})

	// Ensures a recorded attestation cannot be replayed.
	t.Run("replay", func(t *testing.T) {
		if r := a.probe(t, "-record", "/tmp/rec.json"); !r.Accepted {
			t.Fatalf("honest probe refused: %s", r.Error)
		}
		refused(t, a.probe(t, "-replay", "/tmp/rec.json"), activation.ErrKeyMismatch)
		rec := a.guest(t, "base64 -w0 /tmp/rec.json")
		if _, err := sshRun(b.Addr, strings.NewReader(rec), "base64 -d > /tmp/rec.json"); err != nil {
			t.Fatal(err)
		}
		refused(t, b.probe(t, "-replay", "/tmp/rec.json"), activation.ErrKeyMismatch)
	})

	// Ensures an abandoned exchange does not affect the next one.
	t.Run("abandoned-exchange", func(t *testing.T) {
		if r := a.probe(t, "-hangup"); r.Accepted {
			t.Fatalf("accepted as %s", r.SPIFFEID)
		}
		if r := a.probe(t); !r.Accepted {
			t.Fatalf("honest probe refused after an abandoned exchange: %s", r.Error)
		}
	})

	// Ensures the agent re-creates the EK after guest root evicts it.
	t.Run("evicted-key", func(t *testing.T) {
		handle := fmt.Sprintf("%#x", uint32(contract.HandleVM))
		if out := b.guest(t, "tpm2_getcap handles-persistent"); !strings.Contains(out, handle) {
			t.Fatalf("no persisted EK at %s:\n%s", handle, out)
		}
		key := keySelector(t, b.agentID())
		b.guest(t, "tpm2_evictcontrol -C o -c "+handle)
		b.reattest(t, 2*time.Minute)
		if got := keySelector(t, b.agentID()); got != key {
			t.Fatalf("key selector %q after the eviction, want %q", got, key)
		}
	})

	// Ensures the agent survives tpm2_clear and guest root cannot remove the certificate.
	t.Run("guest-root", func(t *testing.T) {
		t.Log(a.guest(t, `tpm2_getcap properties-variable | grep -E "phEnable|shEnable|ehEnable"`))
		if _, err := a.guestRun("tpm2_clear"); err != nil {
			t.Logf("tpm2_clear: %v", err)
		}
		a.reattest(t, 2*time.Minute)
		if _, err := a.guestRun("tpm2_nvundefine -C p " + nvVM); err == nil {
			if r := a.probe(t); r.Accepted {
				t.Fatal("attested without a certificate")
			}
			t.Fatal("guest root undefined the certificate's NV index (platform auth is empty)")
		}
		a.guest(t, "tpm2_nvreadpublic "+nvVM+" >/dev/null")
	})
}

// Ensures the tenant's application credential reads only what the server plugin needs, apart from a known wildcard gap.
func TestAppCredentialScope(t *testing.T) {
	id := bootPlain(t, tenantScope(), "appcred", "")
	secret, err := os.ReadFile(path(appCredSecretFile))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"auth": map[string]any{"identity": map[string]any{
		"methods":                []string{"application_credential"},
		"application_credential": map[string]string{"id": lab.AppCredID, "secret": strings.TrimSpace(string(secret))},
	}}})
	resp, err := http.Post(lab.KeystoneURL+"/auth/tokens", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	token := resp.Header.Get("X-Subject-Token")
	if resp.StatusCode != http.StatusCreated || token == "" {
		t.Fatalf("application credential token: %s", resp.Status)
	}

	cases := []struct {
		name, method, url, body string
		allowed                 bool
	}{
		{"GET server", "GET", lab.NovaURL + "/servers/" + id, "", true},
		{"GET own project", "GET", lab.KeystoneURL + "/projects/" + lab.TenantProjectID, "", true},
		{"list servers", "GET", lab.NovaURL + "/servers", "", false},
		// A known gap: the access-rule wildcard also matches "detail", so the credential can list its project's servers.
		{"GET /servers/detail (matches /servers/*)", "GET", lab.NovaURL + "/servers/detail", "", true},
		{"server action", "POST", lab.NovaURL + "/servers/" + id + "/action", `{"os-stop":null}`, false},
		{"server sub-resource", "GET", lab.NovaURL + "/servers/" + id + "/os-interface", "", false},
		{"flavors", "GET", lab.NovaURL + "/flavors", "", false},
		{"other project", "GET", lab.KeystoneURL + "/projects/" + lab.AdminProjectID, "", false},
		{"users", "GET", lab.KeystoneURL + "/users", "", false},
		{"neutron ports", "GET", lab.NeutronURL + "/v2.0/ports", "", false},
		{"ironic node", "GET", lab.IronicURL + "/v1/nodes/" + lab.Baremetal.Node, "", false},
	}
	// Ensures the credential can read the instance's tags.
	t.Run("tags", func(t *testing.T) {
		req, _ := http.NewRequest("GET", lab.NovaURL+"/servers/"+id, nil)
		req.Header.Set("X-Auth-Token", token)
		req.Header.Set("OpenStack-API-Version", "compute "+openstack.ComputeMicroversion)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Server struct {
				Tags *[]string `json:"tags"`
			} `json:"server"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v", resp.Status, err)
		}
		if out.Server.Tags == nil {
			t.Fatal("no tags in Nova's answer")
		}
	})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest(c.method, c.url, strings.NewReader(c.body))
			req.Header.Set("X-Auth-Token", token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			ok := resp.StatusCode/100 == 2
			if ok != c.allowed {
				t.Fatalf("%s %s: %s, allowed %v", c.method, c.url, resp.Status, c.allowed)
			}
		})
	}
}
