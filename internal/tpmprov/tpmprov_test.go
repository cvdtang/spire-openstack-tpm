package tpmprov

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/cvdtang/openstack-tpm/internal/activation"
	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/issuerapi"
	"github.com/cvdtang/openstack-tpm/internal/pkitest"
	"github.com/cvdtang/openstack-tpm/internal/tpmtest"
)

const (
	node      = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	otherNode = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	instanceA = "11111111-1111-4111-8111-111111111111"
	instanceB = "22222222-2222-4222-8222-222222222222"
	instanceC = "33333333-3333-4333-8333-333333333333"
)

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func clearKeyOf(t *testing.T, k *ecdsa.PrivateKey) issuerapi.ClearKey {
	t.Helper()
	b, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return issuerapi.ClearKey{X: b[1:33], Y: b[33:]}
}

// fakeIssuer signs every clear and certifies every key, unless a test tells it otherwise.
type fakeIssuer struct {
	t             *testing.T
	root, issuing *pkitest.CA
	clearKey      *ecdsa.PrivateKey

	clears, certs int
	refuseClear   error
	refuseCert    error
	signClearWith *ecdsa.PrivateKey                          // signs clears instead of clearKey
	replay        *issuerapi.ClearResponse                   // answers every clear
	lastClear     *issuerapi.ClearResponse                   // the last answer
	claims        func(instance string) contract.Claims      // nil: baremetal claims of the instance
	keyName       func(pub *tpm2.TPMTPublic) *tpm2.TPM2BName // nil: the name of the key
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	root := pkitest.NewCA(t, "root", nil)
	return &fakeIssuer{t: t, root: root, issuing: pkitest.NewIssuing(t, "issuing", root), clearKey: p256(t)}
}

func (f *fakeIssuer) ClearKey(context.Context) (*issuerapi.ClearKey, error) {
	k := clearKeyOf(f.t, f.clearKey)
	return &k, nil
}

func (f *fakeIssuer) Clear(_ context.Context, req *issuerapi.ClearRequest) (*issuerapi.ClearResponse, error) {
	f.clears++
	if f.refuseClear != nil {
		return nil, f.refuseClear
	}
	if f.replay != nil {
		return f.replay, nil
	}
	key := f.clearKey
	if f.signClearWith != nil {
		key = f.signClearWith
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, ClearDigest(req.Nonce, req.Node))
	if err != nil {
		return nil, err
	}
	f.lastClear = &issuerapi.ClearResponse{Key: clearKeyOf(f.t, f.clearKey), R: r.FillBytes(make([]byte, 32)), S: s.FillBytes(make([]byte, 32))}
	return f.lastClear, nil
}

func testClaims(instance string) contract.Claims {
	return contract.Claims{
		Region: "RegionOne", DomainID: "default", ProjectID: "p-" + instance[:8], InstanceID: instance,
		Kind: contract.KindBaremetal, UserID: "u1",
	}
}

func (f *fakeIssuer) Certificate(_ context.Context, req *issuerapi.BaremetalCertificateRequest) (*issuerapi.BaremetalCertificateResponse, error) {
	f.certs++
	if f.refuseCert != nil {
		return nil, f.refuseCert
	}
	ekPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](req.EKPublic)
	if err != nil {
		return nil, err
	}
	keyPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](req.KeyPublic)
	if err != nil {
		return nil, err
	}
	parms, err := keyPub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}
	point, err := keyPub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	key, err := tpm2.ECDSAPub(parms, point)
	if err != nil {
		return nil, err
	}
	c := testClaims(req.Instance)
	if f.claims != nil {
		c = f.claims(req.Instance)
	}
	der, err := contract.Build(c, key, time.Now(), f.issuing.Cert, f.issuing.Key)
	if err != nil {
		return nil, err
	}
	name, err := tpm2.ObjectName(keyPub)
	if err != nil {
		return nil, err
	}
	if f.keyName != nil {
		name = f.keyName(keyPub)
	}
	return SealCertificate(ekPub, name.Buffer, der)
}

func (f *fakeIssuer) verify(t *testing.T, der []byte) *contract.Verified {
	t.Helper()
	v, err := contract.NewBundle([]*x509.Certificate{f.root.Cert, f.issuing.Cert}).Verify(der)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// attest runs an attestation with the certificate in NV and returns the certificate.
func attest(t *testing.T, tpm transport.TPMCloser, f *fakeIssuer) *contract.Verified {
	t.Helper()
	a, err := activation.NewAgent(tpmtest.KeepOpen(tpm))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	v := f.verify(t, a.Cert)
	want, id, enc, err := activation.MakeCredential(v, a.AKPublic)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.ActivateCredential(id, enc)
	if err != nil {
		t.Fatalf("attestation with the certificate in NV: %v", err)
	}
	if !activation.Equal(got, want) {
		t.Fatal("attestation: wrong secret")
	}
	return v
}

// activates reports whether the TPM, with whatever key it has now, answers a challenge for an old certificate.
func activates(t *testing.T, tpm transport.TPMCloser, old *contract.Verified) bool {
	t.Helper()
	a, err := activation.NewAgent(tpmtest.KeepOpen(tpm))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	want, id, enc, err := activation.MakeCredential(old, a.AKPublic)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.ActivateCredential(id, enc)
	return err == nil && activation.Equal(got, want)
}

// tenantClear tries TPM2_Clear with the empty lockout password, as a tenant can.
func tenantClear(tpm transport.TPM) error {
	_, err := tpm2.Clear{AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.PasswordAuth(nil)}}.Execute(tpm)
	return err
}

func mustCleared(t *testing.T, tpm transport.TPM, want bool) {
	t.Helper()
	if got, err := Cleared(tpm); err != nil || got != want {
		t.Fatalf("Cleared = %v, %v; want %v", got, err, want)
	}
}

func persisted(tpm transport.TPM) bool {
	_, err := tpm2.ReadPublic{ObjectHandle: contract.HandleBaremetal}.Execute(tpm)
	return err == nil
}

// Ensures each deploy certifies a fresh key on a TPM only the provider can clear, and no earlier certificate outlives a change of instance.
func TestLifecycle(t *testing.T) {
	ctx := t.Context()
	tpm := tpmtest.Open(t, 1)
	f := newFakeIssuer(t)

	ekHash, err := EK(tpm)
	if err != nil || len(ekHash) != 64 {
		t.Fatalf("EK: %q, %v", ekHash, err)
	}
	mustCleared(t, tpm, true)

	// First deploy on a factory-fresh TPM: nothing to clear.
	res, err := Deploy(ctx, tpm, f, node, instanceA)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "issued" || res.Cleared != "" || res.EK != ekHash || len(res.Key) != 64 || res.Claims != testClaims(instanceA).URI() {
		t.Errorf("first deploy: %+v", res)
	}
	if f.clears != 0 || f.certs != 1 {
		t.Errorf("first deploy: %d clears, %d certificates", f.clears, f.certs)
	}
	// The provider owns the lockout hierarchy, and the tenant cannot clear.
	mustCleared(t, tpm, false)
	if err := tenantClear(tpm); err == nil {
		t.Fatal("the tenant cleared the TPM with the empty lockout password")
	}
	if !persisted(tpm) {
		t.Error("the instance key is not persisted")
	}
	certA := attest(t, tpm, f)
	if !certA.Claims.Equal(testClaims(instanceA)) {
		t.Errorf("certificate claims %+v", certA.Claims)
	}
	if hash, _ := contract.KeyHash(certA.Key); hash != res.Key {
		t.Errorf("result names key %s, certificate %s", res.Key, hash)
	}

	// A rebuild of the same instance clears the TPM and creates a new key.
	rebuilt, err := Deploy(ctx, tpm, f, node, instanceA)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Action != "issued" || rebuilt.Cleared != "authorized" || rebuilt.Key == res.Key || rebuilt.Claims != res.Claims || f.clears != 1 || f.certs != 2 {
		t.Errorf("rebuild: %+v, %d clears, %d certificates", rebuilt, f.clears, f.certs)
	}
	if activates(t, tpm, certA) {
		t.Error("the certificate from before the rebuild still activates")
	}
	certA = attest(t, tpm, f)
	res = rebuilt

	// Without cleaning, the next deploy step clears the TPM with the provider's authorization.
	resB, err := Deploy(ctx, tpm, f, node, instanceB)
	if err != nil {
		t.Fatal(err)
	}
	if resB.Action != "issued" || resB.Cleared != "authorized" || resB.Key == res.Key || resB.EK != ekHash || f.clears != 2 || f.certs != 3 {
		t.Errorf("deploy for another instance: %+v, %d clears, %d certificates", resB, f.clears, f.certs)
	}
	mustCleared(t, tpm, false)
	certB := attest(t, tpm, f)
	if !certB.Claims.Equal(testClaims(instanceB)) || certB.Key.Equal(certA.Key) {
		t.Errorf("second certificate: %+v", certB.Claims)
	}
	if activates(t, tpm, certA) {
		t.Error("the first tenant's certificate still activates")
	}

	// Cleaning removes the certificate, the persisted key and the lock, but not the EK.
	clean, err := Clean(ctx, tpm, f, node)
	if err != nil {
		t.Fatal(err)
	}
	// The simulator flushes the persisted key in TPM2_Clear, as the specification requires, so nothing is left to evict.
	if clean.Action != "cleared" || clean.Cleared != "authorized" || clean.Evicted || f.clears != 3 {
		t.Errorf("clean: %+v, %d clears", clean, f.clears)
	}
	mustCleared(t, tpm, true)
	if _, _, err := activation.Certificate(tpm); !errors.Is(err, activation.ErrNoCertificate) {
		t.Errorf("certificate after cleaning: %v", err)
	}
	if persisted(tpm) {
		t.Error("the instance key survived cleaning")
	}
	if h, err := EK(tpm); err != nil || h != ekHash {
		t.Errorf("EK after cleaning: %s, %v", h, err)
	}

	// Cleaning a TPM that is already free needs no authorization.
	if clean, err = Clean(ctx, tpm, f, node); err != nil || clean.Cleared != "free" || f.clears != 3 {
		t.Errorf("second clean: %+v, %v, %d clears", clean, err, f.clears)
	}

	// The next tenant gets a key of its own.
	resC, err := Deploy(ctx, tpm, f, node, instanceC)
	if err != nil {
		t.Fatal(err)
	}
	if resC.Action != "issued" || resC.Cleared != "" || resC.Key == resB.Key || resC.Key == res.Key || f.clears != 3 {
		t.Errorf("deploy after cleaning: %+v", resC)
	}
	attest(t, tpm, f)
	for name, old := range map[string]*contract.Verified{"first": certA, "second": certB} {
		if activates(t, tpm, old) {
			t.Errorf("the %s tenant's certificate activates after cleaning", name)
		}
	}
}

// Ensures nothing a tenant does to its TPM breaks attestation or the provider's next deploy or clean.
func TestTenantChanges(t *testing.T) {
	ctx := t.Context()
	owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}

	// Ensures the agent attests after the tenant evicts the persisted key.
	t.Run("evicted key", func(t *testing.T) {
		tpm := tpmtest.Open(t, 1)
		f := newFakeIssuer(t)
		res, err := Deploy(ctx, tpm, f, node, instanceA)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := tpm2.ReadPublic{ObjectHandle: contract.HandleBaremetal}.Execute(tpm)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (tpm2.EvictControl{Auth: owner, ObjectHandle: &tpm2.NamedHandle{Handle: contract.HandleBaremetal, Name: pub.Name},
			PersistentHandle: contract.HandleBaremetal}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
		// The key is a primary: the agent re-creates it.
		if v := attest(t, tpm, f); v.Claims.InstanceID != instanceA {
			t.Errorf("claims %+v", v.Claims)
		}
		_ = res
	})

	// Ensures a redeploy recovers from a deleted certificate.
	t.Run("deleted certificate", func(t *testing.T) {
		tpm := tpmtest.Open(t, 1)
		f := newFakeIssuer(t)
		if _, err := Deploy(ctx, tpm, f, node, instanceA); err != nil {
			t.Fatal(err)
		}
		pub, err := tpm2.NVReadPublic{NVIndex: contract.NVIndexBaremetal}.Execute(tpm)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (tpm2.NVUndefineSpace{AuthHandle: owner,
			NVIndex: tpm2.NamedHandle{Handle: contract.NVIndexBaremetal, Name: pub.NVName}}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
		// A rebuild clears and issues again.
		res, err := Deploy(ctx, tpm, f, node, instanceA)
		if err != nil || res.Action != "issued" || res.Cleared != "authorized" {
			t.Fatalf("rebuild without a certificate: %+v, %v", res, err)
		}
		attest(t, tpm, f)
	})

	// Ensures a tenant's owner auth does not block the next deploy or clean.
	t.Run("owner auth", func(t *testing.T) {
		tpm := tpmtest.Open(t, 1)
		f := newFakeIssuer(t)
		if _, err := Deploy(ctx, tpm, f, node, instanceA); err != nil {
			t.Fatal(err)
		}
		if _, err := (tpm2.HierarchyChangeAuth{AuthHandle: owner, NewAuth: tpm2.TPM2BAuth{Buffer: []byte("tenant")}}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
		// The clear resets the owner auth, so the step can use the hierarchy.
		res, err := Deploy(ctx, tpm, f, node, instanceB)
		if err != nil || res.Action != "issued" || res.Cleared != "authorized" {
			t.Fatalf("deploy with a tenant's owner auth: %+v, %v", res, err)
		}
		attest(t, tpm, f)

		if _, err := (tpm2.HierarchyChangeAuth{AuthHandle: owner, NewAuth: tpm2.TPM2BAuth{Buffer: []byte("tenant")}}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
		if clean, err := Clean(ctx, tpm, f, node); err != nil || clean.Cleared != "authorized" {
			t.Fatalf("clean with a tenant's owner auth: %+v, %v", clean, err)
		}
		mustCleared(t, tpm, true)
	})

	// Ensures guessing the lockout password neither clears the TPM nor blocks the provider's clean.
	t.Run("failed lockout auth", func(t *testing.T) {
		tpm := tpmtest.Open(t, 1)
		f := newFakeIssuer(t)
		if _, err := Deploy(ctx, tpm, f, node, instanceA); err != nil {
			t.Fatal(err)
		}
		// The provider's policy still authorizes the clear after wrong lockout passwords.
		for range 2 {
			if _, err := (tpm2.Clear{AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.PasswordAuth([]byte("guess"))}}).Execute(tpm); err == nil {
				t.Fatal("cleared with a guessed lockout password")
			}
		}
		if clean, err := Clean(ctx, tpm, f, node); err != nil || clean.Cleared != "authorized" {
			t.Fatalf("clean after failed lockout auth: %+v, %v", clean, err)
		}
	})
}

// Ensures only the provider's valid signature for the current session clears the TPM.
func TestClearNeedsAuthorization(t *testing.T) {
	ctx := t.Context()
	refused := errors.New(`issuer refused (refused): node is "active", not cleaning or deploying`)

	for name, c := range map[string]struct {
		mod  func(f *fakeIssuer)
		want string
	}{
		"refused":         {func(f *fakeIssuer) { f.refuseClear = refused }, "clear authorization"},
		"another key":     {func(f *fakeIssuer) { f.signClearWith = p256(f.t) }, "TPM2_PolicySigned"},
		"replayed":        {func(f *fakeIssuer) { f.replay = f.lastClear }, "TPM2_PolicySigned"},
		"another keypair": {func(f *fakeIssuer) { f.clearKey = p256(f.t) }, "TPM2_Clear with the provider's authorization"},
		"garbage response": {func(f *fakeIssuer) {
			f.replay = &issuerapi.ClearResponse{Key: clearKeyOf(f.t, f.clearKey), R: []byte{1}, S: []byte{2}}
		}, "TPM2_PolicySigned"},
	} {
		t.Run(name, func(t *testing.T) {
			tpm := tpmtest.Open(t, 1)
			f := newFakeIssuer(t)
			if _, err := Deploy(ctx, tpm, f, node, instanceA); err != nil {
				t.Fatal(err)
			}
			// One good clear and a second deploy give the fake a response to replay.
			if _, err := Clean(ctx, tpm, f, node); err != nil {
				t.Fatal(err)
			}
			res, err := Deploy(ctx, tpm, f, node, instanceA)
			if err != nil {
				t.Fatal(err)
			}
			before := attest(t, tpm, f)

			c.mod(f)
			if _, err := Clean(ctx, tpm, f, node); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("clean: %v, want %q", err, c.want)
			}
			if _, err := Deploy(ctx, tpm, f, node, instanceB); err == nil || !strings.Contains(err.Error(), "clear before deploy") {
				t.Errorf("deploy for another instance: %v", err)
			}
			// The TPM is as it was: locked, with the instance's key and certificate.
			mustCleared(t, tpm, false)
			if after := attest(t, tpm, f); !bytes.Equal(after.Cert.Raw, before.Cert.Raw) {
				t.Error("the certificate changed")
			}
			_ = res
		})
	}
}

// Ensures an authorization for another node, which a tenant can obtain for its own nonce while that node is cleaning, does not clear this TPM.
func TestClearBoundToNode(t *testing.T) {
	ctx := t.Context()
	tpm := tpmtest.Open(t, 1)
	f := newFakeIssuer(t)
	if _, err := Deploy(ctx, tpm, f, node, instanceA); err != nil {
		t.Fatal(err)
	}
	before := attest(t, tpm, f)

	if _, err := Clean(ctx, tpm, f, otherNode); err == nil || !strings.Contains(err.Error(), "TPM2_Clear with the provider's authorization") {
		t.Fatalf("clean with another node's authorization: %v", err)
	}
	mustCleared(t, tpm, false)
	if after := attest(t, tpm, f); !bytes.Equal(after.Cert.Raw, before.Cert.Raw) {
		t.Error("the certificate changed")
	}

	if _, err := Clean(ctx, tpm, f, node); err != nil {
		t.Fatalf("clean with the node's own authorization: %v", err)
	}
	mustCleared(t, tpm, true)
}

// Ensures a key that a clear left at the instance key's handle is evicted, as libtpms 0.10.2 with a profile leaves it (https://github.com/stefanberger/libtpms/issues/626).
func TestEvictLeftover(t *testing.T) {
	tpm := tpmtest.Open(t, 1)
	if evicted, err := evictLeftover(tpm); err != nil || evicted {
		t.Fatalf("empty handle: evicted %v, %v", evicted, err)
	}
	key, err := instanceKey(tpm)
	if err != nil {
		t.Fatal(err)
	}
	defer flush(tpm, key.handle)
	if err := persist(tpm, key, contract.HandleBaremetal); err != nil {
		t.Fatal(err)
	}
	if evicted, err := evictLeftover(tpm); err != nil || !evicted {
		t.Fatalf("leftover key: evicted %v, %v", evicted, err)
	}
	if persisted(tpm) {
		t.Error("the leftover key is still persisted")
	}
}

// Ensures a deploy with a bad issuer answer leaves nothing behind and succeeds on retry.
func TestCertificateFailures(t *testing.T) {
	ctx := t.Context()
	for name, c := range map[string]struct {
		mod  func(f *fakeIssuer)
		want string
	}{
		"refused": {func(f *fakeIssuer) { f.refuseCert = errors.New("issuer refused (unknown_ek)") }, "certificate: issuer refused (unknown_ek)"},
		"another instance": {func(f *fakeIssuer) {
			f.claims = func(string) contract.Claims { return testClaims(instanceB) }
		}, "the issuer's certificate is for baremetal " + instanceB},
		"another kind": {func(f *fakeIssuer) {
			f.claims = func(i string) contract.Claims { c := testClaims(i); c.Kind = contract.KindVM; return c }
		}, "the issuer's certificate is for vm"},
		// The credential names a key this TPM does not have loaded.
		"another key name": {func(f *fakeIssuer) {
			f.keyName = func(pub *tpm2.TPMTPublic) *tpm2.TPM2BName {
				other := *pub
				other.ObjectAttributes.NoDA = false
				name, _ := tpm2.ObjectName(&other)
				return name
			}
		}, "TPM2_ActivateCredential"},
	} {
		t.Run(name, func(t *testing.T) {
			tpm := tpmtest.Open(t, 1)
			f := newFakeIssuer(t)
			c.mod(f)
			if _, err := Deploy(ctx, tpm, f, node, instanceA); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("deploy: %v, want %q", err, c.want)
			}
			if _, _, err := activation.Certificate(tpm); !errors.Is(err, activation.ErrNoCertificate) {
				t.Errorf("a failed deploy left a certificate: %v", err)
			}
			if persisted(tpm) {
				t.Error("a failed deploy left a persisted key")
			}
			// The step is idempotent: once the issuer answers, a retry succeeds.
			f.refuseCert, f.claims, f.keyName = nil, nil, nil
			res, err := Deploy(ctx, tpm, f, node, instanceA)
			if err != nil || res.Action != "issued" {
				t.Fatalf("retry: %+v, %v", res, err)
			}
			attest(t, tpm, f)
		})
	}
}

// Ensures a certificate response opens only on the TPM it was sealed to.
func TestSealedForOneTPM(t *testing.T) {
	ctx := t.Context()
	f := newFakeIssuer(t)

	// TPM 1 asks; the response is kept.
	var sealed *issuerapi.BaremetalCertificateResponse
	var request *issuerapi.BaremetalCertificateRequest
	tpm1 := tpmtest.Open(t, 1)
	rec := &recorder{Issuer: f, onCert: func(req *issuerapi.BaremetalCertificateRequest, rsp *issuerapi.BaremetalCertificateResponse) {
		request, sealed = req, rsp
	}}
	if _, err := Deploy(ctx, tpm1, rec, node, instanceA); err != nil {
		t.Fatal(err)
	}
	tpm1.Close()

	// TPM 2 presents TPM 1's EK and gets TPM 1's response.
	tpm := tpmtest.Open(t, 2)
	replay := &recorder{Issuer: f, answer: sealed}
	if _, err := Deploy(ctx, tpm, replay, node, instanceA); err == nil || !strings.Contains(err.Error(), "TPM2_ActivateCredential") {
		t.Fatalf("TPM 2 opened a certificate sealed for TPM 1: %v", err)
	}
	if bytes.Equal(replay.lastReq.EKPublic, request.EKPublic) {
		t.Error("the two simulators have one EK")
	}

	// A tampered ciphertext does not open either.
	tpm.Close()
	tpm = tpmtest.Open(t, 1)
	tamper := &recorder{Issuer: f, tamper: true}
	if _, err := Deploy(ctx, tpm, tamper, node, instanceA); err == nil || !strings.Contains(err.Error(), "open the certificate") {
		t.Fatalf("tampered certificate: %v", err)
	}
}

// recorder passes requests to an Issuer and records or replaces the certificate response.
type recorder struct {
	Issuer
	onCert  func(*issuerapi.BaremetalCertificateRequest, *issuerapi.BaremetalCertificateResponse)
	answer  *issuerapi.BaremetalCertificateResponse
	tamper  bool
	lastReq *issuerapi.BaremetalCertificateRequest
}

func (r *recorder) Certificate(ctx context.Context, req *issuerapi.BaremetalCertificateRequest) (*issuerapi.BaremetalCertificateResponse, error) {
	r.lastReq = req
	if r.answer != nil {
		return r.answer, nil
	}
	rsp, err := r.Issuer.Certificate(ctx, req)
	if err != nil {
		return nil, err
	}
	if r.tamper {
		rsp.Ciphertext[0] ^= 1
	}
	if r.onCert != nil {
		r.onCert(req, rsp)
	}
	return rsp, nil
}

// Ensures LockoutPolicy differs per clear key and node and matches the policy digest the TPM computes.
func TestLockoutPolicy(t *testing.T) {
	k1, k2 := clearKeyOf(t, p256(t)), clearKeyOf(t, p256(t))
	p1, err := LockoutPolicy(k1, node)
	if err != nil || len(p1) != 32 {
		t.Fatalf("policy %x, %v", p1, err)
	}
	if again, _ := LockoutPolicy(k1, node); !bytes.Equal(p1, again) {
		t.Error("the policy of one key differs between calls")
	}
	if p2, _ := LockoutPolicy(k2, node); bytes.Equal(p1, p2) {
		t.Error("two keys with one policy")
	}
	if p3, _ := LockoutPolicy(k1, otherNode); bytes.Equal(p1, p3) {
		t.Error("two nodes with one policy")
	}

	// The TPM computes the same digest in a trial session.
	tpm := tpmtest.Open(t, 1)
	key, err := tpm2.LoadExternal{InPublic: tpm2.New2B(ClearKeyPublic(k1)), Hierarchy: tpm2.TPMRHNull}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	defer flush(tpm, key.ObjectHandle)
	sess, closeSess, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeSess() }()
	if _, err := (tpm2.PolicySigned{
		AuthObject:    tpm2.NamedHandle{Handle: key.ObjectHandle, Name: key.Name},
		PolicySession: sess.Handle(), PolicyRef: tpm2.TPM2BNonce{Buffer: ClearPolicyRef(node)},
		Auth: tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgECDSA, Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash: tpm2.TPMAlgSHA256, SignatureR: tpm2.TPM2BECCParameter{Buffer: []byte{1}}, SignatureS: tpm2.TPM2BECCParameter{Buffer: []byte{1}},
		})},
	}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	digest, err := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest.PolicyDigest.Buffer, p1) {
		t.Errorf("LockoutPolicy %x, the TPM's %x", p1, digest.PolicyDigest.Buffer)
	}
}

// Ensures EKHash names an EK by its public key hash and is stable per TPM.
func TestEKHash(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := tpm2.RSAEKTemplate
	pub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: rsaKey.N.Bytes()})
	want, _ := contract.KeyHash(&rsaKey.PublicKey)
	if got, err := EKHash(&pub); err != nil || got != want {
		t.Errorf("RSA EK: %s, %v; want %s", got, err, want)
	}

	eccKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecc, err := contract.KeyPublic(contract.KindVM, &eccKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want, _ = contract.KeyHash(&eccKey.PublicKey)
	if got, err := EKHash(&ecc); err != nil || got != want {
		t.Errorf("ECC EK: %s, %v; want %s", got, err, want)
	}

	if _, err := EKHash(&tpm2.TPMTPublic{Type: tpm2.TPMAlgKeyedHash}); err == nil {
		t.Error("keyed-hash EK accepted")
	}

	// EK is stable for one TPM and differs for another.
	tpm := tpmtest.Open(t, 1)
	h1, err := EK(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := EK(tpm); again != h1 {
		t.Error("EK differs between calls")
	}
	tpm.Close()
	tpm = tpmtest.Open(t, 2)
	if h2, err := EK(tpm); err != nil || h2 == h1 {
		t.Errorf("another TPM's EK: %s, %v", h2, err)
	}
}
