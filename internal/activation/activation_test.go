package activation

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/pkitest"
	"github.com/cvdtang/openstack-tpm/internal/tpmtest"
)

const instance = "33333333-3333-4333-8333-333333333333"

func testClaims(kind string) contract.Claims {
	return contract.Claims{
		Region: "RegionOne", DomainID: "default", ProjectID: "p1", InstanceID: instance,
		Kind: kind, UserID: "u1",
	}
}

// pki is the provider's EK root and issuing intermediate.
type pki struct {
	root, issuing *pkitest.CA
}

func newPKI(t *testing.T) *pki {
	root := pkitest.NewCA(t, "root", nil)
	return &pki{root, pkitest.NewIssuing(t, "issuing", root)}
}

func (p *pki) verify(t *testing.T, der []byte) *contract.Verified {
	t.Helper()
	v, err := contract.NewBundle([]*x509.Certificate{p.root.Cert, p.issuing.Cert}).Verify(der)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// attest runs one attestation as the server sees it and returns the secret.
func attest(t *testing.T, p *pki, a *Agent) []byte {
	t.Helper()
	v := p.verify(t, a.Cert)
	want, id, enc, err := MakeCredential(v, a.AKPublic)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.ActivateCredential(id, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(got, want) || len(want) != 32 {
		t.Fatalf("activated %x, want %x", got, want)
	}
	return got
}

// Ensures an agent of either kind answers credential challenges with its certified key and a fresh AK, and cleans up after itself.
func TestExchange(t *testing.T) {
	for _, c := range []struct {
		name string
		kind string
		opts tpmtest.Options
	}{
		{"vm", contract.KindVM, tpmtest.Options{}},
		{"vm persisted", contract.KindVM, tpmtest.Options{Persist: true}},
		{"baremetal", contract.KindBaremetal, tpmtest.Options{}},
		{"baremetal persisted", contract.KindBaremetal, tpmtest.Options{Persist: true}},
		{"vm with a zero-filled unique field", contract.KindVM, tpmtest.Options{Unique: 48}},
		{"baremetal with a zero-filled unique field", contract.KindBaremetal, tpmtest.Options{Unique: 48, Persist: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tpm := tpmtest.Open(t, 1)
			p := newPKI(t)
			der := tpmtest.Provision(t, tpm, testClaims(c.kind), p.issuing, c.opts)
			k, _ := contract.KeyOf(c.kind)

			a, err := NewAgent(tpm)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a.Cert, der) || !a.Claims.Equal(testClaims(c.kind)) {
				t.Errorf("agent has claims %+v", a.Claims)
			}
			// The persisted key is used as it is; otherwise the key is re-created.
			if a.key.persistent != c.opts.Persist || c.opts.Persist && a.key.handle != k.Handle {
				t.Errorf("key handle %#x, persistent %v", uint32(a.key.handle), a.key.persistent)
			}
			first := attest(t, p, a)
			// An answer to one challenge does not answer the next.
			second := attest(t, p, a)
			if Equal(first, second) {
				t.Error("two challenges with one secret")
			}
			// The AK is a child of the certified key; the server checks only its attributes.
			if _, err := CheckAK(a.AKPublic); err != nil {
				t.Error(err)
			}

			a.release()
			if n := tpmtest.Transients(t, tpm); n != 0 {
				t.Errorf("%d transient objects left after release", n)
			}
			if _, err := (tpm2.ReadPublic{ObjectHandle: k.Handle}).Execute(tpm); (err == nil) != c.opts.Persist {
				t.Errorf("persisted key after release: %v", err)
			}
			// The next agent on the same TPM attests with an AK of its own.
			b, err := NewAgent(tpm)
			if err != nil {
				t.Fatal(err)
			}
			defer b.release()
			if bytes.Equal(b.AKPublic, a.AKPublic) {
				t.Error("AK reused")
			}
			attest(t, p, b)
		})
	}
}

// Ensures the agent re-creates an evicted certified key and ignores a foreign key at its handle.
func TestPersistedKey(t *testing.T) {
	tpm := tpmtest.Open(t, 1)
	p := newPKI(t)
	tpmtest.Provision(t, tpm, testClaims(contract.KindBaremetal), p.issuing, tpmtest.Options{Persist: true})
	at := contract.HandleBaremetal

	// After the tenant evicts the persisted key, the agent re-creates it.
	pub, err := tpm2.ReadPublic{ObjectHandle: at}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	tpmtest.Evict(t, tpm, at, pub.Name, at)
	a, err := NewAgent(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if a.key.persistent {
		t.Error("evicted key reported as persistent")
	}
	attest(t, p, a)
	a.release()

	// Another key at the handle is not the certified key.
	tmpl, _ := contract.Template(contract.KindBaremetal, []byte{1}, nil)
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}, InPublic: tpm2.New2B(tmpl),
	}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	tpmtest.Evict(t, tpm, rsp.ObjectHandle, rsp.Name, at)
	flush(tpm, rsp.ObjectHandle)
	if a, err = NewAgent(tpm); err != nil {
		t.Fatal(err)
	}
	if a.key.persistent || a.key.handle == at {
		t.Error("another key at the handle was taken for the certified key")
	}
	attest(t, p, a)
	a.release()
}

// Ensures an owner auth set by the tenant leaves the persisted bare-metal key usable and fails cleanly when the key must be re-created.
func TestHierarchyAuth(t *testing.T) {
	tpm := tpmtest.Open(t, 1)
	p := newPKI(t)
	tpmtest.Provision(t, tpm, testClaims(contract.KindBaremetal), p.issuing, tpmtest.Options{Persist: true})
	if _, err := (tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NewAuth:    tpm2.TPM2BAuth{Buffer: []byte("owner")},
	}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	a, err := NewAgent(tpm)
	if err != nil {
		t.Fatalf("with the key persisted and an owner auth set: %v", err)
	}
	attest(t, p, a)
	a.release()

	pub, err := tpm2.ReadPublic{ObjectHandle: contract.HandleBaremetal}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.EvictControl{
		Auth:         tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth([]byte("owner"))},
		ObjectHandle: &tpm2.NamedHandle{Handle: contract.HandleBaremetal, Name: pub.Name}, PersistentHandle: contract.HandleBaremetal,
	}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAgent(tpm); err == nil || errors.Is(err, ErrKeyMismatch) || errors.Is(err, ErrNoCertificate) {
		t.Errorf("without the persisted key and with an owner auth set: %v", err)
	}
	if n := tpmtest.Transients(t, tpm); n != 0 {
		t.Errorf("%d transient objects left after a failed NewAgent", n)
	}
}

// Ensures a certificate is useless on any TPM but its own.
func TestAnotherTPM(t *testing.T) {
	for _, kind := range []string{contract.KindVM, contract.KindBaremetal} {
		t.Run(kind, func(t *testing.T) {
			p := newPKI(t)
			tpm1 := tpmtest.Open(t, 1)
			cert1 := tpmtest.Provision(t, tpm1, testClaims(kind), p.issuing, tpmtest.Options{})
			tpm1.Close()
			k, _ := contract.KeyOf(kind)

			tpm := tpmtest.Open(t, 2)
			// The agent refuses, since this TPM's key is not the certified key.
			tpmtest.WriteNV(t, tpm, k.NVIndex, cert1)
			if _, err := NewAgent(tpm); !errors.Is(err, ErrKeyMismatch) {
				t.Fatalf("agent with another TPM's certificate: %v", err)
			}
			if n := tpmtest.Transients(t, tpm); n != 0 {
				t.Errorf("%d transient objects left after a failed NewAgent", n)
			}

			// A modified agent sends certificate 1 with an AK of TPM 2, which cannot open a credential made for TPM 1's key.
			tpmtest.Provision(t, tpm, testClaims(kind), p.issuing, tpmtest.Options{})
			a, err := NewAgent(tpm)
			if err != nil {
				t.Fatal(err)
			}
			defer a.release()
			_, id, enc, err := MakeCredential(p.verify(t, cert1), a.AKPublic)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := a.ActivateCredential(id, enc)
			if !errors.Is(err, tpm2.TPMRCIntegrity) {
				t.Errorf("TPM 2 answered a challenge for TPM 1's key: %x, %v", secret, err)
			}
		})
	}
}

// Ensures a credential is bound to the AK it was made for.
func TestAnotherAK(t *testing.T) {
	tpm := tpmtest.Open(t, 1)
	p := newPKI(t)
	tpmtest.Provision(t, tpm, testClaims(contract.KindVM), p.issuing, tpmtest.Options{})
	a, err := NewAgent(tpm)
	if err != nil {
		t.Fatal(err)
	}
	defer a.release()
	first := a.AKPublic
	flush(tpm, a.ak.handle)
	if err := a.createAK(); err != nil {
		t.Fatal(err)
	}
	_, id, enc, err := MakeCredential(p.verify(t, a.Cert), first)
	if err != nil {
		t.Fatal(err)
	}
	if secret, err := a.ActivateCredential(id, enc); err == nil {
		t.Errorf("a credential for another AK was opened: %x", secret)
	}
}

// Ensures a TPM without a usable certificate is reported as ErrNoCertificate.
func TestNoCertificate(t *testing.T) {
	tpm := tpmtest.Open(t, 1)
	if _, err := NewAgent(tpm); !errors.Is(err, ErrNoCertificate) {
		t.Errorf("empty TPM: %v", err)
	}
	if _, _, err := Certificate(tpm); !errors.Is(err, ErrNoCertificate) {
		t.Errorf("empty TPM: %v", err)
	}

	// Data that is no certificate, and a manufacturer's EK certificate without claims.
	p := newPKI(t)
	tpmtest.WriteNV(t, tpm, contract.NVIndexBaremetal, []byte("not DER at all"))
	tpmtest.WriteNV(t, tpm, contract.NVIndexVM, p.root.Cert.Raw)
	if _, err := NewAgent(tpm); !errors.Is(err, ErrNoCertificate) {
		t.Errorf("TPM without a certificate with claims: %v", err)
	}
	if n := tpmtest.Transients(t, tpm); n != 0 {
		t.Errorf("%d transient objects left", n)
	}
}

// Ensures the bare-metal certificate takes precedence and indexes without claims are skipped.
func TestCertificatePrecedence(t *testing.T) {
	tpm := tpmtest.Open(t, 1)
	p := newPKI(t)
	vm := tpmtest.Provision(t, tpm, testClaims(contract.KindVM), p.issuing, tpmtest.Options{})
	der, v, err := Certificate(tpm)
	if err != nil || !bytes.Equal(der, vm) || v.Claims.Kind != contract.KindVM {
		t.Fatalf("vm index alone: %v", err)
	}

	tpmtest.WriteNV(t, tpm, contract.NVIndexBaremetal, p.root.Cert.Raw)
	if der, _, err = Certificate(tpm); err != nil || !bytes.Equal(der, vm) {
		t.Fatalf("vm index next to a baremetal index without claims: %v", err)
	}

	bm := tpmtest.Provision(t, tpm, testClaims(contract.KindBaremetal), p.issuing, tpmtest.Options{})
	if der, v, err = Certificate(tpm); err != nil || !bytes.Equal(der, bm) || v.Claims.Kind != contract.KindBaremetal {
		t.Fatalf("both indexes: %v", err)
	}
	a, err := NewAgent(tpm)
	if err != nil {
		t.Fatal(err)
	}
	defer a.release()
	if a.Claims.Kind != contract.KindBaremetal {
		t.Errorf("agent attests as %s", a.Claims.Kind)
	}
	attest(t, p, a)
}

// Ensures ReadNV returns exactly the DER certificate and refuses undefined or erased indexes.
func TestReadNV(t *testing.T) {
	tpm := tpmtest.Open(t, 1)
	p := newPKI(t)
	der := p.issuing.Cert.Raw
	for _, pad := range []int{0, 1, 700} {
		tpmtest.WriteNV(t, tpm, contract.NVIndexBaremetal, append(bytes.Clone(der), make([]byte, pad)...))
		got, err := ReadNV(tpm, contract.NVIndexBaremetal)
		if err != nil || !bytes.Equal(got, der) {
			t.Errorf("padding %d: %d bytes, %v", pad, len(got), err)
		}
	}
	if _, err := ReadNV(tpm, contract.NVIndexVM); err == nil {
		t.Error("read an undefined index")
	}
	tpmtest.WriteNV(t, tpm, contract.NVIndexBaremetal, bytes.Repeat([]byte{0xff}, 64))
	if _, err := ReadNV(tpm, contract.NVIndexBaremetal); err == nil {
		t.Error("an erased index read as DER")
	}
}

// Ensures only a restricted, TPM-resident signing key is accepted as AK.
func TestCheckAK(t *testing.T) {
	if _, err := CheckAK(tpm2.Marshal(akTemplate())); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*tpm2.TPMAObject){
		"not restricted":      func(a *tpm2.TPMAObject) { a.Restricted = false },
		"not signing":         func(a *tpm2.TPMAObject) { a.SignEncrypt = false },
		"decrypting":          func(a *tpm2.TPMAObject) { a.Decrypt = true },
		"storage key":         func(a *tpm2.TPMAObject) { a.SignEncrypt, a.Decrypt = false, true },
		"not fixed to TPM":    func(a *tpm2.TPMAObject) { a.FixedTPM = false },
		"not fixed to parent": func(a *tpm2.TPMAObject) { a.FixedParent = false },
		"imported":            func(a *tpm2.TPMAObject) { a.SensitiveDataOrigin = false },
		"policy only":         func(a *tpm2.TPMAObject) { a.UserWithAuth = false },
	} {
		tmpl := akTemplate()
		mod(&tmpl.ObjectAttributes)
		if _, err := CheckAK(tpm2.Marshal(tmpl)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, b := range map[string][]byte{"empty": nil, "junk": []byte("junk"), "truncated": tpm2.Marshal(akTemplate())[:7]} {
		if _, err := CheckAK(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A keyed-hash object with a signing key's attributes.
	hmac := tpm2.TPMTPublic{
		Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256, ObjectAttributes: akTemplate().ObjectAttributes,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256})},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: make([]byte, 32)}),
	}
	if _, err := CheckAK(tpm2.Marshal(hmac)); err == nil {
		t.Error("keyed-hash AK accepted")
	}

	// MakeCredential applies the same check.
	issuing := pkitest.NewCA(t, "issuing", nil)
	key := issuing.Key.PublicKey // any P-384 key
	der, err := contract.Build(testClaims(contract.KindVM), &key, time.Now(), issuing.Cert, issuing.Key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := contract.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	bad := akTemplate()
	bad.ObjectAttributes.Restricted = false
	if _, _, _, err := MakeCredential(v, tpm2.Marshal(bad)); err == nil {
		t.Error("credential made for an unrestricted AK")
	}
	if _, _, _, err := MakeCredential(v, tpm2.Marshal(akTemplate())); err != nil {
		t.Errorf("credential for a well-formed AK: %v", err)
	}
}

// Ensures Equal compares contents exactly.
func TestEqual(t *testing.T) {
	if !Equal([]byte("abc"), []byte("abc")) || Equal([]byte("abc"), []byte("abd")) || Equal([]byte("abc"), nil) || Equal(nil, []byte("a")) {
		t.Error("Equal")
	}
}
