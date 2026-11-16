// Package tpmtest gives unit tests a simulated TPM and the platform's part of provisioning it.
package tpmtest

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/pkitest"
)

// Open opens a factory-fresh simulated TPM whose hierarchy seeds derive from seed, and closes it when the test ends.
// The simulator is a process-wide singleton, so a second Open blocks until the first is closed.
func Open(t testing.TB, seed int64) transport.TPMCloser {
	t.Helper()
	s, err := simulator.GetWithFixedSeedInsecure(seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !s.IsClosed() {
			s.Close()
		}
	})
	return transport.FromReadWriteCloser(s)
}

type keepOpen struct{ transport.TPM }

func (keepOpen) Close() error { return nil }

// KeepOpen wraps a TPM so that closing what uses it leaves the simulator open.
func KeepOpen(tpm transport.TPM) transport.TPMCloser { return keepOpen{tpm} }

// Options vary what Provision does.
type Options struct {
	Persist bool // persist the key at the kind's handle
	Unique  int  // bytes of zeros per coordinate in the template's unique field
}

// Provision creates the kind's key, certifies it with issuing, and stores and returns the certificate.
func Provision(t testing.TB, tpm transport.TPM, claims contract.Claims, issuing *pkitest.CA, o Options) []byte {
	t.Helper()
	k, err := contract.KeyOf(claims.Kind)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := contract.Template(claims.Kind, make([]byte, o.Unique), make([]byte, o.Unique))
	if err != nil {
		t.Fatal(err)
	}
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: k.Hierarchy, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(tmpl),
	}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(tpm) }()
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	key, err := contract.PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	der, err := contract.Build(claims, key.(*ecdsa.PublicKey), time.Now(), issuing.Cert, issuing.Key)
	if err != nil {
		t.Fatal(err)
	}
	WriteNV(t, tpm, k.NVIndex, der)
	if o.Persist {
		Evict(t, tpm, rsp.ObjectHandle, rsp.Name, k.Handle)
	}
	return der
}

// WriteNV replaces idx with data, defined by the platform for the vm index as swtpm_setup does, and by the owner otherwise.
func WriteNV(t testing.TB, tpm transport.TPM, idx tpm2.TPMHandle, data []byte) {
	t.Helper()
	auth := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	attrs := tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, AuthRead: true, NoDA: true, NT: tpm2.TPMNTOrdinary}
	if idx == contract.NVIndexVM {
		auth.Handle = tpm2.TPMRHPlatform
		attrs = tpm2.TPMANV{PPWrite: true, PPRead: true, OwnerRead: true, AuthRead: true, NoDA: true, PlatformCreate: true, NT: tpm2.TPMNTOrdinary}
	}
	if pub, err := (tpm2.NVReadPublic{NVIndex: idx}).Execute(tpm); err == nil {
		if _, err := (tpm2.NVUndefineSpace{AuthHandle: auth, NVIndex: tpm2.NamedHandle{Handle: idx, Name: pub.NVName}}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: auth, PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
		NVIndex: idx, NameAlg: tpm2.TPMAlgSHA256, Attributes: attrs, DataSize: uint16(len(data)),
	})}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	pub, err := tpm2.NVReadPublic{NVIndex: idx}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(data); off += 512 {
		if _, err := (tpm2.NVWrite{AuthHandle: auth, NVIndex: tpm2.NamedHandle{Handle: idx, Name: pub.NVName},
			Data: tpm2.TPM2BMaxNVBuffer{Buffer: data[off:min(off+512, len(data))]}, Offset: uint16(off)}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
	}
}

// Evict persists a transient object at a handle, or evicts the persistent object there, with the empty owner auth.
func Evict(t testing.TB, tpm transport.TPM, object tpm2.TPMHandle, name tpm2.TPM2BName, at tpm2.TPMHandle) {
	t.Helper()
	if _, err := (tpm2.EvictControl{
		Auth:         tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		ObjectHandle: &tpm2.NamedHandle{Handle: object, Name: name}, PersistentHandle: at,
	}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
}

// Transients is the number of loaded transient objects, which shows leaked handles.
func Transients(t testing.TB, tpm transport.TPM) int {
	t.Helper()
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: uint32(tpm2.TPMHTTransient) << 24, PropertyCount: 16}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	h, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		t.Fatal(err)
	}
	return len(h.Handle)
}
