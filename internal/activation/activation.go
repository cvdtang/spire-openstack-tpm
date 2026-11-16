// Package activation is the credential-activation exchange of an attestation, agent and server side.
package activation

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/cvdtang/openstack-tpm/internal/contract"
)

// ErrKeyMismatch means the TPM does not hold the key the certificate names.
var ErrKeyMismatch = errors.New("key_mismatch")

// ErrNoCertificate means no NV index holds a certificate with claims.
var ErrNoCertificate = errors.New("no instance certificate in the TPM")

// akTemplate is a restricted ECDSA P-256 signing key, created fresh under the certified key for every attestation.
func akTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, Restricted: true, SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
}

// CheckAK parses the agent's AK and requires a restricted signing key that the TPM generated and cannot move.
func CheckAK(akPublic []byte) (*tpm2.TPMTPublic, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](akPublic)
	if err != nil {
		return nil, fmt.Errorf("AK public area: %w", err)
	}
	a := pub.ObjectAttributes
	signing := a.Restricted && a.SignEncrypt && a.FixedTPM && a.FixedParent && a.SensitiveDataOrigin && a.UserWithAuth
	if !signing || a.Decrypt {
		return nil, fmt.Errorf("AK attributes %+v are not those of a restricted TPM-resident signing key", a)
	}
	if pub.Type != tpm2.TPMAlgECC && pub.Type != tpm2.TPMAlgRSA {
		return nil, fmt.Errorf("AK type %v", pub.Type)
	}
	return pub, nil
}

// MakeCredential wraps a fresh 32-byte secret to the certified key and the AK's name.
// The key's public area comes from the certificate, never from the agent.
func MakeCredential(v *contract.Verified, akPublic []byte) (secret, idObject, encSecret []byte, err error) {
	ak, err := CheckAK(akPublic)
	if err != nil {
		return nil, nil, nil, err
	}
	name, err := tpm2.ObjectName(ak)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPub, err := contract.KeyPublic(v.Claims.Kind, v.Key)
	if err != nil {
		return nil, nil, nil, err
	}
	kem, err := tpm2.ImportEncapsulationKey(&keyPub)
	if err != nil {
		return nil, nil, nil, err
	}
	secret = make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, nil, err
	}
	idObject, encSecret, err = tpm2.CreateCredential(rand.Reader, kem, name.Buffer, secret)
	return secret, idObject, encSecret, err
}

// Equal compares a challenge answer in constant time.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

type object struct {
	handle     tpm2.TPMHandle
	name       tpm2.TPM2BName
	persistent bool // not flushed
}

// Agent holds the certified key and a transient AK for one attestation.
type Agent struct {
	tpm     transport.TPMCloser
	key, ak object
	// Cert is the instance's certificate from NV.
	Cert   []byte
	Claims contract.Claims
	// AKPublic is the marshaled TPMT_PUBLIC of the AK.
	AKPublic []byte
}

// Open opens the TPM (device on Linux, TBS on Windows), reads the certificate, finds the certified key and creates an AK under it.
func Open(device string) (*Agent, error) {
	t, err := openTPM(device)
	if err != nil {
		return nil, err
	}
	a, err := NewAgent(t)
	if err != nil {
		t.Close()
		return nil, err
	}
	return a, nil
}

// NewAgent does Open's work on an open TPM.
// It uses the persisted key when it is the certified one, and otherwise re-creates the key, which needs the hierarchy's empty auth.
func NewAgent(t transport.TPMCloser) (*Agent, error) {
	der, v, err := Certificate(t)
	if err != nil {
		return nil, err
	}
	a := &Agent{tpm: t, Cert: der, Claims: v.Claims}
	if a.key, err = findKey(t, v); err != nil {
		return nil, err
	}
	if err := a.createAK(); err != nil {
		a.release()
		return nil, err
	}
	return a, nil
}

// Certificate reads the first certificate with claims from the bare-metal NV index, then the vTPM EK certificate index.
func Certificate(t transport.TPM) ([]byte, *contract.Verified, error) {
	var errs []error
	for _, idx := range []tpm2.TPMHandle{contract.NVIndexBaremetal, contract.NVIndexVM} {
		der, err := ReadNV(t, idx)
		if err != nil {
			errs = append(errs, fmt.Errorf("NV %#x: %w", uint32(idx), err))
			continue
		}
		v, err := contract.Parse(der)
		if err != nil {
			errs = append(errs, fmt.Errorf("NV %#x: %w", uint32(idx), err))
			continue
		}
		return der, v, nil
	}
	return nil, nil, fmt.Errorf("%w: %w", ErrNoCertificate, errors.Join(errs...))
}

func findKey(t transport.TPM, v *contract.Verified) (object, error) {
	k, err := contract.KeyOf(v.Claims.Kind)
	if err != nil {
		return object{}, err
	}
	want, err := contract.KeyPublic(v.Claims.Kind, v.Key)
	if err != nil {
		return object{}, err
	}
	if rsp, err := (tpm2.ReadPublic{ObjectHandle: k.Handle}).Execute(t); err == nil &&
		bytes.Equal(rsp.OutPublic.Bytes(), tpm2.Marshal(want)) {
		return object{handle: k.Handle, name: rsp.Name, persistent: true}, nil
	}
	wantName, err := tpm2.ObjectName(&want)
	if err != nil {
		return object{}, err
	}
	// Some TPMs were provisioned with a zero-filled unique field, which yields another key.
	for _, n := range []int{0, 48} {
		tmpl, err := contract.Template(v.Claims.Kind, make([]byte, n), make([]byte, n))
		if err != nil {
			return object{}, err
		}
		rsp, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{Handle: k.Hierarchy, Auth: tpm2.PasswordAuth(nil)},
			InPublic:      tpm2.New2B(tmpl),
		}.Execute(t)
		if err != nil {
			return object{}, fmt.Errorf("re-create the certified key (persisted key %#x is missing or another key; an auth set on the hierarchy prevents this): %w",
				uint32(k.Handle), err)
		}
		if bytes.Equal(rsp.Name.Buffer, wantName.Buffer) {
			return object{handle: rsp.ObjectHandle, name: rsp.Name}, nil
		}
		flush(t, rsp.ObjectHandle)
	}
	return object{}, fmt.Errorf("%w: the TPM's %s key is not the certified key", ErrKeyMismatch, v.Claims.Kind)
}

// createAK creates and loads a fresh AK under the certified key.
func (a *Agent) createAK() error {
	parent := tpm2.AuthHandle{Handle: a.key.handle, Name: a.key.name, Auth: tpm2.PasswordAuth(nil)}
	c, err := tpm2.Create{ParentHandle: parent, InPublic: tpm2.New2B(akTemplate())}.Execute(a.tpm)
	if err != nil {
		return fmt.Errorf("create AK: %w", err)
	}
	l, err := tpm2.Load{ParentHandle: parent, InPrivate: c.OutPrivate, InPublic: c.OutPublic}.Execute(a.tpm)
	if err != nil {
		return fmt.Errorf("load AK: %w", err)
	}
	a.ak = object{handle: l.ObjectHandle, name: l.Name}
	a.AKPublic = c.OutPublic.Bytes()
	return nil
}

// ActivateCredential answers the server's challenge.
func (a *Agent) ActivateCredential(idObject, encSecret []byte) ([]byte, error) {
	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: a.ak.handle, Name: a.ak.name, Auth: tpm2.PasswordAuth(nil)},
		KeyHandle:      tpm2.AuthHandle{Handle: a.key.handle, Name: a.key.name, Auth: tpm2.PasswordAuth(nil)},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: idObject},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encSecret},
	}.Execute(a.tpm)
	if err != nil {
		return nil, err
	}
	return rsp.CertInfo.Buffer, nil
}

// Close flushes the transient objects and closes the TPM.
func (a *Agent) Close() {
	a.release()
	a.tpm.Close()
}

// release flushes the transient objects; the caller owns the transport.
func (a *Agent) release() {
	for _, o := range []object{a.ak, a.key} {
		if o.handle != 0 && !o.persistent {
			flush(a.tpm, o.handle)
		}
	}
	a.ak, a.key = object{}, object{}
}

// flush flushes a transient object, best effort.
func flush(t transport.TPM, h tpm2.TPMHandle) { _, _ = tpm2.FlushContext{FlushHandle: h}.Execute(t) }

// ReadNV reads a whole NV index with its empty auth and trims it to the DER certificate it holds.
func ReadNV(t transport.TPM, idx tpm2.TPMHandle) ([]byte, error) {
	pub, err := tpm2.NVReadPublic{NVIndex: idx}.Execute(t)
	if err != nil {
		return nil, err
	}
	nv, err := pub.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	h := tpm2.NamedHandle{Handle: idx, Name: pub.NVName}
	var out []byte
	for off := uint16(0); off < nv.DataSize; {
		n := min(nv.DataSize-off, 512)
		rsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{Handle: idx, Name: pub.NVName, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    h, Size: n, Offset: off,
		}.Execute(t)
		if err != nil {
			return nil, err
		}
		out = append(out, rsp.Data.Buffer...)
		off += n
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("NV data is not DER: %w", err)
	}
	return bytes.Clone(raw.FullBytes), nil
}
