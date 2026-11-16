// Package tpmprov provisions a bare-metal node's TPM in the IPA deploy and clean steps.
// The issuer uses the same helpers for the values both sides must agree on.
package tpmprov

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/issuerapi"
)

// ClearPolicyRef binds a clear authorization to one node and tells it apart from any other signature of the provider's clear key.
// It is hashed because a policyRef holds at most one digest of the TPM's largest hash.
func ClearPolicyRef(node string) []byte {
	h := sha256.New()
	h.Write([]byte("openstack-tpm clear\x00"))
	h.Write([]byte(node))
	return h.Sum(nil)
}

// TPMA_PERMANENT bits.
const (
	ownerAuthSet       = 1 << 0
	endorsementAuthSet = 1 << 1
	lockoutAuthSet     = 1 << 2
)

type Issuer interface {
	ClearKey(ctx context.Context) (*issuerapi.ClearKey, error)
	Clear(ctx context.Context, req *issuerapi.ClearRequest) (*issuerapi.ClearResponse, error)
	Certificate(ctx context.Context, req *issuerapi.BaremetalCertificateRequest) (*issuerapi.BaremetalCertificateResponse, error)
}

// ClearKeyPublic is the public area of the provider's clear key (ECDSA P-256) for TPM2_LoadExternal.
func ClearKeyPublic(k issuerapi.ClearKey) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{SignEncrypt: true, UserWithAuth: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: k.X},
			Y: tpm2.TPM2BECCParameter{Buffer: k.Y},
		}),
	}
}

// LockoutPolicy is the lockout hierarchy's policy the deploy step sets on a node, TPM2_PolicySigned by the provider's clear key for that node.
func LockoutPolicy(k issuerapi.ClearKey, node string) ([]byte, error) {
	pub := ClearKeyPublic(k)
	name, err := tpm2.ObjectName(&pub)
	if err != nil {
		return nil, err
	}
	pc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	err = tpm2.PolicySigned{
		AuthObject: tpm2.NamedHandle{Handle: tpm2.TPMRHNull, Name: *name},
		PolicyRef:  tpm2.TPM2BNonce{Buffer: ClearPolicyRef(node)},
	}.Update(pc)
	if err != nil {
		return nil, err
	}
	return pc.Hash().Digest, nil
}

// clearCPHash is the command-parameter hash of TPM2_Clear(TPM_RH_LOCKOUT), which limits an authorization to that command.
func clearCPHash() []byte {
	h := sha256.New()
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(tpm2.TPMCCClear)))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(tpm2.TPMRHLockout))) // the name of a hierarchy is its handle
	return h.Sum(nil)
}

// ClearDigest is what the provider signs to authorize one TPM2_Clear of the node's TPM in the policy session with nonceTPM.
func ClearDigest(nonceTPM []byte, node string) []byte {
	h := sha256.New()
	h.Write(nonceTPM)
	h.Write(binary.BigEndian.AppendUint32(nil, 0)) // expiration
	h.Write(clearCPHash())
	h.Write(ClearPolicyRef(node))
	return h.Sum(nil)
}

// SealCertificate encrypts a certificate so that only the TPM with this EK and a loaded key of this name can open it.
func SealCertificate(ek *tpm2.TPMTPublic, keyName, der []byte) (*issuerapi.BaremetalCertificateResponse, error) {
	kem, err := tpm2.ImportEncapsulationKey(ek)
	if err != nil {
		return nil, fmt.Errorf("EK: %w", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	idObject, encSecret, err := tpm2.CreateCredential(rand.Reader, kem, keyName, secret)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &issuerapi.BaremetalCertificateResponse{
		IDObject: idObject, EncSecret: encSecret, Nonce: nonce, Ciphertext: gcm.Seal(nil, nonce, der, nil),
	}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EKHash is the hash of an EK as recorded for a node at inspection.
func EKHash(pub *tpm2.TPMTPublic) (string, error) {
	key, err := contract.PublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("EK: %w", err)
	}
	return contract.KeyHash(key)
}

type object struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	pub    tpm2.TPMTPublic
}

// emptyAuth authorizes with a hierarchy's empty password.
func emptyAuth(hierarchy tpm2.TPMHandle) tpm2.AuthHandle {
	return tpm2.AuthHandle{Handle: hierarchy, Auth: tpm2.PasswordAuth(nil)}
}

// flush flushes a transient object, best effort.
func flush(t transport.TPM, h tpm2.TPMHandle) { _, _ = tpm2.FlushContext{FlushHandle: h}.Execute(t) }

func permanent(t transport.TPM) (uint32, error) {
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapTPMProperties,
		Property: uint32(tpm2.TPMPTPermanent), PropertyCount: 1}.Execute(t)
	if err != nil {
		return 0, err
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	if len(props.TPMProperty) == 0 {
		return 0, errors.New("the TPM reports no TPM_PT_PERMANENT")
	}
	return props.TPMProperty[0].Value, nil
}

func primary(t transport.TPM, hierarchy tpm2.TPMHandle, tmpl tpm2.TPMTPublic) (object, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: emptyAuth(hierarchy),
		InPublic:      tpm2.New2B(tmpl),
	}.Execute(t)
	if err != nil {
		return object{}, err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		flush(t, rsp.ObjectHandle)
		return object{}, err
	}
	return object{rsp.ObjectHandle, rsp.Name, *pub}, nil
}

// ek creates the RSA-2048 EK from the TCG low-range template, which every TPM 2.0 has a certificate for.
func ek(t transport.TPM) (object, error) {
	o, err := primary(t, tpm2.TPMRHEndorsement, tpm2.RSAEKTemplate)
	if err != nil {
		return object{}, fmt.Errorf("create the EK: %w", err)
	}
	return o, nil
}

func instanceKey(t transport.TPM) (object, error) {
	tmpl, err := contract.Template(contract.KindBaremetal, nil, nil)
	if err != nil {
		return object{}, err
	}
	o, err := primary(t, tpm2.TPMRHOwner, tmpl)
	if err != nil {
		return object{}, fmt.Errorf("create the instance key: %w", err)
	}
	return o, nil
}

// EK returns the hash of the TPM's RSA EK, for the inspection collector.
func EK(t transport.TPM) (string, error) {
	o, err := ek(t)
	if err != nil {
		return "", err
	}
	defer flush(t, o.handle)
	return EKHash(&o.pub)
}

// writeNV (re)defines an owner index that the agent can read without hierarchy auth, and writes data.
func writeNV(t transport.TPM, idx tpm2.TPMHandle, data []byte) error {
	owner := emptyAuth(tpm2.TPMRHOwner)
	if pub, err := (tpm2.NVReadPublic{NVIndex: idx}).Execute(t); err == nil {
		if _, err := (tpm2.NVUndefineSpace{AuthHandle: owner,
			NVIndex: tpm2.NamedHandle{Handle: idx, Name: pub.NVName}}).Execute(t); err != nil {
			return fmt.Errorf("undefine NV %#x: %w", uint32(idx), err)
		}
	}
	_, err := tpm2.NVDefineSpace{
		AuthHandle: owner,
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: idx, NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, AuthRead: true, NoDA: true, NT: tpm2.TPMNTOrdinary},
			DataSize:   uint16(len(data)),
		}),
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("define NV %#x (%d bytes): %w", uint32(idx), len(data), err)
	}
	pub, err := tpm2.NVReadPublic{NVIndex: idx}.Execute(t)
	if err != nil {
		return err
	}
	for off := 0; off < len(data); off += 512 {
		end := min(off+512, len(data))
		_, err := tpm2.NVWrite{AuthHandle: owner, NVIndex: tpm2.NamedHandle{Handle: idx, Name: pub.NVName},
			Data: tpm2.TPM2BMaxNVBuffer{Buffer: data[off:end]}, Offset: uint16(off)}.Execute(t)
		if err != nil {
			return fmt.Errorf("write NV %#x at %d: %w", uint32(idx), off, err)
		}
	}
	return nil
}

// persist stores the object at an owner handle, evicting what was there.
func persist(t transport.TPM, o object, at tpm2.TPMHandle) error {
	owner := emptyAuth(tpm2.TPMRHOwner)
	if old, err := (tpm2.ReadPublic{ObjectHandle: at}).Execute(t); err == nil {
		if _, err := (tpm2.EvictControl{Auth: owner, ObjectHandle: &tpm2.NamedHandle{Handle: at, Name: old.Name},
			PersistentHandle: at}).Execute(t); err != nil {
			return fmt.Errorf("evict %#x: %w", uint32(at), err)
		}
	}
	_, err := tpm2.EvictControl{Auth: owner, ObjectHandle: &tpm2.NamedHandle{Handle: o.handle, Name: o.name},
		PersistentHandle: at}.Execute(t)
	return err
}

// setPrimaryPolicy sends TPM2_SetPrimaryPolicy, which go-tpm does not wrap.
func setPrimaryPolicy(t transport.TPM, hierarchy tpm2.TPMHandle, auth, policy []byte, alg tpm2.TPMAlgID) error {
	var b bytes.Buffer
	// Writing fixed-size values into a buffer cannot fail.
	w := func(v any) { _ = binary.Write(&b, binary.BigEndian, v) }
	w(uint16(0x8002)) // TPM_ST_SESSIONS
	w(uint32(0))      // size, patched below
	w(uint32(tpm2.TPMCCSetPrimaryPolicy))
	w(uint32(hierarchy))
	w(uint32(9 + len(auth))) // authorization area: one password session
	w(uint32(0x40000009))    // TPM_RS_PW
	w(uint16(0))             // nonce
	w(uint8(0))              // session attributes
	w(uint16(len(auth)))
	b.Write(auth)
	w(uint16(len(policy)))
	b.Write(policy)
	w(uint16(alg))
	cmd := b.Bytes()
	binary.BigEndian.PutUint32(cmd[2:], uint32(len(cmd)))
	rsp, err := t.Send(cmd)
	if err != nil {
		return err
	}
	if len(rsp) < 10 {
		return errors.New("short TPM2_SetPrimaryPolicy response")
	}
	if rc := binary.BigEndian.Uint32(rsp[6:10]); rc != 0 {
		return fmt.Errorf("TPM2_SetPrimaryPolicy: %w", tpm2.TPMRC(rc))
	}
	return nil
}

// Cleared reports whether the lockout auth is unset, which means the TPM was cleared since the last deploy.
func Cleared(t transport.TPM) (bool, error) {
	perm, err := permanent(t)
	return perm&lockoutAuthSet == 0, err
}

// clear clears the TPM with the empty lockout password or the provider's signed authorization, and returns which.
func clear(ctx context.Context, t transport.TPM, is Issuer, node string) (string, error) {
	free, err := Cleared(t)
	if err != nil {
		return "", err
	}
	if free {
		_, err := tpm2.Clear{AuthHandle: emptyAuth(tpm2.TPMRHLockout)}.Execute(t)
		if err != nil {
			return "", fmt.Errorf("TPM2_Clear with the empty lockout password: %w", err)
		}
		return "free", nil
	}
	sess, closeSess, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 32)
	if err != nil {
		return "", fmt.Errorf("policy session: %w", err)
	}
	defer func() { _ = closeSess() }()
	rsp, err := is.Clear(ctx, &issuerapi.ClearRequest{Node: node, Nonce: sess.NonceTPM().Buffer})
	if err != nil {
		return "", fmt.Errorf("clear authorization: %w", err)
	}
	key, err := tpm2.LoadExternal{InPublic: tpm2.New2B(ClearKeyPublic(rsp.Key)), Hierarchy: tpm2.TPMRHNull}.Execute(t)
	if err != nil {
		return "", fmt.Errorf("load the provider's clear key: %w", err)
	}
	defer flush(t, key.ObjectHandle)
	_, err = tpm2.PolicySigned{
		AuthObject:    tpm2.NamedHandle{Handle: key.ObjectHandle, Name: key.Name},
		PolicySession: sess.Handle(), NonceTPM: sess.NonceTPM(),
		CPHashA:   tpm2.TPM2BDigest{Buffer: clearCPHash()},
		PolicyRef: tpm2.TPM2BNonce{Buffer: ClearPolicyRef(node)},
		Auth: tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
				Hash:       tpm2.TPMAlgSHA256,
				SignatureR: tpm2.TPM2BECCParameter{Buffer: rsp.R},
				SignatureS: tpm2.TPM2BECCParameter{Buffer: rsp.S},
			})},
	}.Execute(t)
	if err != nil {
		return "", fmt.Errorf("TPM2_PolicySigned: %w", err)
	}
	if _, err := (tpm2.Clear{AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: sess}}).Execute(t); err != nil {
		return "", fmt.Errorf("TPM2_Clear with the provider's authorization: %w", err)
	}
	return "authorized", nil
}

// evictLeftover evicts the instance key if a clear left it persisted, and reports whether it did.
// TPM2_Clear flushes it on a TPM that follows the specification; libtpms 0.10.2 with a profile does not (https://github.com/stefanberger/libtpms/issues/626).
func evictLeftover(t transport.TPM) (bool, error) {
	at := contract.HandleBaremetal
	old, err := tpm2.ReadPublic{ObjectHandle: at}.Execute(t)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("read %#x after the clear: %w", uint32(at), err)
	}
	if _, err := (tpm2.EvictControl{Auth: emptyAuth(tpm2.TPMRHOwner), ObjectHandle: &tpm2.NamedHandle{Handle: at, Name: old.Name},
		PersistentHandle: at}).Execute(t); err != nil {
		return false, fmt.Errorf("evict the key the clear left at %#x: %w", uint32(at), err)
	}
	return true, nil
}

// lock hands the lockout hierarchy to the provider's signature and sets its password to a random value kept nowhere.
func lock(ctx context.Context, t transport.TPM, is Issuer, node string) error {
	key, err := is.ClearKey(ctx)
	if err != nil {
		return fmt.Errorf("the provider's clear key: %w", err)
	}
	policy, err := LockoutPolicy(*key, node)
	if err != nil {
		return err
	}
	if err := setPrimaryPolicy(t, tpm2.TPMRHLockout, nil, policy, tpm2.TPMAlgSHA256); err != nil {
		return err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	_, err = tpm2.HierarchyChangeAuth{
		AuthHandle: emptyAuth(tpm2.TPMRHLockout),
		NewAuth:    tpm2.TPM2BAuth{Buffer: random},
	}.Execute(t)
	return err
}

// Result is what a step did, for the step's log.
type Result struct {
	Action  string `json:"action"`            // issued (deploy) or cleared (clean)
	Cleared string `json:"cleared,omitempty"` // how the TPM was cleared: free or authorized
	Evicted bool   `json:"evicted,omitempty"` // the clear left the instance key persisted, and the step evicted it
	EK      string `json:"ek_sha256,omitempty"`
	Key     string `json:"key_sha256,omitempty"`
	Claims  string `json:"claims,omitempty"`
}

// Deploy is the IPA deploy step, which creates a new instance key at every deploy.
func Deploy(ctx context.Context, t transport.TPM, is Issuer, node, instance string) (*Result, error) {
	// 1. The TPM has not been cleared since the last deploy.
	free, err := Cleared(t)
	if err != nil {
		return nil, err
	}
	res := &Result{Action: "issued"}
	if !free {
		if res.Cleared, err = clear(ctx, t, is, node); err != nil {
			return nil, fmt.Errorf("clear before deploy: %w", err)
		}
		if res.Evicted, err = evictLeftover(t); err != nil {
			return nil, err
		}
		if free, err = Cleared(t); err != nil {
			return nil, err
		} else if !free {
			return nil, errors.New("the lockout hierarchy is still owned after the clear")
		}
	}

	// 2. From here the provider owns the lockout hierarchy.
	if err := lock(ctx, t, is, node); err != nil {
		return nil, fmt.Errorf("lock the lockout hierarchy: %w", err)
	}

	// 3. The instance key and its certificate.
	ekObj, err := ek(t)
	if err != nil {
		return nil, err
	}
	defer flush(t, ekObj.handle)
	key, err := instanceKey(t)
	if err != nil {
		return nil, err
	}
	defer flush(t, key.handle)
	rsp, err := is.Certificate(ctx, &issuerapi.BaremetalCertificateRequest{
		Node: node, Instance: instance, EKPublic: tpm2.Marshal(ekObj.pub), KeyPublic: tpm2.Marshal(key.pub),
	})
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	der, err := openCertificate(t, ekObj, key, rsp)
	if err != nil {
		return nil, err
	}
	v, err := contract.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("the issuer's certificate: %w", err)
	}
	if v.Claims.InstanceID != instance || v.Claims.Kind != contract.KindBaremetal {
		return nil, fmt.Errorf("the issuer's certificate is for %s %s", v.Claims.Kind, v.Claims.InstanceID)
	}

	// 4. Certificate to NV, key to its handle.
	if err := writeNV(t, contract.NVIndexBaremetal, der); err != nil {
		return nil, err
	}
	if err := persist(t, key, contract.HandleBaremetal); err != nil {
		return nil, fmt.Errorf("persist the instance key: %w", err)
	}
	res.EK, _ = EKHash(&ekObj.pub)
	res.Key, _ = contract.KeyHash(v.Key)
	res.Claims = v.Claims.URI()
	return res, nil
}

// openCertificate recovers the secret with TPM2_ActivateCredential and decrypts the certificate.
// The RSA EK is adminWithPolicy, so using it needs PolicySecret(endorsement).
func openCertificate(t transport.TPM, ekObj, key object, rsp *issuerapi.BaremetalCertificateResponse) ([]byte, error) {
	sess, closeSess, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("policy session: %w", err)
	}
	defer func() { _ = closeSess() }()
	if _, err := (tpm2.PolicySecret{
		AuthHandle:    emptyAuth(tpm2.TPMRHEndorsement),
		PolicySession: sess.Handle(), NonceTPM: sess.NonceTPM(),
	}).Execute(t); err != nil {
		return nil, fmt.Errorf("TPM2_PolicySecret(endorsement): %w", err)
	}
	act, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: key.handle, Name: key.name, Auth: tpm2.PasswordAuth(nil)},
		KeyHandle:      tpm2.AuthHandle{Handle: ekObj.handle, Name: ekObj.name, Auth: sess},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: rsp.IDObject},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: rsp.EncSecret},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("TPM2_ActivateCredential with the EK and the instance key: %w", err)
	}
	gcm, err := newGCM(act.CertInfo.Buffer)
	if err != nil {
		return nil, err
	}
	der, err := gcm.Open(nil, rsp.Nonce, rsp.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("open the certificate: %w", err)
	}
	return der, nil
}

// Clean is the IPA clean step.
func Clean(ctx context.Context, t transport.TPM, is Issuer, node string) (*Result, error) {
	var before []byte
	if key, err := instanceKey(t); err == nil {
		before = key.name.Buffer
		flush(t, key.handle)
	}
	how, err := clear(ctx, t, is, node)
	if err != nil {
		return nil, err
	}
	evicted, err := evictLeftover(t)
	if err != nil {
		return nil, err
	}
	perm, err := permanent(t)
	if err != nil {
		return nil, err
	}
	if perm&(lockoutAuthSet|ownerAuthSet|endorsementAuthSet) != 0 {
		return nil, errors.New("a hierarchy auth is still set after the clear")
	}
	key, err := instanceKey(t)
	if err != nil {
		return nil, err
	}
	defer flush(t, key.handle)
	if before != nil && bytes.Equal(before, key.name.Buffer) {
		return nil, errors.New("the storage primary survived the clear")
	}
	return &Result{Action: "cleared", Cleared: how, Evicted: evicted}, nil
}
