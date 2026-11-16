// Package issuerapi defines the issuer's HTTP requests, responses and error codes.
package issuerapi

// Issuer endpoints.
const (
	PathVMCertificate        = "/v1/vm/certificates"
	PathBaremetalCertificate = "/v1/baremetal/certificates"
	PathBaremetalClear       = "/v1/baremetal/clear"
	PathBaremetalClearKey    = "/v1/baremetal/clear-key"
)

// VMCertificateRequest is the hypervisor hook's request for a vTPM EK certificate; the answer is the certificate in DER.
type VMCertificateRequest struct {
	InstanceUUID string `json:"instance_uuid"`
	Key          string `json:"key"` // swtpm's --ek argument for the ECC P-384 EK
}

// BaremetalCertificateRequest is the IPA deploy step's request for an instance key certificate.
type BaremetalCertificateRequest struct {
	Node      string `json:"node"`       // Ironic node UUID
	Instance  string `json:"instance"`   // Nova instance UUID
	EKPublic  []byte `json:"ek_public"`  // marshaled TPMT_PUBLIC of the RSA-2048 EK
	KeyPublic []byte `json:"key_public"` // marshaled TPMT_PUBLIC of the instance key
}

// BaremetalCertificateResponse is the certificate encrypted under a credential that only the node's TPM with the instance key can activate.
type BaremetalCertificateResponse struct {
	IDObject   []byte `json:"id_object"`
	EncSecret  []byte `json:"enc_secret"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"` // AES-256-GCM(secret, nonce, certificate DER)
}

// ClearKey is the public part of the provider's clear key (ECDSA P-256).
type ClearKey struct {
	X []byte `json:"x"`
	Y []byte `json:"y"`
}

// ClearRequest asks for a clear authorization bound to the nonce of a TPM policy session.
type ClearRequest struct {
	Node  string `json:"node"`
	Nonce []byte `json:"nonce"`
}

// ClearResponse is the provider's signature authorizing TPM2_Clear on the lockout hierarchy for that nonce.
type ClearResponse struct {
	Key ClearKey `json:"key"`
	R   []byte   `json:"r"`
	S   []byte   `json:"s"`
}

// Error is the body of every non-2xx issuer response.
type Error struct {
	Code    string `json:"error"`
	Message string `json:"message"`
}

// Issuer error codes (Error.Code).
const (
	CodeInvalid     = "invalid"     // malformed request
	CodeRefused     = "refused"     // the control plane does not show this build, deploy or clean for the caller
	CodeForbidden   = "forbidden"   // the issuer's OpenStack identity lacks a role or policy rule for a lookup
	CodeUnavailable = "unavailable" // a control-plane lookup or the signature failed
)
