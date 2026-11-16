package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/contract"
)

// swtpm_setup also needs an RSA EK and a platform certificate, which attestation never uses and no verifier trusts.
// openstack-tpm-swtpm makes both itself, signed by a throwaway key under an issuer named untrusted.

// UntrustedIssuer is the issuer of the locally made certificates.
const UntrustedIssuer = "openstack-tpm-swtpm (untrusted)"

// parseEK decodes swtpm's --ek, an ECC point or an RSA modulus in hex with exponent 65537.
func parseEK(s string) (crypto.PublicKey, error) {
	if isECC(s) {
		return contract.ParsePoint(s)
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok || n.BitLen() < 2048 {
		return nil, errors.New("--ek is not an RSA modulus of at least 2048 bits")
	}
	return &rsa.PublicKey{N: n, E: 65537}, nil
}

// localCert makes an untrusted certificate for swtpm_setup's EK.
func localCert(a *args) ([]byte, error) {
	if a.vmid == "" || a.ek == "" {
		return nil, errors.New("--vmid and --ek are required")
	}
	pub, err := parseEK(a.ek)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := contract.NewSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: a.vmid},
		NotBefore: time.Now().UTC().Truncate(time.Second), NotAfter: contract.NotAfter(),
	}
	issuer := &x509.Certificate{Subject: pkix.Name{CommonName: UntrustedIssuer}}
	return x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, key)
}
