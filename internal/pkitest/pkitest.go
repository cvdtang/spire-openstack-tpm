// Package pkitest creates throwaway CAs for tests.
package pkitest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is a P-384 certificate authority, valid for one hour around now unless it is an issuing intermediate.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA creates a CA named name, self-signed if parent is nil.
func NewCA(t testing.TB, name string, parent *CA) *CA {
	t.Helper()
	return newCA(t, name, parent, func(*x509.Certificate) {})
}

// NewIssuing creates an issuing intermediate under root that does not expire, like the certificates it signs.
func NewIssuing(t testing.TB, name string, root *CA) *CA {
	t.Helper()
	return newCA(t, name, root, func(c *x509.Certificate) {
		c.NotAfter = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
		c.MaxPathLen, c.MaxPathLenZero = 0, true
	})
}

func newCA(t testing.TB, name string, parent *CA, mod func(*x509.Certificate)) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	mod(tmpl)
	issuer, signer := tmpl, key
	if parent != nil {
		issuer, signer = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{cert, key}
}

// PEM returns the certificate in PEM form.
func (c *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

// WriteBundle writes the CAs' certificates to a PEM file in a temp dir.
func WriteBundle(t testing.TB, cas ...*CA) string {
	t.Helper()
	var b []byte
	for _, c := range cas {
		b = append(b, c.PEM()...)
	}
	f := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}
