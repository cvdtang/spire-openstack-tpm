// Package contract is the interface between the platform and SPIRE.
package contract

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// Version is the version of the claims URI, the certificate profile and the key templates.
const Version = "v1"

// Kinds of instance.
const (
	KindVM        = "vm"
	KindBaremetal = "baremetal"
)

// Where the certificate and the persisted key live in the TPM.
const (
	NVIndexVM        = tpm2.TPMHandle(0x01c00016)
	NVIndexBaremetal = tpm2.TPMHandle(0x01800016)
	HandleVM         = tpm2.TPMHandle(0x81010016)
	HandleBaremetal  = tpm2.TPMHandle(0x81008016)
)

// Scheme is the URI scheme of the claims.
const Scheme = "openstack"

// Refusal reasons.
var (
	// ErrChainInvalid means the certificate does not chain to the bundle.
	ErrChainInvalid = errors.New("chain_invalid")
	// ErrProfile means the certificate chains but is not of this profile.
	ErrProfile = errors.New("profile_invalid")
)

var (
	valueRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	uuidRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	notAfter = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	oidSAN   = asn1.ObjectIdentifier{2, 5, 29, 17} // id-ce-subjectAltName (RFC 5280, 4.2.1.6), built by hand to mark it critical
)

// ValidUUID reports whether s is a canonical lowercase UUID.
func ValidUUID(s string) bool { return uuidRE.MatchString(s) }

func unknownKind(kind string) error {
	return fmt.Errorf("kind %q: want %s or %s", kind, KindVM, KindBaremetal)
}

// Claims are the immutable values a certificate carries.
type Claims struct {
	Region     string
	DomainID   string
	Ancestors  []string
	ProjectID  string
	InstanceID string
	Kind       string
	UserID     string
}

// ParentID is the project's parent: its nearest ancestor, or the domain for a top-level project.
func (c Claims) ParentID() string {
	if len(c.Ancestors) == 0 {
		return c.DomainID
	}
	return c.Ancestors[len(c.Ancestors)-1]
}

// Equal reports whether c and o are the same claims, which valid claims are exactly when their URIs are.
func (c Claims) Equal(o Claims) bool { return c.URI() == o.URI() }

// Validate checks that the claims are complete and have exactly one spelling as a URI.
func (c Claims) Validate() error {
	for _, f := range []struct{ name, v string }{
		{"region", c.Region}, {"domain", c.DomainID}, {"project", c.ProjectID}, {"user", c.UserID},
	} {
		if !valueRE.MatchString(f.v) {
			return fmt.Errorf("claim %s %q: want 1 to 128 letters, digits, '.', '_' or '-'", f.name, f.v)
		}
	}
	if c.DomainID == c.ProjectID {
		return fmt.Errorf("claim project %q is the domain", c.ProjectID)
	}
	seen := map[string]bool{c.DomainID: true, c.ProjectID: true}
	for _, a := range c.Ancestors {
		if !valueRE.MatchString(a) {
			return fmt.Errorf("claim ancestor %q: want 1 to 128 letters, digits, '.', '_' or '-'", a)
		}
		if seen[a] {
			return fmt.Errorf("claim ancestor %q repeats the domain or a project of the chain", a)
		}
		seen[a] = true
	}
	if !ValidUUID(c.InstanceID) {
		return fmt.Errorf("claim instance %q is not a canonical UUID", c.InstanceID)
	}
	if c.Kind != KindVM && c.Kind != KindBaremetal {
		return fmt.Errorf("claim %w", unknownKind(c.Kind))
	}
	return nil
}

// URI returns the claims as the URI a certificate carries. Call Validate first.
func (c Claims) URI() string {
	var u strings.Builder
	u.WriteString(Scheme + ":/" + Version + "/region/" + c.Region + "/domain/" + c.DomainID + "/project/")
	for _, a := range c.Ancestors {
		u.WriteString(a + "/")
	}
	return u.String() + c.ProjectID + "/instance/" + c.InstanceID + "?kind=" + c.Kind + "&user=" + c.UserID
}

// ParseClaims reads the claims from a certificate's URI.
func ParseClaims(u *url.URL) (Claims, error) {
	var c Claims
	if u.Scheme != Scheme || u.Opaque != "" || u.Host != "" || !u.OmitHost || u.User != nil || u.Fragment != "" {
		return c, fmt.Errorf("claims URI %q: want %s:/%s/… without authority or fragment", u.String(), Scheme, Version)
	}
	seg := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if len(seg) > 0 && seg[0] != Version {
		return c, fmt.Errorf("claims version %q is not supported (this build knows %s)", seg[0], Version)
	}
	// The project chain lies between "project" and "instance", found from both ends.
	n := len(seg)
	if n < 9 || seg[1] != "region" || seg[3] != "domain" || seg[5] != "project" || seg[n-2] != "instance" {
		return c, fmt.Errorf("claims path %q: want /%s/region/…/domain/…/project/…/instance/…", u.Path, Version)
	}
	c.Region, c.DomainID, c.InstanceID = seg[2], seg[4], seg[n-1]
	if n > 9 {
		c.Ancestors = seg[6 : n-3]
	}
	c.ProjectID = seg[n-3]
	seen := map[string]bool{}
	for kv := range strings.SplitSeq(u.RawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		var dst *string
		switch k {
		case "kind":
			dst = &c.Kind
		case "user":
			dst = &c.UserID
		default:
			continue
		}
		if seen[k] {
			return c, fmt.Errorf("claims URI repeats %s", k)
		}
		seen[k] = true
		*dst = v
	}
	return c, c.Validate()
}

// policyBSHA384 is the authPolicy of EK template H-3, PolicyBSHA384 in the TCG EK Credential Profile for TPM Family 2.0 v2.6, B.6.5 (Table 36).
// It is the TPM2_PolicyOR of PolicyA, a PolicySecret on the endorsement hierarchy, and PolicyC, a PolicyAuthorizeNV on a reserved NV index.
var policyBSHA384 = []byte{
	0xb2, 0x6e, 0x7d, 0x28, 0xd1, 0x1a, 0x50, 0xbc, 0x53, 0xd8, 0x82, 0xbc,
	0xf5, 0xfd, 0x3a, 0x1a, 0x07, 0x41, 0x48, 0xbb, 0x35, 0xd3, 0xb4, 0xe4,
	0xcb, 0x1c, 0x0a, 0xd9, 0xbd, 0xe4, 0x19, 0xca, 0xcb, 0x47, 0xba, 0x09,
	0x69, 0x96, 0x46, 0x15, 0x0f, 0x9f, 0xc0, 0x00, 0xf3, 0xf8, 0x0e, 0x12,
}

// Key is where a kind's certified primary key and its certificate live in the TPM.
type Key struct {
	Hierarchy tpm2.TPMHandle // endorsement for vm, owner for baremetal
	NVIndex   tpm2.TPMHandle // the certificate
	Handle    tpm2.TPMHandle // the persisted key
}

// KeyOf returns where the key and certificate of a kind live.
func KeyOf(kind string) (Key, error) {
	switch kind {
	case KindVM:
		return Key{tpm2.TPMRHEndorsement, NVIndexVM, HandleVM}, nil
	case KindBaremetal:
		return Key{tpm2.TPMRHOwner, NVIndexBaremetal, HandleBaremetal}, nil
	}
	return Key{}, unknownKind(kind)
}

// Template returns the public area of a kind's key with the unique point x, y (nil for the bare template).
// vm is the TCG EK high-range template H-3; baremetal has the same parameters with noDA and no policy.
func Template(kind string, x, y []byte) (tpm2.TPMTPublic, error) {
	attrs := tpm2.TPMAObject{
		FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
		UserWithAuth: true, Restricted: true, Decrypt: true,
	}
	var policy []byte
	switch kind {
	case KindVM:
		attrs.AdminWithPolicy = true
		policy = policyBSHA384
	case KindBaremetal:
		attrs.NoDA = true
	default:
		return tpm2.TPMTPublic{}, unknownKind(kind)
	}
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA384, ObjectAttributes: attrs,
		AuthPolicy: tpm2.TPM2BDigest{Buffer: policy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(256)),
				Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
			},
			CurveID: tpm2.TPMECCNistP384,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x},
			Y: tpm2.TPM2BECCParameter{Buffer: y},
		}),
	}, nil
}

// KeyPublic returns the public area of a kind's key for a certified point, so verifiers never trust the TPM's.
func KeyPublic(kind string, pub *ecdsa.PublicKey) (tpm2.TPMTPublic, error) {
	if err := CheckKey(pub); err != nil {
		return tpm2.TPMTPublic{}, err
	}
	b, err := pub.Bytes() // 0x04 || X || Y, fixed width
	if err != nil {
		return tpm2.TPMTPublic{}, err
	}
	return Template(kind, b[1:49], b[49:])
}

// CheckKey enforces a P-384 point on the curve.
func CheckKey(pub *ecdsa.PublicKey) error {
	if pub == nil || pub.Curve != elliptic.P384() {
		return errors.New("key is not ECC NIST P-384")
	}
	if _, err := pub.ECDH(); err != nil { // rejects points not on the curve
		return fmt.Errorf("key point: %w", err)
	}
	return nil
}

// ParsePoint decodes swtpm's --ek argument for an ECC EK.
func ParsePoint(s string) (*ecdsa.PublicKey, error) {
	var x, y *big.Int
	for part := range strings.SplitSeq(s, ",") {
		k, v, _ := strings.Cut(part, "=")
		n, ok := new(big.Int).SetString(v, 16)
		switch k {
		case "x":
			x = n
		case "y":
			y = n
		case "id":
			if v != "secp384r1" {
				return nil, fmt.Errorf("curve %q, want secp384r1", v)
			}
			continue
		default:
			return nil, fmt.Errorf("unknown ECC field %q", k)
		}
		if !ok {
			return nil, fmt.Errorf("ECC %s is not hex", k)
		}
	}
	if x == nil || y == nil {
		return nil, errors.New("ECC point needs x and y")
	}
	if x.Sign() < 0 || y.Sign() < 0 || x.BitLen() > 384 || y.BitLen() > 384 {
		return nil, errors.New("ECC point is out of range")
	}
	point := append([]byte{4}, x.FillBytes(make([]byte, 48))...)
	return parsePoint(append(point, y.FillBytes(make([]byte, 48))...))
}

// parsePoint decodes an uncompressed P-384 point and rejects one off the curve.
func parsePoint(b []byte) (*ecdsa.PublicKey, error) {
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), b)
	if err != nil {
		return nil, fmt.Errorf("ECC point: %w", err)
	}
	return k, CheckKey(k)
}

// PublicKey converts an RSA or ECC public area to a Go public key.
func PublicKey(pub *tpm2.TPMTPublic) (crypto.PublicKey, error) {
	switch pub.Type {
	case tpm2.TPMAlgRSA:
		parms, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, err
		}
		n, err := pub.Unique.RSA()
		if err != nil {
			return nil, err
		}
		return tpm2.RSAPub(parms, n)
	case tpm2.TPMAlgECC:
		parms, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, err
		}
		point, err := pub.Unique.ECC()
		if err != nil {
			return nil, err
		}
		return tpm2.ECDSAPub(parms, point)
	}
	return nil, fmt.Errorf("key type %v", pub.Type)
}

// KeyHash is the hex SHA-256 of a key's SubjectPublicKeyInfo, which names keys in logs, selectors and EK records.
func KeyHash(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// Build creates the certificate of key for the claims, signed by signer under issuer.
func Build(c Claims, key *ecdsa.PublicKey, now time.Time, issuer *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := CheckKey(key); err != nil {
		return nil, err
	}
	san, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(c.URI())}})
	if err != nil {
		return nil, err
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: c.InstanceID},
		NotBefore:             now.UTC().Truncate(time.Second),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: oidSAN, Critical: true, Value: san}},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, issuer, key, signer)
}

// NotAfter is the "no well-defined expiration" value of the certificates.
func NotAfter() time.Time { return notAfter }

// NewSerial is a random 128-bit certificate serial number.
func NewSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// Verified is what a valid certificate says.
type Verified struct {
	Cert   *x509.Certificate
	Claims Claims
	Key    *ecdsa.PublicKey
}

// Parse reads a certificate's claims and key without checking who signed it.
func Parse(der []byte) (*Verified, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}
	return profile(cert)
}

func profile(cert *x509.Certificate) (*Verified, error) {
	var claims *url.URL
	for _, u := range cert.URIs {
		if u.Scheme != Scheme {
			continue
		}
		if claims != nil {
			return nil, fmt.Errorf("%w: more than one %s URI", ErrProfile, Scheme)
		}
		claims = u
	}
	if claims == nil {
		return nil, fmt.Errorf("%w: no %s URI", ErrProfile, Scheme)
	}
	c, err := ParseClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: key is %T, want ECC NIST P-384", ErrProfile, cert.PublicKey)
	}
	if err := CheckKey(key); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}
	if cert.IsCA {
		return nil, fmt.Errorf("%w: certificate is a CA", ErrProfile)
	}
	return &Verified{Cert: cert, Claims: c, Key: key}, nil
}

// ReadCertificates reads every certificate in a PEM file.
func ReadCertificates(file string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s: no certificates", file)
	}
	return certs, nil
}

// Bundle is the provider's roots and issuing intermediates, which a verifier trusts.
type Bundle struct {
	roots, intermediates *x509.CertPool
}

// LoadBundle reads a PEM bundle of roots and issuing intermediates.
func LoadBundle(file string) (*Bundle, error) {
	certs, err := ReadCertificates(file)
	if err != nil {
		return nil, err
	}
	return NewBundle(certs), nil
}

// NewBundle builds a bundle with the self-signed certificates as roots and the others as intermediates.
func NewBundle(certs []*x509.Certificate) *Bundle {
	b := &Bundle{roots: x509.NewCertPool(), intermediates: x509.NewCertPool()}
	for _, c := range certs {
		if bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
			b.roots.AddCert(c)
		} else {
			b.intermediates.AddCert(c)
		}
	}
	return b
}

// Verify checks that a certificate chains to the bundle and has this profile.
func (b *Bundle) Verify(der []byte) (*Verified, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrChainInvalid, err)
	}
	// The certificate has no extended key usage; a chain for any usage will do.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: b.roots, Intermediates: b.intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrChainInvalid, err)
	}
	return profile(cert)
}
