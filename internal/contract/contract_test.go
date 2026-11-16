package contract

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/cvdtang/openstack-tpm/internal/pkitest"
)

const (
	instance = "11111111-1111-4111-8111-111111111111"
	project  = "0123456789abcdef0123456789abcdef"
	user     = "fedcba9876543210fedcba9876543210"
	group    = "22222222-2222-4222-8222-222222222222"
)

func testClaims(kind string) Claims {
	return Claims{
		Region: "RegionOne", DomainID: "default", ProjectID: project, InstanceID: instance,
		Kind: kind, UserID: user,
	}
}

func p384(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func bundle(t testing.TB, cas ...*pkitest.CA) *Bundle {
	t.Helper()
	var certs []*x509.Certificate
	for _, c := range cas {
		certs = append(certs, c.Cert)
	}
	return NewBundle(certs)
}

// Ensures the claims URI has its fixed form for both kinds, with ancestors root first.
func TestClaimsURI(t *testing.T) {
	c := testClaims(KindVM)
	want := "openstack:/v1/region/RegionOne/domain/default/project/" + project + "/instance/" + instance +
		"?kind=vm&user=" + user
	if got := c.URI(); got != want {
		t.Errorf("URI\n got %s\nwant %s", got, want)
	}
	c.Kind = KindBaremetal
	want = strings.Replace(want, "kind=vm", "kind=baremetal", 1)
	if got := c.URI(); got != want {
		t.Errorf("bare-metal URI\n got %s\nwant %s", got, want)
	}
	// The ancestors precede the project, root first.
	c.Ancestors = []string{"root", "mid"}
	want = strings.Replace(want, "/project/", "/project/root/mid/", 1)
	if got := c.URI(); got != want {
		t.Errorf("URI with ancestors\n got %s\nwant %s", got, want)
	}
}

// Ensures a project's parent is its nearest ancestor, or the domain.
func TestClaimsParentID(t *testing.T) {
	c := testClaims(KindVM)
	if got := c.ParentID(); got != "default" {
		t.Errorf("top-level project: parent %q, want the domain", got)
	}
	c.Ancestors = []string{"root", "mid"}
	if got := c.ParentID(); got != "mid" {
		t.Errorf("sub-project: parent %q, want mid", got)
	}
}

// Ensures valid claims survive a round trip through their URI.
func TestClaimsRoundTrip(t *testing.T) {
	for _, kind := range []string{KindVM, KindBaremetal} {
		for _, anc := range [][]string{nil, {"root"}, {"root", "mid", "instance"}} {
			c := testClaims(kind)
			c.Ancestors = anc
			if err := c.Validate(); err != nil {
				t.Fatalf("%+v: %v", c, err)
			}
			u, err := url.Parse(c.URI())
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseClaims(u)
			if err != nil || !got.Equal(c) {
				t.Errorf("round trip of %s: got %+v, %v", c.URI(), got, err)
			}
			// A URL that went through String keeps its one spelling.
			if u.String() != c.URI() {
				t.Errorf("url.URL spells %q, want %q", u.String(), c.URI())
			}
		}
	}
}

// Ensures ParseClaims ignores unknown query parameters and their order.
func TestParseClaimsTolerates(t *testing.T) {
	c := testClaims(KindVM)
	path := "openstack:/v1/region/RegionOne/domain/default/project/" + project + "/instance/" + instance
	for name, s := range map[string]string{
		"unknown parameter": c.URI() + "&rack=r1",
		"unknown first":     path + "?rack=r1&kind=vm&user=" + user,
		"another order":     path + "?user=" + user + "&kind=vm",
		"repeated unknown":  c.URI() + "&x=1&x=2",
	} {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ParseClaims(u); err != nil || !got.Equal(c) {
			t.Errorf("%s: got %+v, %v", name, got, err)
		}
	}
}

// Ensures ParseClaims accepts only the canonical URI form.
func TestParseClaimsRefuses(t *testing.T) {
	path := "/v1/region/RegionOne/domain/default/project/" + project + "/instance/" + instance
	query := "?kind=vm&user=" + user
	long := strings.Repeat("a", 129)
	for name, s := range map[string]string{
		"authority":           "openstack://keystone.example" + path + query,
		"authority is v1":     "openstack:/" + path + query,
		"empty authority":     "openstack://" + path + query,
		"userinfo":            "openstack://u@" + path + query,
		"scheme":              "https:" + path + query,
		"spiffe scheme":       "spiffe:" + path + query,
		"opaque":              "openstack:" + strings.TrimPrefix(path, "/") + query,
		"fragment":            "openstack:" + path + query + "#frag",
		"version":             "openstack:" + strings.Replace(path, "/v1/", "/v2/", 1) + query,
		"no version":          "openstack:" + strings.TrimPrefix(path, "/v1") + query,
		"short path":          "openstack:/v1/region/RegionOne/domain/default/project/" + project + query,
		"long path":           "openstack:" + path + "/extra" + query,
		"trailing slash":      "openstack:" + path + "/" + query,
		"plural keys":         "openstack:" + strings.Replace(path, "/region/", "/regions/", 1) + query,
		"swapped keys":        "openstack:/v1/domain/default/region/RegionOne/project/" + project + "/instance/" + instance + query,
		"empty region":        "openstack:" + strings.Replace(path, "RegionOne", "", 1) + query,
		"escaped slash":       "openstack:" + strings.Replace(path, "RegionOne", "Region%2FOne", 1) + query,
		"space in region":     "openstack:" + strings.Replace(path, "RegionOne", "Region%20One", 1) + query,
		"long domain":         "openstack:" + strings.Replace(path, "default", long, 1) + query,
		"instance not a UUID": "openstack:" + strings.Replace(path, instance, "i-1", 1) + query,
		"uppercase UUID":      "openstack:" + strings.Replace(path, instance, strings.ToUpper("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), 1) + query,
		"no query":            "openstack:" + path,
		"no kind":             "openstack:" + path + "?user=" + user,
		"unknown kind":        "openstack:" + path + "?kind=container&user=" + user,
		"no user":             "openstack:" + path + "?kind=vm",
		"empty user":          "openstack:" + path + "?kind=vm&user=",
		"repeated kind":       "openstack:" + path + query + "&kind=baremetal",
		"empty ancestor":      "openstack:" + strings.Replace(path, "/project/", "/project//", 1) + query,
		"ancestor is project": "openstack:" + strings.Replace(path, "/project/", "/project/"+project+"/", 1) + query,
		"ancestor is domain":  "openstack:" + strings.Replace(path, "/project/", "/project/default/", 1) + query,
		"repeated ancestor":   "openstack:" + strings.Replace(path, "/project/", "/project/a/a/", 1) + query,
		"escaped ancestor":    "openstack:" + strings.Replace(path, "/project/", "/project/a%20b/", 1) + query,
		"no project":          "openstack:/v1/region/RegionOne/domain/default/project/instance/" + instance + query,
		"repeated user":       "openstack:" + path + query + "&user=" + user,
		"escaped user":        "openstack:" + path + "?kind=vm&user=a%20b",
	} {
		u, err := url.Parse(s)
		if err != nil {
			t.Errorf("%s: %q does not parse: %v", name, s, err)
			continue
		}
		if c, err := ParseClaims(u); err == nil {
			t.Errorf("%s: %q accepted as %+v", name, s, c)
		}
	}

	// The version is named, so an operator sees what to upgrade.
	u, _ := url.Parse("openstack:" + strings.Replace(path, "/v1/", "/v2/", 1) + query)
	if _, err := ParseClaims(u); err == nil || !strings.Contains(err.Error(), `"v2" is not supported`) {
		t.Errorf("version error: %v", err)
	}
}

// Ensures Validate accepts only complete claims with one URI spelling, and ValidUUID only canonical UUIDs.
func TestClaimsValidate(t *testing.T) {
	for name, mod := range map[string]func(*Claims){
		"empty region":        func(c *Claims) { c.Region = "" },
		"region with slash":   func(c *Claims) { c.Region = "a/b" },
		"region with query":   func(c *Claims) { c.Region = "a?b" },
		"region with &":       func(c *Claims) { c.Region = "a&kind=vm" },
		"empty domain":        func(c *Claims) { c.DomainID = "" },
		"empty project":       func(c *Claims) { c.ProjectID = "" },
		"project with space":  func(c *Claims) { c.ProjectID = "a b" },
		"empty ancestor":      func(c *Claims) { c.Ancestors = []string{""} },
		"ancestor with slash": func(c *Claims) { c.Ancestors = []string{"a/b"} },
		"ancestor is domain":  func(c *Claims) { c.Ancestors = []string{"default"} },
		"ancestor is project": func(c *Claims) { c.Ancestors = []string{project} },
		"repeated ancestor":   func(c *Claims) { c.Ancestors = []string{"a", "b", "a"} },
		"project is domain":   func(c *Claims) { c.ProjectID = "default" },
		"empty user":          func(c *Claims) { c.UserID = "" },
		"non-ASCII user":      func(c *Claims) { c.UserID = "üser" },
		"long user":           func(c *Claims) { c.UserID = strings.Repeat("u", 129) },
		"instance":            func(c *Claims) { c.InstanceID = "not-a-uuid" },
		"instance uppercase":  func(c *Claims) { c.InstanceID = "AAAAAAAA-1111-4111-8111-111111111111" },
		"no kind":             func(c *Claims) { c.Kind = "" },
		"kind":                func(c *Claims) { c.Kind = "VM" },
	} {
		c := testClaims(KindVM)
		mod(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: %+v accepted", name, c)
		}
	}
	c := testClaims(KindBaremetal)
	c.Region, c.UserID = "eu-west_1.a", strings.Repeat("u", 128)
	if err := c.Validate(); err != nil {
		t.Errorf("%+v: %v", c, err)
	}
	if !ValidUUID(instance) || ValidUUID(instance+"0") || ValidUUID("") || ValidUUID(strings.ReplaceAll(instance, "-", "")) {
		t.Error("ValidUUID")
	}
}

// Ensures a built certificate has the profile and verifies only against its own issuing CA.
func TestBuildVerify(t *testing.T) {
	root := pkitest.NewCA(t, "root", nil)
	issuing := pkitest.NewIssuing(t, "issuing", root)
	trusted := bundle(t, root, issuing)
	other := pkitest.NewCA(t, "another root", nil)
	now := time.Now().Add(-time.Minute)

	for _, kind := range []string{KindVM, KindBaremetal} {
		t.Run(kind, func(t *testing.T) {
			c := testClaims(kind)
			key := p384(t)
			der, err := Build(c, &key.PublicKey, now, issuing.Cert, issuing.Key)
			if err != nil {
				t.Fatal(err)
			}
			v, err := trusted.Verify(der)
			if err != nil {
				t.Fatal(err)
			}
			if !v.Claims.Equal(c) || !v.Key.Equal(&key.PublicKey) || !bytes.Equal(v.Cert.Raw, der) {
				t.Errorf("verified %+v", v.Claims)
			}

			// The certificate profile.
			cert := v.Cert
			if len(cert.URIs) != 1 || cert.URIs[0].String() != c.URI() {
				t.Errorf("URIs %v, want %s", cert.URIs, c.URI())
			}
			if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses) != 0 {
				t.Error("SAN has other names")
			}
			var critical bool
			for _, e := range cert.Extensions {
				critical = critical || e.Id.Equal(oidSAN) && e.Critical
			}
			if !critical {
				t.Error("SubjectAltName is not critical")
			}
			if cert.Subject.CommonName != instance || cert.IsCA || cert.KeyUsage != x509.KeyUsageKeyAgreement ||
				len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage) != 0 {
				t.Errorf("subject %q CA %v key usage %v", cert.Subject, cert.IsCA, cert.KeyUsage)
			}
			if !cert.NotAfter.Equal(NotAfter()) || cert.NotAfter.Year() != 9999 || !cert.NotBefore.Equal(now.UTC().Truncate(time.Second)) {
				t.Errorf("validity %s to %s", cert.NotBefore, cert.NotAfter)
			}
			if cert.SerialNumber.Sign() <= 0 || cert.Issuer.CommonName != "issuing" {
				t.Errorf("serial %v issuer %q", cert.SerialNumber, cert.Issuer)
			}

			// Parse is Verify without the chain.
			p, err := Parse(der)
			if err != nil || !p.Claims.Equal(c) || !p.Key.Equal(&key.PublicKey) {
				t.Errorf("Parse: %+v %v", p, err)
			}

			// Signed by a CA that does not chain to the bundle.
			signed := func(ca *pkitest.CA) []byte {
				t.Helper()
				der, err := Build(c, &key.PublicKey, now, ca.Cert, ca.Key)
				if err != nil {
					t.Fatal(err)
				}
				return der
			}
			for name, tc := range map[string]struct {
				b    *Bundle
				der  []byte
				want string
			}{
				"another root":           {bundle(t, other, pkitest.NewIssuing(t, "issuing", other)), der, "unknown authority"},
				"under the intermediate": {trusted, signed(pkitest.NewCA(t, "sub", issuing)), "unknown authority"},
				"intermediate removed":   {bundle(t, root), der, "unknown authority"},
			} {
				_, err := tc.b.Verify(tc.der)
				if !errors.Is(err, ErrChainInvalid) || errors.Is(err, ErrProfile) || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("%s: %v, want ErrChainInvalid with %q", name, err, tc.want)
				}
			}
			// One flipped bit in the signature.
			bad := bytes.Clone(der)
			bad[len(bad)-1] ^= 1
			if _, err := trusted.Verify(bad); !errors.Is(err, ErrChainInvalid) {
				t.Errorf("tampered certificate: %v", err)
			}
		})
	}

	if _, err := trusted.Verify([]byte("junk")); !errors.Is(err, ErrChainInvalid) {
		t.Errorf("junk: %v, want ErrChainInvalid", err)
	}
	if _, err := Parse([]byte("junk")); !errors.Is(err, ErrProfile) {
		t.Errorf("junk: %v, want ErrProfile", err)
	}
}

// Ensures Build refuses invalid claims and keys.
func TestBuildRefuses(t *testing.T) {
	issuing := pkitest.NewCA(t, "issuing", nil)
	key := p384(t)
	bad := testClaims(KindVM)
	bad.Region = "a/b"
	if _, err := Build(bad, &key.PublicKey, time.Now(), issuing.Cert, issuing.Key); err == nil {
		t.Error("invalid claims signed")
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := Build(testClaims(KindVM), &p256.PublicKey, time.Now(), issuing.Cert, issuing.Key); err == nil {
		t.Error("P-256 key certified")
	}
	if _, err := Build(testClaims(KindVM), nil, time.Now(), issuing.Cert, issuing.Key); err == nil {
		t.Error("nil key certified")
	}
}

// Ensures a chained certificate that breaks the profile fails as a profile error.
func TestProfile(t *testing.T) {
	root := pkitest.NewCA(t, "root", nil)
	issuing := pkitest.NewIssuing(t, "issuing", root)
	trusted := bundle(t, root, issuing)
	key := p384(t)
	uri := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	claims := uri(testClaims(KindVM).URI())
	sign := func(tmpl *x509.Certificate, pub any) []byte {
		t.Helper()
		tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, issuing.Cert, pub, issuing.Key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other := testClaims(KindBaremetal)

	for name, der := range map[string][]byte{
		"no SAN":          sign(&x509.Certificate{Subject: pkix.Name{CommonName: instance}}, &key.PublicKey),
		"no claims URI":   sign(&x509.Certificate{URIs: []*url.URL{uri("spiffe://example.org/x")}, DNSNames: []string{"host"}}, &key.PublicKey),
		"two claims URIs": sign(&x509.Certificate{URIs: []*url.URL{claims, uri(other.URI())}}, &key.PublicKey),
		"same URI twice":  sign(&x509.Certificate{URIs: []*url.URL{claims, claims}}, &key.PublicKey),
		"unknown kind":    sign(&x509.Certificate{URIs: []*url.URL{uri(strings.Replace(claims.String(), "kind=vm", "kind=lxc", 1))}}, &key.PublicKey),
		"with authority":  sign(&x509.Certificate{URIs: []*url.URL{uri(strings.Replace(claims.String(), "openstack:/v1", "openstack://cloud/v1", 1))}}, &key.PublicKey),
		"later version":   sign(&x509.Certificate{URIs: []*url.URL{uri(strings.Replace(claims.String(), "/v1/", "/v2/", 1))}}, &key.PublicKey),
		"P-256 key":       sign(&x509.Certificate{URIs: []*url.URL{claims}}, &p256.PublicKey),
		"RSA key":         sign(&x509.Certificate{URIs: []*url.URL{claims}}, &rsaKey.PublicKey),
		"CA":              sign(&x509.Certificate{URIs: []*url.URL{claims}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, &key.PublicKey),
	} {
		_, err := trusted.Verify(der)
		if !errors.Is(err, ErrProfile) || errors.Is(err, ErrChainInvalid) {
			t.Errorf("%s: Verify: %v, want ErrProfile", name, err)
		}
		if _, err := Parse(der); !errors.Is(err, ErrProfile) {
			t.Errorf("%s: Parse: %v, want ErrProfile", name, err)
		}
	}

	// URIs of other schemes are not claims and do not count.
	der := sign(&x509.Certificate{URIs: []*url.URL{uri("spiffe://example.org/x"), claims}}, &key.PublicKey)
	if v, err := trusted.Verify(der); err != nil || !v.Claims.Equal(testClaims(KindVM)) {
		t.Errorf("claims next to another URI: %v", err)
	}
}

// pointWithLeadingZero is a P-384 key whose X starts with a zero byte, since swtpm prints coordinates without padding.
func pointWithLeadingZero(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	scalar := make([]byte, 48)
	for i := 1; i < 1<<16; i++ {
		scalar[46], scalar[47] = byte(i>>8), byte(i)
		k, err := ecdh.P384().NewPrivateKey(scalar)
		if err != nil {
			t.Fatal(err)
		}
		if b := k.PublicKey().Bytes(); b[1] == 0 {
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), b)
			if err != nil {
				t.Fatal(err)
			}
			return pub
		}
	}
	t.Fatal("no point with a leading zero byte")
	return nil
}

// coords are the hex coordinates of a key, fixed width.
func coords(t testing.TB, pub *ecdsa.PublicKey) (x, y string) {
	t.Helper()
	b, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[1:49]), hex.EncodeToString(b[49:])
}

// Ensures ParsePoint reads swtpm's ECC point format and refuses anything but a valid P-384 point.
func TestParsePoint(t *testing.T) {
	for _, pub := range []*ecdsa.PublicKey{&p384(t).PublicKey, pointWithLeadingZero(t)} {
		x, y := coords(t, pub)
		short := strings.TrimLeft(x, "0")
		for _, s := range []string{
			"x=" + x + ",y=" + y,
			"x=" + x + ",y=" + y + ",id=secp384r1",
			"id=secp384r1,y=" + y + ",x=" + x,
			"x=" + short + ",y=" + y + ",id=secp384r1",
			"x=" + strings.ToUpper(x) + ",y=" + strings.ToUpper(y),
			"x=00" + x + ",y=" + y,
		} {
			got, err := ParsePoint(s)
			if err != nil || !got.Equal(pub) {
				t.Errorf("%q: %v", s, err)
			}
		}
	}

	x, y := coords(t, &p384(t).PublicKey)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := p256.PublicKey.Bytes()
	for name, s := range map[string]string{
		"empty":         "",
		"RSA modulus":   "c0ffee",
		"no y":          "x=" + x,
		"no x":          "y=" + y,
		"not hex":       "x=zz,y=" + y,
		"empty x":       "x=,y=" + y,
		"off the curve": "x=01,y=02",
		"swapped":       "x=" + y + ",y=" + x,
		"too long":      "x=01" + x + ",y=" + y,
		"negative":      "x=-" + x + ",y=" + y,
		"another curve": "x=" + x + ",y=" + y + ",id=prime256v1",
		"P-256 point":   "x=" + hex.EncodeToString(b[1:33]) + ",y=" + hex.EncodeToString(b[33:]),
		"unknown field": "x=" + x + ",y=" + y + ",z=01",
		"infinity":      "x=0,y=0",
	} {
		if k, err := ParsePoint(s); err == nil {
			t.Errorf("%s: %q accepted as %v", name, s, k)
		}
	}
}

// Ensures each kind has its own hierarchy, NV index, handle and key template.
func TestKey(t *testing.T) {
	for kind, want := range map[string]Key{
		KindVM:        {tpm2.TPMRHEndorsement, 0x01c00016, 0x81010016},
		KindBaremetal: {tpm2.TPMRHOwner, 0x01800016, 0x81008016},
	} {
		if got, err := KeyOf(kind); err != nil || got != want {
			t.Errorf("KeyOf(%s) = %+v, %v", kind, got, err)
		}
	}
	if _, err := KeyOf("container"); err == nil {
		t.Error("KeyOf accepted an unknown kind")
	}
	if _, err := Template("container", nil, nil); err == nil {
		t.Error("Template accepted an unknown kind")
	}

	vm, err := Template(KindVM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	bm, err := Template(KindBaremetal, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Both are ECC NIST P-384 restricted decryption keys with a SHA-384 name and AES-256-CFB that the TPM generated and cannot move.
	for kind, tmpl := range map[string]tpm2.TPMTPublic{KindVM: vm, KindBaremetal: bm} {
		a := tmpl.ObjectAttributes
		decrypting := a.FixedTPM && a.FixedParent && a.SensitiveDataOrigin && a.UserWithAuth && a.Restricted && a.Decrypt
		if tmpl.Type != tpm2.TPMAlgECC || tmpl.NameAlg != tpm2.TPMAlgSHA384 || !decrypting || a.SignEncrypt {
			t.Errorf("%s: type %v name %v attributes %+v", kind, tmpl.Type, tmpl.NameAlg, a)
		}
		ecc, err := tmpl.Parameters.ECCDetail()
		if err != nil {
			t.Fatal(err)
		}
		bits, _ := ecc.Symmetric.KeyBits.AES()
		mode, _ := ecc.Symmetric.Mode.AES()
		if ecc.CurveID != tpm2.TPMECCNistP384 || ecc.Symmetric.Algorithm != tpm2.TPMAlgAES || *bits != 256 || *mode != tpm2.TPMAlgCFB {
			t.Errorf("%s: parameters %+v", kind, ecc)
		}
		u, err := tmpl.Unique.ECC()
		if err != nil || len(u.X.Buffer)+len(u.Y.Buffer) != 0 {
			t.Errorf("%s: the template's unique field is not empty", kind)
		}
	}
	// vm is the EK template H-3 with PolicyB and adminWithPolicy; baremetal has no policy and noDA instead.
	if a := vm.ObjectAttributes; !a.AdminWithPolicy || a.NoDA || len(vm.AuthPolicy.Buffer) != sha384Size {
		t.Errorf("vm: attributes %+v, policy of %d bytes", a, len(vm.AuthPolicy.Buffer))
	}
	if a := bm.ObjectAttributes; a.AdminWithPolicy || !a.NoDA || len(bm.AuthPolicy.Buffer) != 0 {
		t.Errorf("baremetal: attributes %+v, policy of %d bytes", a, len(bm.AuthPolicy.Buffer))
	}

	// KeyPublic fills the template with fixed-width coordinates, and the two kinds of one point have different names.
	names := map[string]bool{}
	for _, pub := range []*ecdsa.PublicKey{&p384(t).PublicKey, pointWithLeadingZero(t)} {
		for _, kind := range []string{KindVM, KindBaremetal} {
			area, err := KeyPublic(kind, pub)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := area.Unique.ECC()
			x, y := coords(t, pub)
			if hex.EncodeToString(u.X.Buffer) != x || hex.EncodeToString(u.Y.Buffer) != y {
				t.Errorf("%s: unique %x %x", kind, u.X.Buffer, u.Y.Buffer)
			}
			name, err := tpm2.ObjectName(&area)
			if err != nil {
				t.Fatal(err)
			}
			if names[string(name.Buffer)] {
				t.Errorf("%s: name is not unique", kind)
			}
			names[string(name.Buffer)] = true
		}
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := KeyPublic(KindVM, &p256.PublicKey); err == nil {
		t.Error("KeyPublic accepted a P-256 key")
	}
}

const sha384Size = 48

// Ensures CheckKey accepts only P-384 points on the curve.
func TestCheckKey(t *testing.T) {
	if err := CheckKey(&p384(t).PublicKey); err != nil {
		t.Error(err)
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	off := &ecdsa.PublicKey{Curve: elliptic.P384(), X: big.NewInt(1), Y: big.NewInt(2)} //nolint:staticcheck // only the raw coordinates make a point off the curve
	for name, k := range map[string]*ecdsa.PublicKey{"nil": nil, "P-256": &p256.PublicKey, "off the curve": off} {
		if err := CheckKey(k); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Ensures KeyHash is the SHA-256 of the key's SubjectPublicKeyInfo.
func TestKeyHash(t *testing.T) {
	issuing := pkitest.NewCA(t, "issuing", nil)
	key := p384(t)
	got, err := KeyHash(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := Build(testClaims(KindVM), &key.PublicKey, time.Now(), issuing.Cert, issuing.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	// The hash of the certificate's SubjectPublicKeyInfo, as openssl prints it.
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if got != hex.EncodeToString(sum[:]) || len(got) != 64 {
		t.Errorf("KeyHash %s, SPKI hash %x", got, sum)
	}
	if other, _ := KeyHash(&p384(t).PublicKey); other == got {
		t.Error("two keys with one hash")
	}
	if _, err := KeyHash("not a key"); err == nil {
		t.Error("KeyHash of a string")
	}
}

// Ensures a PEM bundle loads its roots and intermediates and unusable files are refused.
func TestBundle(t *testing.T) {
	root := pkitest.NewCA(t, "root", nil)
	issuing := pkitest.NewIssuing(t, "issuing", root)
	second := pkitest.NewCA(t, "second root", nil)
	dir := t.TempDir()
	write := func(name string, blocks ...[]byte) string {
		t.Helper()
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, bytes.Join(blocks, nil), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("ignored")})

	certs, err := ReadCertificates(write("three", root.PEM(), keyPEM, issuing.PEM(), []byte("trailing text\n"), second.PEM()))
	if err != nil || len(certs) != 3 || certs[1].Subject.CommonName != "issuing" {
		t.Fatalf("ReadCertificates: %d certificates, %v", len(certs), err)
	}
	for name, file := range map[string]string{
		"missing":         filepath.Join(dir, "missing"),
		"empty":           write("empty"),
		"no certificate":  write("key", keyPEM),
		"bad certificate": write("bad", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})),
	} {
		if _, err := ReadCertificates(file); err == nil {
			t.Errorf("ReadCertificates: %s accepted", name)
		}
		if _, err := LoadBundle(file); err == nil {
			t.Errorf("LoadBundle: %s accepted", name)
		}
	}

	// Roots and intermediates in any order.
	b, err := LoadBundle(write("bundle", issuing.PEM(), second.PEM(), root.PEM()))
	if err != nil {
		t.Fatal(err)
	}
	key := p384(t)
	der, err := Build(testClaims(KindVM), &key.PublicKey, time.Now(), issuing.Cert, issuing.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(der); err != nil {
		t.Errorf("verify against the loaded bundle: %v", err)
	}
}
