package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "conf")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// Ensures swtpm_setup's arguments parse and unknown or malformed ones are refused.
func TestParseArgs(t *testing.T) {
	a, err := parseArgs([]string{"--type", "ek", "--ek", "x=01,y=02,id=secp384r1", "--dir", "/d", "--allow-signing", "--decryption",
		"--logfile", "/l", "--vmid", "instance-1:uuid", "--tpm2", "--tpm-spec-family", "2.0", "--tpm-spec-level", "0",
		"--tpm-spec-revision", "164", "--tpm-manufacturer", "id:00001014", "--tpm-model", "swtpm", "--tpm-version", "id:20191023",
		"--configfile", "/c", "--optsfile", "/o"})
	want := args{typ: "ek", ek: "x=01,y=02,id=secp384r1", dir: "/d", vmid: "instance-1:uuid", configfile: "/c", logfile: "/l"}
	if err != nil || *a != want {
		t.Fatalf("got %+v %v", a, err)
	}
	if a, err := parseArgs([]string{"--type", "platform"}); err != nil || a.configfile != defaultConfig {
		t.Errorf("default config: %+v %v", a, err)
	}
	for _, bad := range [][]string{{"ek"}, {"--type"}, {"--tpm2", "--dir"}, {"--unknown", "x"}, {"--type", "ek", "extra"}} {
		if a, err := parseArgs(bad); err == nil {
			t.Errorf("%v accepted as %+v", bad, a)
		}
	}
}

// Ensures the hook's config needs every key and an HTTPS URL.
func TestReadConfig(t *testing.T) {
	const base = `
		url = "https://issuer:8443/v1/vm/certificates"
		cert = "/c"
		key = "/k"
		ca = "/ca"
	`
	c, err := readConfig(writeFile(t, base))
	if err != nil || c.url != "https://issuer:8443/v1/vm/certificates" || c.cert != "/c" || c.key != "/k" || c.ca != "/ca" {
		t.Fatalf("got %+v %v", c, err)
	}
	for name, conf := range map[string]string{
		"missing key": strings.Replace(base, `ca = "/ca"`, "", 1),
		"plain http":  strings.Replace(base, "https://", "http://", 1),
		"unknown key": base + `token = "x"`,
		"bad line":    base + "no equals sign",
	} {
		if c, err := readConfig(writeFile(t, conf)); err == nil {
			t.Errorf("%s accepted as %+v", name, c)
		}
	}
	if _, err := readConfig(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file was accepted")
	}
}

// Ensures the issuance request carries the instance UUID from libvirt and a valid ECC EK, or is refused.
func TestRequest(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	const id = "9506c951-5bb1-466d-aae1-bcac379f20c3"
	ek := fmt.Sprintf("x=%x,y=%x,id=secp384r1", pub[1:49], pub[49:])
	if !isECC(ek) || isECC("a1b2c3") {
		t.Fatal("isECC")
	}
	// libvirt passes --vmid <name>:<uuid>.
	req, err := request(&args{vmid: "instance-0000002a:" + id, dir: "/tmp", ek: ek})
	if err != nil || req.InstanceUUID != id || req.Key != ek {
		t.Fatalf("got %+v %v", req, err)
	}
	for name, a := range map[string]args{
		"no vmid":      {dir: "/tmp", ek: ek},
		"no uuid":      {vmid: "instance-0000002a", dir: "/tmp", ek: ek},
		"upper case":   {vmid: "x:" + strings.ToUpper(id), dir: "/tmp", ek: ek},
		"not a point":  {vmid: "x:" + id, dir: "/tmp", ek: "x=00,y=00"},
		"an RSA value": {vmid: "x:" + id, dir: "/tmp", ek: "a1b2c3"},
	} {
		if req, err := request(&a); err == nil {
			t.Errorf("%s accepted as %+v", name, req)
		}
	}
}

// Ensures the locally made EK certificates parse and name the untrusted issuer.
func TestLocalCert(t *testing.T) {
	ecc, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ecc.PublicKey.Bytes()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, ek := range map[string]string{
		"ECC": fmt.Sprintf("x=%x,y=%x,id=secp384r1", pub[1:49], pub[49:]),
		"RSA": rsaKey.N.Text(16),
	} {
		der, err := localCert(&args{vmid: "instance-1:uuid", ek: ek})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil || c.Issuer.CommonName != UntrustedIssuer {
			t.Errorf("%s: issuer %q, %v", name, c.Issuer, err)
		}
	}
	if _, err := localCert(&args{vmid: "instance-1:uuid", ek: "c0ffee"}); err == nil {
		t.Error("a short RSA modulus was accepted")
	}
}
