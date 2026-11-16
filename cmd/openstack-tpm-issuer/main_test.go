package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/baotest"
	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/pkitest"
	"github.com/cvdtang/openstack-tpm/internal/transit"
)

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	f := filepath.Join(dir, name)
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// files are the issuer's configuration files of a test.
type files struct{ issuingCert, clientCA, tlsCert, tlsKey string }

// setEnv sets a complete, valid issuer environment against a new OpenBao with the lab's keys, with an issuing certificate made by `ca`.
func setEnv(t *testing.T) files {
	t.Helper()
	b := baotest.Start(t)
	b.Key(t, "issuing", "ecdsa-p384", false)
	b.Key(t, "clear", "ecdsa-p256", false)
	t.Setenv("BAO_ADDR", b.Addr)
	t.Setenv("BAO_TOKEN", baotest.RootToken)
	t.Setenv("ISSUER_TRANSIT_MOUNT", "transit")
	t.Setenv("ISSUER_ISSUING_KEY", "issuing")
	t.Setenv("ISSUER_CLEAR_KEY", "clear")
	var ca bytes.Buffer
	if err := run(t.Context(), []string{"ca"}, &ca); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	hosts := pkitest.NewCA(t, "hosts", nil)
	server := pkitest.NewCA(t, "server", hosts)
	der, err := x509.MarshalECPrivateKey(server.Key)
	if err != nil {
		t.Fatal(err)
	}
	f := files{
		issuingCert: writeFile(t, dir, "issuing.crt", ca.Bytes()),
		clientCA:    writeFile(t, dir, "hosts.pem", hosts.PEM()),
		tlsCert:     writeFile(t, dir, "server.crt", server.PEM()),
		tlsKey:      writeFile(t, dir, "server.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
	}
	for k, v := range map[string]string{
		"ISSUER_ISSUING_CERT": f.issuingCert, "ISSUER_REGION": "RegionOne", "ISSUER_CLIENT_CA": f.clientCA,
		"ISSUER_TLS_CERT": f.tlsCert, "ISSUER_TLS_KEY": f.tlsKey,
		"OS_AUTH_URL": "http://127.0.0.1:1/identity", "OS_USERNAME": "issuer", "OS_PASSWORD": "secret", "OS_PROJECT_NAME": "service",
	} {
		t.Setenv(k, v)
	}
	return f
}

// start runs the issuer's startup checks without listening.
func start(t *testing.T) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	_, err = setup(t.Context(), cfg)
	return err
}

// Ensures the issuer starts only with a configuration it can serve and names what is wrong otherwise.
func TestConfig(t *testing.T) {
	f := setEnv(t)
	if err := start(t); err != nil {
		t.Fatalf("valid configuration refused: %v", err)
	}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing setting", map[string]string{"ISSUER_REGION": ""}, "missing environment: ISSUER_REGION"},
		{"OpenBao unreachable", map[string]string{"BAO_ADDR": "http://127.0.0.1:1", "BAO_MAX_RETRIES": "0"}, "openbao: "},
		{"OpenBao token", map[string]string{"BAO_TOKEN": "invalid"}, "openbao 403"},
		{"unknown issuing key", map[string]string{"ISSUER_ISSUING_KEY": "missing"}, "ISSUER_ISSUING_KEY: openbao"},
		{"unknown clear key", map[string]string{"ISSUER_CLEAR_KEY": "missing"}, "ISSUER_CLEAR_KEY: openbao"},
		// The clear key signs what a TPM verifies with a P-256 key.
		{"clear key of another curve", map[string]string{"ISSUER_CLEAR_KEY": "issuing"}, "must be an ECDSA P-256 Transit key"},
		{"issuing certificate of another key", map[string]string{"ISSUER_ISSUING_CERT": f.tlsCert}, "is not a CA certificate for transit key"},
		{"client CA without certificates", map[string]string{"ISSUER_CLIENT_CA": f.tlsKey}, "ISSUER_CLIENT_CA: no certificates"},
		{"client CA missing", map[string]string{"ISSUER_CLIENT_CA": filepath.Join(t.TempDir(), "missing.pem")}, "ISSUER_CLIENT_CA: "},
		{"TLS key", map[string]string{"ISSUER_TLS_KEY": f.clientCA}, "ISSUER_TLS_CERT/KEY"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			err := start(t)
			if err == nil {
				t.Fatal("issuer started")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused with %v, want %q", err, c.want)
			}
		})
	}
}

// Ensures the command line refuses unknown commands and invalid ca arguments.
func TestCommands(t *testing.T) {
	var out bytes.Buffer
	if err := run(t.Context(), []string{"bogus"}, &out); err == nil || !strings.Contains(err.Error(), `unknown command "bogus"`) {
		t.Errorf("bogus: %v", err)
	}
	setEnv(t)
	if err := run(t.Context(), []string{"ca", "extra"}, &out); err == nil {
		t.Error("ca accepted an argument")
	}
	t.Setenv("BAO_TOKEN", "")
	if err := run(t.Context(), []string{"ca"}, &out); err == nil || err.Error() != "missing environment: BAO_TOKEN" {
		t.Errorf("ca without a token: %v", err)
	}
}

// Ensures ca prints a self-signed CA certificate of the Transit issuing key; e2e verifies the certificates under it.
func TestCA(t *testing.T) {
	setEnv(t)
	var out bytes.Buffer
	if err := run(t.Context(), []string{"ca", "-cn", "test issuing"}, &out); err != nil {
		t.Fatal(err)
	}
	f := writeFile(t, t.TempDir(), "bundle.pem", out.Bytes())
	certs, err := contract.ReadCertificates(f)
	if err != nil || len(certs) != 1 {
		t.Fatalf("ca printed %d certificates: %v", len(certs), err)
	}
	ca := certs[0]
	bao, err := transit.NewClient(os.Getenv("BAO_ADDR"), os.Getenv("BAO_TOKEN"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := transit.NewSigner(t.Context(), bao, "transit", "issuing")
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case !signer.Public().(*ecdsa.PublicKey).Equal(ca.PublicKey):
		t.Error("certificate is not for the issuing key")
	case ca.CheckSignatureFrom(ca) != nil:
		t.Error("certificate is not self-signed")
	case ca.Subject.CommonName != "test issuing" || len(ca.Subject.Organization) != 1 || ca.Subject.Organization[0] != "openstack-tpm":
		t.Errorf("subject %q", ca.Subject)
	case !ca.IsCA || !ca.BasicConstraintsValid || ca.MaxPathLen != 0 || !ca.MaxPathLenZero:
		t.Error("not a CA without a path length")
	case ca.KeyUsage != x509.KeyUsageCertSign:
		t.Errorf("key usage %v", ca.KeyUsage)
	case !ca.NotAfter.Equal(contract.NotAfter()) || time.Since(ca.NotBefore) < 4*time.Minute:
		t.Errorf("validity %v to %v", ca.NotBefore, ca.NotAfter)
	case len(ca.SubjectKeyId) == 0 || ca.SerialNumber.Sign() <= 0:
		t.Error("no subject key ID or serial")
	}

}
