//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/issuerapi"
)

// issuerClient is an issuer client with host's mTLS identity, or with none like the IPA ramdisk if host is "".
func issuerClient(t testing.TB, host string) *http.Client {
	t.Helper()
	switch host {
	case "":
		return issuerClientWith(t, nil)
	case lab.Controller:
		cert, err := tls.LoadX509KeyPair(path(".state/pki/compute-1.crt"), path(".state/pki/compute-1.key"))
		must(t, err, "compute-1 certificate")
		return issuerClientWith(t, &cert)
	}
	pair, err := tls.LoadX509KeyPair(path(hostCA), path(hostCAKey))
	must(t, err, "host CA key")
	ca, err := x509.ParseCertificate(pair.Certificate[0])
	must(t, err, "host CA")
	cert := leafCert(t, ca, pair.PrivateKey, host, x509.ExtKeyUsageClientAuth)
	return issuerClientWith(t, &cert)
}

// issuerClientWith is an issuer client that trusts the lab's host CA and presents cert, if any, even when the server's acceptable CAs omit its issuer, where Go would send none.
func issuerClientWith(t testing.TB, cert *tls.Certificate) *http.Client {
	t.Helper()
	ca, err := os.ReadFile(path(hostCA))
	must(t, err, "host CA")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// leafCert makes a certificate for host with one extended key usage, signed by ca, or self-signed if ca is nil.
func leafCert(t testing.TB, ca *x509.Certificate, caKey any, host string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err, "key")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if ca == nil {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign
		ca, caKey = tmpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
	must(t, err, "certificate")
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// issuerDo sends a request to the issuer and returns the status (0 on a transport error), the refusal and the body.
func issuerDo(t testing.TB, c *http.Client, method, endpoint string, body []byte) (int, issuerapi.Error, []byte) {
	t.Helper()
	var e issuerapi.Error
	req, err := http.NewRequest(method, lab.IssuerURL+endpoint, bytes.NewReader(body))
	must(t, err, "request")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Logf("issuer: %v", err)
		return 0, e, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if err := json.Unmarshal(b, &e); err != nil {
			t.Logf("issuer error body: %v", err)
		}
	}
	t.Logf("issuer %s %s: %d %s %s", method, endpoint, resp.StatusCode, e.Code, e.Message)
	return resp.StatusCode, e, b
}

// issuerPost asks for a virtual machine's certificate.
func issuerPost(t testing.TB, c *http.Client, body []byte) (int, issuerapi.Error) {
	t.Helper()
	code, e, _ := issuerDo(t, c, http.MethodPost, issuerapi.PathVMCertificate, body)
	return code, e
}

// vmRequest is a well-formed request for uuid with a fresh ECC P-384 key in swtpm_setup's EK format.
func vmRequest(t testing.TB, uuid string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.PublicKey.Bytes() // 0x04 || X || Y
	must(t, err, "key")
	b, _ := json.Marshal(issuerapi.VMCertificateRequest{InstanceUUID: uuid,
		Key: fmt.Sprintf("x=%x,y=%x,id=secp384r1", pub[1:49], pub[49:])})
	return b
}

// unknownUUID names no instance and no node.
const unknownUUID = "00000000-0000-4000-8000-000000000000"

// tinyVTPMFlavor returns a small vTPM flavor for Cirros builds, creating it on first use.
func tinyVTPMFlavor(t testing.TB) string {
	t.Helper()
	const flavor = "m1.vtpm-tiny"
	ensureFlavor(t, flavor, 1, 512, 1, map[string]string{
		"hw:tpm_version": "2.0", "hw:tpm_model": "tpm-crb", "hw:tpm_secret_security": "host"})
	return flavor
}

// Ensures the issuer refuses VM certificates it cannot vouch for.
func TestIssuerRefusals(t *testing.T) {
	const unknown = unknownUUID
	host := lab.Controller

	// Ensures the VM endpoint refuses a caller without a client certificate.
	t.Run("no-client-certificate", func(t *testing.T) {
		if code, e := issuerPost(t, issuerClient(t, ""), vmRequest(t, unknown)); code != 403 || e.Code != issuerapi.CodeRefused {
			t.Fatalf("got %d %s without a client certificate", code, e.Code)
		}
	})
	// Ensures a client certificate the hosts' CA did not issue fails the TLS handshake.
	t.Run("foreign-client-certificate", func(t *testing.T) {
		cert := leafCert(t, nil, nil, host, x509.ExtKeyUsageClientAuth)
		if code, e := issuerPost(t, issuerClientWith(t, &cert), vmRequest(t, unknown)); code != 0 {
			t.Fatalf("got %d %s, want a failed handshake", code, e.Code)
		}
	})
	// Ensures a certificate of the hosts' CA without client authentication, such as the issuer's own, fails the TLS handshake.
	t.Run("server-certificate-as-client", func(t *testing.T) {
		pair, err := tls.LoadX509KeyPair(path(hostCA), path(hostCAKey))
		must(t, err, "host CA key")
		ca, err := x509.ParseCertificate(pair.Certificate[0])
		must(t, err, "host CA")
		cert := leafCert(t, ca, pair.PrivateKey, host, x509.ExtKeyUsageServerAuth)
		if code, e := issuerPost(t, issuerClientWith(t, &cert), vmRequest(t, unknown)); code != 0 {
			t.Fatalf("got %d %s, want a failed handshake", code, e.Code)
		}
	})
	// Ensures an instance unknown to Nova is refused.
	t.Run("unknown-instance", func(t *testing.T) {
		if code, e := issuerPost(t, issuerClient(t, host), vmRequest(t, unknown)); code != 403 || e.Code != issuerapi.CodeRefused {
			t.Fatalf("got %d %s", code, e.Code)
		}
	})

	// Ensures missing issuer permissions report a misconfiguration, not a refusal.
	t.Run("forbidden", func(t *testing.T) {
		project := throwawayProject(t, "forbidden")
		id := bootPlain(t, scope{projectID: project}, "forbidden", "")
		code, e := issuerPost(t, issuerClient(t, host), vmRequest(t, id))
		if code != 503 || e.Code != issuerapi.CodeForbidden {
			t.Fatalf("got %d %s %s", code, e.Code, e.Message)
		}
	})

	// A running vTPM instance on compute-1.
	id := bootPlain(t, adminScope, "refusals", tinyVTPMFlavor(t))
	// Ensures a host cannot get a certificate for another host's instance.
	t.Run("other-host", func(t *testing.T) {
		code, e := issuerPost(t, issuerClient(t, "compute-2"), vmRequest(t, id))
		if code != 403 || e.Code != issuerapi.CodeRefused || !strings.Contains(e.Message, "is not the caller") {
			t.Fatalf("compute-2 asking for an instance on %s: %d %s %s", host, code, e.Code, e.Message)
		}
	})
	// Ensures a running instance gets no certificate.
	t.Run("running-instance", func(t *testing.T) {
		code, e := issuerPost(t, issuerClient(t, host), vmRequest(t, id))
		if code != 403 || e.Code != issuerapi.CodeRefused || !strings.Contains(e.Message, "want building/spawning") {
			t.Fatalf("certificate for a running instance: %d %s %s", code, e.Code, e.Message)
		}
	})
}

// Ensures a vTPM build fails closed while the issuer or OpenBao is down.
func TestFailClosed(t *testing.T) {
	flavor := tinyVTPMFlavor(t)
	failedBuild := func(t *testing.T, name string) {
		inst := boot(t, name, bootSpec{scope: adminScope, flavor: flavor, image: lab.CirrosImage, network: lab.OtherNetwork})
		if inst.ID == "" {
			t.Fatal("no server was created")
		}
		s := showServer(t, inst.ID)
		t.Logf("status %s, fault %q", s.Status, s.fault())
		if s.Status != "ERROR" {
			t.Fatalf("build ended %s, want ERROR", s.Status)
		}
		if swtpmState(t, inst.ID) {
			t.Fatal("swtpm state left on compute-1")
		}
	}
	issuerHealthy := func() bool { _, err := run(nil, "curl", "-fsS", "-m", "30", lab.IssuerHealthURL); return err == nil }

	// Ensures a vTPM build fails while the issuer is stopped.
	t.Run("issuer-down", func(t *testing.T) {
		local(t, "docker", "stop", "issuer")
		t.Cleanup(func() {
			local(t, "docker", "start", "issuer")
			eventually(t, 2*time.Minute, "issuer healthy", issuerHealthy)
		})
		failedBuild(t, "failclosed-issuer")
	})
	// Ensures a vTPM build fails while OpenBao is unresponsive, and the issuer's health shows it.
	t.Run("openbao-unresponsive", func(t *testing.T) {
		// Paused, not stopped: OpenBao keeps its keys in memory (dev mode).
		local(t, "docker", "pause", "openbao")
		t.Cleanup(func() {
			local(t, "docker", "unpause", "openbao")
			eventually(t, 2*time.Minute, "issuer healthy", issuerHealthy)
		})
		if code, _ := run(nil, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "30", lab.IssuerHealthURL); code != "503" {
			t.Fatalf("issuer health with OpenBao paused: HTTP %s, want 503", code)
		}
		failedBuild(t, "failclosed-openbao")
	})
}
