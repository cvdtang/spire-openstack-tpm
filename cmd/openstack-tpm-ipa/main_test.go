package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/pkitest"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// Ensures the IPA tool's config has working defaults and refuses malformed or unknown settings.
func TestReadConfig(t *testing.T) {
	// The inspection collector runs without a config.
	c, err := readConfig(filepath.Join(t.TempDir(), "missing"))
	if err != nil || c.url != "" || c.timeout != 60*time.Second {
		t.Fatalf("no file: %+v %v", c, err)
	}
	c, err = readConfig(writeFile(t, "ipa.conf", `
		# openstack-tpm
		url = "https://issuer:8443/"

		ca      = "/etc/ca.pem"
		tpm     = "/dev/tpm0"
		timeout = "5s"
	`))
	if err != nil || c.url != "https://issuer:8443" || c.ca != "/etc/ca.pem" || c.tpm != "/dev/tpm0" || c.timeout != 5*time.Second {
		t.Fatalf("got %+v %v", c, err)
	}
	for name, conf := range map[string]string{
		"bad line": "url", "unquoted value": "url = https://issuer", "unknown key": `token = "x"`,
		"bad timeout": `timeout = "soon"`, "zero timeout": `timeout = "0s"`,
	} {
		if c, err := readConfig(writeFile(t, "ipa.conf", conf)); err == nil {
			t.Errorf("%s accepted as %+v", name, c)
		}
	}
}

// Ensures the issuer client requires an HTTPS URL and a usable CA.
func TestNewClient(t *testing.T) {
	ca := pkitest.WriteBundle(t, pkitest.NewCA(t, "issuer CA", nil))
	if c, err := newClient(&config{url: "https://issuer:8443", ca: ca, timeout: time.Second}); err != nil || c.base != "https://issuer:8443" {
		t.Fatalf("got %+v %v", c, err)
	}
	for name, cfg := range map[string]*config{
		"no url":     {ca: ca},
		"no ca":      {url: "https://issuer:8443"},
		"plain http": {url: "http://issuer:8443", ca: ca},
		"missing ca": {url: "https://issuer:8443", ca: filepath.Join(t.TempDir(), "missing")},
		"empty ca":   {url: "https://issuer:8443", ca: writeFile(t, "empty.pem", "not PEM")},
	} {
		if c, err := newClient(cfg); err == nil {
			t.Errorf("%s accepted as %+v", name, c)
		}
	}
}

// Ensures the command line refuses unknown flags and a missing command.
func TestRun(t *testing.T) {
	if _, err := run(nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("no command: %v", err)
	}
	if _, err := run([]string{"deploy", "-bogus"}); err == nil {
		t.Error("an unknown flag was accepted")
	}
}
