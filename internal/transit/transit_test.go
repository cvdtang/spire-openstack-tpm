package transit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/openbao/openbao/api/v2"

	"github.com/cvdtang/openstack-tpm/internal/baotest"
)

func newClient(t *testing.T, addr, token string) *api.Client {
	t.Helper()
	c, err := NewClient(addr, token)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func digest() []byte {
	d := sha512.Sum384([]byte("tbs"))
	return d[:]
}

// Ensures the Transit signer's signatures verify and Check notices a rotated key.
func TestSign(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := baotest.Start(t)
	b.Key(t, "k", "ecdsa-p384", false)
	s, err := NewSigner(ctx, newClient(t, b.Addr, baotest.RootToken), "transit", "k")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(nil, digest(), crypto.SHA384)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest(), sig) {
		t.Fatal("signature does not verify")
	}
	if err := s.Check(ctx); err != nil {
		t.Fatal(err)
	}
	b.Rotate(t, "k")
	if err := s.Check(ctx); err == nil {
		t.Fatal("Check accepted a rotated key")
	}
}

// Ensures the Transit signer refuses unsuitable keys, tokens, digests and responses.
func TestRefusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := baotest.Start(t)
	b.Key(t, "k", "ecdsa-p384", false)
	b.Key(t, "exportable", "ecdsa-p384", true)
	b.Key(t, "rsa", "rsa-2048", false)
	c := newClient(t, b.Addr, baotest.RootToken)
	for name, key := range map[string]string{"exportable key": "exportable", "RSA key": "rsa", "missing key": "missing"} {
		if _, err := NewSigner(ctx, c, "transit", key); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := NewSigner(ctx, newClient(t, b.Addr, "wrong"), "transit", "k"); err == nil || !strings.Contains(err.Error(), "openbao 403") {
		t.Errorf("wrong token: %v", err)
	}

	s, err := NewSigner(ctx, c, "transit", "k")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(nil, digest()[:10], crypto.SHA384); err == nil {
		t.Error("short digest accepted")
	}
	if _, err := s.Sign(nil, digest(), crypto.SHA1); err == nil {
		t.Error("SHA-1 accepted")
	}

	// A proxy in front of OpenBao replaces the signature, which a working OpenBao never gets wrong.
	var mu sync.Mutex
	var bad string
	target, _ := url.Parse(b.Addr)
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = func(r *http.Response) error {
		if !strings.HasPrefix(r.Request.URL.Path, "/v1/transit/sign/") {
			return nil
		}
		mu.Lock()
		body, _ := json.Marshal(map[string]any{"data": map[string]string{"signature": bad}})
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
	proxy := httptest.NewServer(rp)
	t.Cleanup(proxy.Close)
	s, err = NewSigner(ctx, newClient(t, proxy.URL, baotest.RootToken), "transit", "k")
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range []string{"nonsense", "vault:v1:", "vault:v1:!!", "vault:v1:" + base64.StdEncoding.EncodeToString([]byte("junk"))} {
		mu.Lock()
		bad = sig
		mu.Unlock()
		if _, err := s.Sign(nil, digest(), crypto.SHA384); err == nil {
			t.Errorf("signature %q accepted", sig)
		}
	}
}
