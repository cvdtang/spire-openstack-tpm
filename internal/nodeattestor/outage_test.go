package nodeattestor

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Outages of Nova and Keystone, with the real openstack client against local servers.

// refusedURL is the URL of a closed server, which refuses connections.
func refusedURL(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.NotFoundHandler())
	s.Close()
	return s.URL
}

// silentURL accepts connections and never answers.
func silentURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return "http://" + l.Addr().String()
}

// liveAttestor is a server configured like the lab's tenant server, with an application credential.
func (p *pki) liveAttestor(t *testing.T, authURL, selectors string) *Attestor {
	t.Helper()
	return p.attestor(t, fmt.Sprintf(`
		domains = ["*"]
		%s
		openstack {
			auth_url    = %q
			credentials = [{ application_credential_id = "app", application_credential_secret_file = %q }]
		}`, selectors, authURL+"/v3", secretFile(t, "app-secret")), nil)
}

const bothSelectors = "nova_selectors = true\nkeystone_selectors = true"

func attest(t *testing.T, a *Attestor, der []byte) ([]string, error) {
	t.Helper()
	v, err := a.Verify(der)
	if err != nil {
		t.Fatal(err)
	}
	return a.Selectors(t.Context(), v)
}

// wantUnavailable checks that err is retryable and its text starts with what could not be asked.
func wantUnavailable(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRefused) || errors.Is(err, ErrMismatch) {
		t.Errorf("%v: want only %v", err, ErrUnavailable)
	}
	if prefix := ErrUnavailable.Error() + ": " + what; err == nil || !strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("%v: want %q first", err, prefix)
	}
}

// Ensures an unreachable Keystone makes live selectors unavailable, naming Keystone.
func TestOutageKeystoneUnreachable(t *testing.T) {
	p := newPKI(t)
	der := p.cert(t, testClaims())
	auth := refusedURL(t)

	// An application credential learns its project when it authenticates, before any read.
	sel, err := attest(t, p.liveAttestor(t, auth, bothSelectors), der)
	if sel != nil {
		t.Errorf("selectors %q", sel)
	}
	wantUnavailable(t, err, "keystone")

	// A user authenticates at its first read, so the error names that read first and Keystone after it.
	a := p.attestor(t, fmt.Sprintf(`
		domains = ["*"]
		nova_selectors = true
		openstack {
			auth_url    = %q
			credentials = [{ username = "spire", password_file = %q }]
		}`, auth+"/v3", secretFile(t, "user-secret")), nil)
	_, err = attest(t, a, der)
	wantUnavailable(t, err, "nova: keystone: ")
}

// Ensures an unreachable Nova makes live selectors unavailable, naming Nova.
func TestOutageNovaUnreachable(t *testing.T) {
	p := newPKI(t)
	k := newKeystone(t, refusedURL(t))
	_, err := attest(t, p.liveAttestor(t, k.URL, bothSelectors), p.cert(t, testClaims()))
	wantUnavailable(t, err, "nova")
	if k.authCount() == 0 {
		t.Error("no token was taken")
	}
}

// Ensures a Nova that never answers fails live selectors after the request timeout.
func TestOutageNovaSilent(t *testing.T) {
	prev := requestTimeout
	requestTimeout = 300 * time.Millisecond
	t.Cleanup(func() { requestTimeout = prev })
	p := newPKI(t)
	k := newKeystone(t, silentURL(t))
	a := p.liveAttestor(t, k.URL, bothSelectors)
	start := time.Now()
	_, err := attest(t, a, p.cert(t, testClaims()))
	wantUnavailable(t, err, "nova")
	if d := time.Since(start); d < requestTimeout || d > requestTimeout+time.Second {
		t.Errorf("refused after %v, want %v", d, requestTimeout)
	}
}

// Ensures cached tokens keep Nova selectors working while Keystone is down.
func TestOutageKeystoneAfterToken(t *testing.T) {
	p := newPKI(t)
	der := p.cert(t, testClaims())
	k := newKeystone(t, newNova(t).URL)
	nova := p.liveAttestor(t, k.URL, "nova_selectors = true")
	both := p.liveAttestor(t, k.URL, bothSelectors)
	for _, a := range []*Attestor{nova, both} {
		if _, err := attest(t, a, der); err != nil {
			t.Fatal(err)
		}
	}
	// The tokens are cached, so a second attestation takes none.
	before := k.authCount()
	for _, a := range []*Attestor{nova, both} {
		if _, err := attest(t, a, der); err != nil {
			t.Fatal(err)
		}
	}
	if n := k.authCount() - before; n != 0 {
		t.Fatalf("%d authentications for servers that hold a token", n)
	}

	k.Close()
	sel, err := attest(t, nova, der)
	if err != nil || !slices.Contains(sel, "instance:name:web-1") {
		t.Errorf("nova_selectors with a cached token: %q, %v", sel, err)
	}
	_, err = attest(t, both, der)
	wantUnavailable(t, err, "keystone")
	_, err = attest(t, p.liveAttestor(t, k.URL, "nova_selectors = true"), der)
	wantUnavailable(t, err, "keystone")
}
