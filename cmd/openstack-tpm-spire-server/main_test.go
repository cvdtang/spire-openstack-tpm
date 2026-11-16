package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cvdtang/openstack-tpm/internal/activation"
	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/nodeattestor"
	"github.com/cvdtang/openstack-tpm/internal/pkitest"
	"github.com/cvdtang/openstack-tpm/internal/tpmtest"
)

const (
	instanceID = "11111111-1111-4111-8111-111111111111"
	projectID  = "0123456789abcdef0123456789abcdef"
)

func testClaims(kind string) contract.Claims {
	return contract.Claims{
		Region: "RegionOne", DomainID: "domain-a", ProjectID: projectID, InstanceID: instanceID,
		Kind: kind, UserID: "u1",
	}
}

// stream is the agent's side of an attestation, which sends the payload and answers the challenge with answer.
type stream struct {
	grpc.ServerStream
	payload []byte
	answer  func(challenge []byte) []byte
	sent    []*nodeattestorv1.AttestResponse
	recvs   int
}

func (s *stream) Context() context.Context { return context.Background() }

func (s *stream) Recv() (*nodeattestorv1.AttestRequest, error) {
	s.recvs++
	switch {
	case s.recvs == 1:
		return &nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: s.payload}}, nil
	case s.recvs == 2 && len(s.sent) == 1 && s.answer != nil:
		return &nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_ChallengeResponse{
			ChallengeResponse: s.answer(s.sent[0].GetChallenge()),
		}}, nil
	}
	return nil, io.EOF
}

func (s *stream) Send(r *nodeattestorv1.AttestResponse) error {
	s.sent = append(s.sent, r)
	return nil
}

func configured(t *testing.T, bundle, hcl string) (*plugin, *bytes.Buffer) {
	t.Helper()
	log := &bytes.Buffer{}
	p := &plugin{log: hclog.New(&hclog.LoggerOptions{Output: log, Level: hclog.Debug})}
	_, err := p.Configure(t.Context(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  fmt.Sprintf("ca_bundle = %q\n%s", bundle, hcl),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, log
}

// Ensures the server plugin attests only with a complete config, and Validate reports problems without configuring it.
func TestConfigure(t *testing.T) {
	ctx := t.Context()
	root := pkitest.NewCA(t, "root", nil)
	bundle := pkitest.WriteBundle(t, root, pkitest.NewIssuing(t, "issuing", root))
	good := fmt.Sprintf("ca_bundle = %q\nprojects = [%q]", bundle, projectID)
	core := &configv1.CoreConfiguration{TrustDomain: "example.org"}
	p := &plugin{log: hclog.NewNullLogger()}

	if err := p.Attest(&stream{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("attestation before Configure: %v", err)
	}
	for name, req := range map[string]*configv1.ConfigureRequest{
		"no allowlist":   {HclConfiguration: fmt.Sprintf("ca_bundle = %q", bundle), CoreConfiguration: core},
		"missing bundle": {HclConfiguration: `ca_bundle = "/nonexistent"` + "\n" + `domains = ["*"]`, CoreConfiguration: core},
		"syntax":         {HclConfiguration: "ca_bundle = ", CoreConfiguration: core},
	} {
		if _, err := p.Configure(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if p.cfg.Load() != nil {
		t.Error("a refused configuration configured the plugin")
	}

	// Validate reads the files too, and changes nothing.
	for hcl, valid := range map[string]bool{
		good:                                  true,
		fmt.Sprintf("ca_bundle = %q", bundle): false,
		`ca_bundle = "/nonexistent"` + "\n" + `domains = ["*"]`: false,
		`domains = ["*"]`: false,
	} {
		r, err := p.Validate(ctx, &configv1.ValidateRequest{HclConfiguration: hcl, CoreConfiguration: core})
		if err != nil || r.Valid != valid || valid == (len(r.Notes) > 0) {
			t.Errorf("Validate(%q): %+v %v", hcl, r, err)
		}
	}
	if p.cfg.Load() != nil {
		t.Error("Validate configured the plugin")
	}

	if _, err := p.Configure(ctx, &configv1.ConfigureRequest{HclConfiguration: good, CoreConfiguration: core}); err != nil {
		t.Fatal(err)
	}
	if c := p.cfg.Load(); c == nil || c.trustDomain != "example.org" {
		t.Error("not configured")
	}
}

// Ensures a repeated Configure, as SPIRE sends on SIGUSR1 for plugin_data_file, replaces the config, and a refused one keeps the previous.
func TestReconfigure(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noHTTP{t}
	t.Cleanup(func() { http.DefaultTransport = prev })

	root := pkitest.NewCA(t, "root", nil)
	issuing := pkitest.NewIssuing(t, "issuing", root)
	bundle := pkitest.WriteBundle(t, root, issuing)
	tpm := tpmtest.Open(t, 1)
	tpmtest.Provision(t, tpm, testClaims(contract.KindVM), issuing, tpmtest.Options{Persist: true})
	agent, err := activation.NewAgent(tpmtest.KeepOpen(tpm))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	payload, _ := json.Marshal(activation.AttestPayload{Version: activation.AttestVersion, Cert: agent.Cert, AKPublic: agent.AKPublic})
	activate := func(challenge []byte) []byte {
		var c activation.Challenge
		if err := json.Unmarshal(challenge, &c); err != nil {
			t.Fatal(err)
		}
		secret, err := agent.ActivateCredential(c.IDObject, c.EncSecret)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(activation.ChallengeResponse{Secret: secret})
		return b
	}
	attest := func(p *plugin) (string, error) {
		s := &stream{payload: payload, answer: activate}
		if err := p.Attest(s); err != nil {
			return "", err
		}
		return s.sent[1].GetAgentAttributes().GetSpiffeId(), nil
	}
	configure := func(p *plugin, td, hcl string) error {
		_, err := p.Configure(t.Context(), &configv1.ConfigureRequest{
			CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: td},
			HclConfiguration:  fmt.Sprintf("ca_bundle = %q\n%s", bundle, hcl),
		})
		return err
	}
	allowed := fmt.Sprintf("projects = [%q]", projectID)
	path := "/spire/agent/openstack_tpm/RegionOne/" + projectID + "/" + instanceID

	p, _ := configured(t, bundle, allowed)
	if id, err := attest(p); err != nil || id != "spiffe://example.org"+path {
		t.Fatalf("first config: %q %v", id, err)
	}
	if err := configure(p, "example.org", `projects = ["another"]`); err != nil {
		t.Fatal(err)
	}
	if _, err := attest(p); status.Code(err) != codes.PermissionDenied {
		t.Errorf("after the allowlist was replaced: %v", err)
	}
	if err := configure(p, "example.org", "projects = "); status.Code(err) != codes.InvalidArgument {
		t.Errorf("Configure with a syntax error: %v", err)
	}
	if _, err := attest(p); status.Code(err) != codes.PermissionDenied {
		t.Errorf("after a refused Configure: %v", err)
	}
	if err := configure(p, "other.org", allowed); err != nil {
		t.Fatal(err)
	}
	if id, err := attest(p); err != nil || id != "spiffe://other.org"+path {
		t.Errorf("after a new trust domain: %q %v", id, err)
	}

	// Configure runs concurrently with attestations; -race checks the swap.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 50 {
			_ = configure(p, fmt.Sprintf("td%d.org", i), allowed)
		}
	}()
	for range 50 {
		if err := p.Attest(&stream{payload: []byte("junk")}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("malformed payload during Configure: %v", err)
		}
	}
	<-done
}

// noHTTP fails the test on any HTTP request from a client without its own transport, such as the plugin's OpenStack clients.
type noHTTP struct{ t *testing.T }

func (n noHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	n.t.Errorf("HTTP request %s %s", r.Method, r.URL)
	return nil, errors.New("no HTTP in this test")
}

// Ensures the server plugin attests VM and bare-metal agents from the certificate alone and refuses every malformed or unauthorized exchange.
func TestAttest(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noHTTP{t}
	t.Cleanup(func() { http.DefaultTransport = prev })

	root := pkitest.NewCA(t, "root", nil)
	issuing := pkitest.NewIssuing(t, "issuing", root)
	bundle := pkitest.WriteBundle(t, root, issuing)

	for _, kind := range []string{contract.KindVM, contract.KindBaremetal} {
		t.Run(kind, func(t *testing.T) {
			tpm := tpmtest.Open(t, 1)
			der := tpmtest.Provision(t, tpm, testClaims(kind), issuing, tpmtest.Options{Persist: true})
			agent, err := activation.NewAgent(tpmtest.KeepOpen(tpm))
			if err != nil {
				t.Fatal(err)
			}
			defer agent.Close()
			payload := func(mod func(*activation.AttestPayload)) []byte {
				p := activation.AttestPayload{Version: activation.AttestVersion, Cert: agent.Cert, AKPublic: agent.AKPublic}
				if mod != nil {
					mod(&p)
				}
				b, _ := json.Marshal(p)
				return b
			}
			// activate is the agent plugin's answer to a challenge.
			activate := func(challenge []byte) []byte {
				var c activation.Challenge
				if err := json.Unmarshal(challenge, &c); err != nil {
					t.Fatal(err)
				}
				secret, err := agent.ActivateCredential(c.IDObject, c.EncSecret)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := json.Marshal(activation.ChallengeResponse{Secret: secret})
				return b
			}

			p, log := configured(t, bundle, fmt.Sprintf("projects = [%q]", projectID))
			s := &stream{payload: payload(nil), answer: activate}
			if err := p.Attest(s); err != nil {
				t.Fatal(err)
			}
			if len(s.sent) != 2 || s.sent[0].GetChallenge() == nil {
				t.Fatalf("%d messages sent", len(s.sent))
			}
			attrs := s.sent[1].GetAgentAttributes()
			if attrs == nil {
				t.Fatal("no agent attributes")
			}
			if want := "spiffe://example.org/spire/agent/openstack_tpm/RegionOne/" + projectID + "/" + instanceID; attrs.SpiffeId != want {
				t.Errorf("agent ID %q, want %q", attrs.SpiffeId, want)
			}
			if !attrs.CanReattest {
				t.Error("the agent cannot re-attest")
			}
			v, _ := contract.Parse(der)
			keyHash, _ := contract.KeyHash(v.Key)
			for _, sel := range []string{"region:RegionOne", "domain:id:domain-a", "project:id:" + projectID, "instance:id:" + instanceID,
				"instance:kind:" + kind, "instance:user:id:u1", "project:parent:id:domain-a", "tpm:key:sha256:" + keyHash} {
				if !slices.Contains(attrs.SelectorValues, sel) {
					t.Errorf("no selector %q in %q", sel, attrs.SelectorValues)
				}
			}
			if log.Len() != 0 && strings.Contains(log.String(), "refused") {
				t.Errorf("a refusal was logged:\n%s", log)
			}

			// Each refusal has a code and gets no agent attributes.
			other := tpm2.Marshal(tpm2.TPMTPublic{Type: tpm2.TPMAlgECC})
			for name, c := range map[string]struct {
				hcl       string
				stream    *stream
				code      codes.Code
				challenge bool // a challenge was sent
			}{
				"wrong secret": {"", &stream{payload: payload(nil), answer: func([]byte) []byte {
					b, _ := json.Marshal(activation.ChallengeResponse{Secret: make([]byte, 32)})
					return b
				}}, codes.PermissionDenied, true},
				"empty secret":          {"", &stream{payload: payload(nil), answer: func([]byte) []byte { return []byte(`{}`) }}, codes.PermissionDenied, true},
				"malformed answer":      {"", &stream{payload: payload(nil), answer: func([]byte) []byte { return []byte("junk") }}, codes.InvalidArgument, true},
				"no answer":             {"", &stream{payload: payload(nil)}, codes.Unknown, true},
				"malformed payload":     {"", &stream{payload: []byte("junk")}, codes.InvalidArgument, false},
				"empty payload":         {"", &stream{}, codes.InvalidArgument, false},
				"later payload version": {"", &stream{payload: payload(func(p *activation.AttestPayload) { p.Version = 2 })}, codes.InvalidArgument, false},
				"no payload version":    {"", &stream{payload: payload(func(p *activation.AttestPayload) { p.Version = 0 })}, codes.InvalidArgument, false},
				"no certificate":        {"", &stream{payload: payload(func(p *activation.AttestPayload) { p.Cert = nil })}, codes.PermissionDenied, false},
				"no AK":                 {"", &stream{payload: payload(func(p *activation.AttestPayload) { p.AKPublic = nil })}, codes.InvalidArgument, false},
				"AK that is no AK":      {"", &stream{payload: payload(func(p *activation.AttestPayload) { p.AKPublic = other })}, codes.InvalidArgument, false},
				"project not allowed":   {`projects = ["another"]`, &stream{payload: payload(nil), answer: activate}, codes.PermissionDenied, false},
				"domain not allowed":    {`domains = ["domain-b"]`, &stream{payload: payload(nil), answer: activate}, codes.PermissionDenied, false},
			} {
				hcl := c.hcl
				if hcl == "" {
					hcl = `domains = ["*"]`
				}
				p, log := configured(t, bundle, hcl)
				err := p.Attest(c.stream)
				if err == nil || status.Code(err) != c.code {
					t.Errorf("%s: %v, want %v", name, err, c.code)
				}
				if challenged := len(c.stream.sent) > 0 && c.stream.sent[0].GetChallenge() != nil; challenged != c.challenge {
					t.Errorf("%s: challenge sent: %v", name, challenged)
				}
				for _, m := range c.stream.sent {
					if m.GetAgentAttributes() != nil {
						t.Errorf("%s: agent attributes sent", name)
					}
				}
				// Every policy refusal is logged.
				if c.code == codes.PermissionDenied && !strings.Contains(log.String(), "attestation refused") {
					t.Errorf("%s: no log line for the refusal:\n%s", name, log)
				}
			}

			// A server with another provider's bundle refuses the certificate.
			foreign := pkitest.NewCA(t, "another root", nil)
			p, _ = configured(t, pkitest.WriteBundle(t, foreign, pkitest.NewIssuing(t, "issuing", foreign)), `domains = ["*"]`)
			s = &stream{payload: payload(nil), answer: activate}
			if err := p.Attest(s); status.Code(err) != codes.PermissionDenied || len(s.sent) != 0 {
				t.Errorf("certificate of another PKI: %v, %d messages", err, len(s.sent))
			}
		})
	}
}

// Ensures each attestor error maps to its gRPC code and log line.
func TestGRPCError(t *testing.T) {
	log := &bytes.Buffer{}
	p := &plugin{log: hclog.New(&hclog.LoggerOptions{Output: log, Level: hclog.Debug})}
	for _, c := range []struct {
		err  error
		code codes.Code
		log  string
	}{
		{fmt.Errorf("%w: project", nodeattestor.ErrMismatch), codes.PermissionDenied, "ALERT"},
		{fmt.Errorf("%w: nova", nodeattestor.ErrUnavailable), codes.Unavailable, "attestation failed"},
		{fmt.Errorf("%w: not on the allowlists", nodeattestor.ErrRefused), codes.PermissionDenied, "attestation refused"},
		{fmt.Errorf("something else"), codes.PermissionDenied, "attestation refused"},
	} {
		log.Reset()
		err := p.grpcError(c.err, "instance_uuid", instanceID)
		if status.Code(err) != c.code || !strings.Contains(log.String(), c.log) || !strings.Contains(log.String(), instanceID) {
			t.Errorf("%v: code %v, log %q", c.err, status.Code(err), log)
		}
		if c.log != "ALERT" && strings.Contains(log.String(), "ALERT") {
			t.Errorf("%v: logged as an alert", c.err)
		}
	}
}
