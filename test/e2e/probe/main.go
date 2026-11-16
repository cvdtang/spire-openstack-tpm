// Command probe is the e2e tests' attacker client, which runs in an instance and sends a SPIRE server what an honest agent never would.
// It prints one JSON Result and exits 0 whether or not the server accepted.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/cvdtang/openstack-tpm/internal/activation"
)

// Result is the probe's output.
type Result struct {
	Accepted bool   `json:"accepted"`
	SPIFFEID string `json:"spiffe_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

type recording struct {
	Payload activation.AttestPayload `json:"payload"`
	Answer  []byte                   `json:"answer"`
}

func main() {
	server := flag.String("server", "", "SPIRE Server address (host:port)")
	device := flag.String("tpm", "/dev/tpmrm0", "TPM device")
	certFile := flag.String("cert", "", "certificate (DER) to present instead of the one in NV")
	forge := flag.Bool("forge", false, "present a look-alike certificate from a self-made CA")
	record := flag.String("record", "", "save payload and answer here")
	replay := flag.String("replay", "", "replay a recording")
	hangup := flag.Bool("hangup", false, "abandon the exchange at the challenge")
	flag.Parse()
	if *server == "" {
		fmt.Fprintln(os.Stderr, "probe: -server is required")
		os.Exit(2)
	}

	var res Result
	id, err := run(*server, *device, *certFile, *forge, *record, *replay, *hangup)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Accepted, res.SPIFFEID = true, id
	}
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		os.Exit(1)
	}
}

func run(server, device, certFile string, forge bool, record, replay string, hangup bool) (string, error) {
	var rec recording
	var agent *activation.Agent
	if replay != "" {
		b, err := os.ReadFile(replay)
		if err != nil {
			return "", err
		}
		if err := json.Unmarshal(b, &rec); err != nil {
			return "", err
		}
	} else {
		a, err := activation.Open(device)
		if err != nil {
			return "", fmt.Errorf("probe setup: %w", err)
		}
		defer a.Close()
		agent = a
		rec.Payload = activation.AttestPayload{Version: activation.AttestVersion, Cert: a.Cert, AKPublic: a.AKPublic}
		if certFile != "" {
			if rec.Payload.Cert, err = os.ReadFile(certFile); err != nil {
				return "", err
			}
		}
		if forge {
			if rec.Payload.Cert, err = forgeCert(a.Cert); err != nil {
				return "", err
			}
		}
	}

	// The attacker does not need to verify the server.
	conn, err := grpc.NewClient(server, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := agentv1.NewAgentClient(conn).AttestAgent(ctx)
	if err != nil {
		return "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(rec.Payload)
	if err != nil {
		return "", err
	}
	if err := stream.Send(&agentv1.AttestAgentRequest{Step: &agentv1.AttestAgentRequest_Params_{Params: &agentv1.AttestAgentRequest_Params{
		Data:   &types.AttestationData{Type: "openstack_tpm", Payload: payload},
		Params: &agentv1.AgentX509SVIDParams{Csr: csr},
	}}}); err != nil {
		return "", err
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			return "", err
		}
		if r := resp.GetResult(); r != nil {
			if record != "" {
				b, err := json.Marshal(rec)
				if err != nil {
					return "", err
				}
				if err := os.WriteFile(record, b, 0o600); err != nil {
					return "", err
				}
			}
			id := r.GetSvid().GetId()
			return "spiffe://" + id.GetTrustDomain() + id.GetPath(), nil
		}
		if hangup {
			cancel()
			return "", errors.New("hung up at the challenge")
		}
		var c activation.Challenge
		if err := json.Unmarshal(resp.GetChallenge(), &c); err != nil {
			return "", err
		}
		answer := rec.Answer
		if agent != nil {
			if answer, err = agent.ActivateCredential(c.IDObject, c.EncSecret); err != nil {
				fmt.Fprintln(os.Stderr, "probe: own TPM cannot activate this credential:", err)
				answer = make([]byte, 32)
				rand.Read(answer)
			}
			rec.Answer = answer
		}
		b, err := json.Marshal(activation.ChallengeResponse{Secret: answer})
		if err != nil {
			return "", err
		}
		if err := stream.Send(&agentv1.AttestAgentRequest{Step: &agentv1.AttestAgentRequest_ChallengeResponse{ChallengeResponse: b}}); err != nil {
			return "", err
		}
	}
}

// forgeCert re-signs the genuine certificate's contents under a self-signed look-alike of the provider's issuing CA.
func forgeCert(genuine []byte) ([]byte, error) {
	g, err := x509.ParseCertificate(genuine)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: g.Issuer, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: g.SerialNumber, Subject: g.Subject, NotBefore: g.NotBefore, NotAfter: g.NotAfter,
		KeyUsage: g.KeyUsage, BasicConstraintsValid: true,
	}
	for _, e := range g.Extensions {
		if e.Id.String() == "2.5.29.17" { // the SAN with the claims URI
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, e)
		}
	}
	if len(tmpl.ExtraExtensions) != 1 {
		return nil, errors.New("genuine certificate has no subject alternative name")
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca, g.PublicKey, key)
}
