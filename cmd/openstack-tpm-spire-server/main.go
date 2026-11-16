// Command openstack-tpm-spire-server is the SPIRE Server NodeAttestor plugin "openstack_tpm".
// It verifies the certificate and allowlists, runs the credential challenge and returns the selectors.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cvdtang/openstack-tpm/internal/activation"
	"github.com/cvdtang/openstack-tpm/internal/nodeattestor"
)

// PluginName is the attestation type agents and servers agree on, and the type of the selectors.
const PluginName = "openstack_tpm"

type plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	cfg atomic.Pointer[config]
}

type config struct {
	att         *nodeattestor.Attestor
	trustDomain string
}

// SetLogger implements pluginsdk.NeedsLogger.
func (p *plugin) SetLogger(log hclog.Logger) { p.log = log }

func (p *plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg, err := nodeattestor.ParseConfig(req.HclConfiguration)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	att, err := nodeattestor.New(cfg, nil)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	p.cfg.Store(&config{att: att, trustDomain: req.GetCoreConfiguration().GetTrustDomain()})
	p.log.Info("configured", "projects", len(cfg.Projects), "domains", cfg.Domains,
		"nova_selectors", cfg.NovaSelectors, "keystone_selectors", cfg.KeystoneSelectors)
	return &configv1.ConfigureResponse{}, nil
}

func (p *plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	cfg, err := nodeattestor.ParseConfig(req.HclConfiguration)
	if err == nil {
		err = cfg.Check()
	}
	if err != nil {
		return &configv1.ValidateResponse{Valid: false, Notes: []string{err.Error()}}, nil
	}
	return &configv1.ValidateResponse{Valid: true}, nil
}

// grpcError maps attestor error kinds to gRPC codes and logs every refusal, as an alert when Nova or Keystone contradict the certificate.
func (p *plugin) grpcError(err error, attrs ...any) error {
	switch {
	case errors.Is(err, nodeattestor.ErrMismatch):
		p.log.Error("ALERT attestation refused: Nova or Keystone contradicts the certificate", append(attrs, "err", err)...)
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, nodeattestor.ErrUnavailable):
		p.log.Warn("attestation failed", append(attrs, "err", err)...)
		return status.Error(codes.Unavailable, err.Error())
	default:
		p.log.Warn("attestation refused", append(attrs, "err", err)...)
		return status.Error(codes.PermissionDenied, err.Error())
	}
}

func (p *plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	cfg := p.cfg.Load()
	if cfg == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}
	var payload activation.AttestPayload
	if err := json.Unmarshal(req.GetPayload(), &payload); err != nil {
		return status.Errorf(codes.InvalidArgument, "malformed payload: %v", err)
	}
	if payload.Version != activation.AttestVersion {
		return status.Errorf(codes.InvalidArgument, "payload version %d is not supported (this server knows %d)", payload.Version, activation.AttestVersion)
	}

	// Certificate and allowlists.
	v, err := cfg.att.Verify(payload.Cert)
	if err != nil {
		return p.grpcError(err)
	}
	attrs := []any{"instance_uuid", v.Claims.InstanceID, "project_id", v.Claims.ProjectID, "kind", v.Claims.Kind}

	// Credential activation against the certified key.
	want, idObject, encSecret, err := activation.MakeCredential(v, payload.AKPublic)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "AK: %v", err)
	}
	cb, err := json.Marshal(activation.Challenge{IDObject: idObject, EncSecret: encSecret})
	if err != nil {
		return status.Errorf(codes.Internal, "challenge: %v", err)
	}
	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{Challenge: cb},
	}); err != nil {
		return err
	}
	resp, err := stream.Recv()
	if err != nil {
		return err
	}
	var answer activation.ChallengeResponse
	if err := json.Unmarshal(resp.GetChallengeResponse(), &answer); err != nil {
		return status.Errorf(codes.InvalidArgument, "malformed challenge response: %v", err)
	}
	if !activation.Equal(answer.Secret, want) {
		return p.grpcError(fmt.Errorf("%w: %w: credential activation failed", nodeattestor.ErrRefused, activation.ErrKeyMismatch), attrs...)
	}

	// Selectors.
	selectors, err := cfg.att.Selectors(stream.Context(), v)
	if err != nil {
		return p.grpcError(err, attrs...)
	}
	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{AgentAttributes: &nodeattestorv1.AgentAttributes{
			SpiffeId:       fmt.Sprintf("spiffe://%s/spire/agent/%s/%s", cfg.trustDomain, PluginName, nodeattestor.AgentPath(v)),
			SelectorValues: selectors,
			CanReattest:    true,
		}},
	})
}

func main() {
	p := &plugin{log: hclog.NewNullLogger()}
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
