// Command openstack-tpm-spire-agent is the SPIRE Agent NodeAttestor plugin "openstack_tpm".
// It sends the certificate from the TPM's NV and answers the server's challenge with the certified key.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cvdtang/openstack-tpm/internal/activation"
)

// pluginConfig is the HCL configuration; everything else comes from the certificate.
type pluginConfig struct {
	TPMDevice string `hcl:"tpm_device"`
}

type plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	cfg atomic.Pointer[pluginConfig]
	// tpmMu serialises TPM use within this process.
	tpmMu sync.Mutex
}

// SetLogger implements pluginsdk.NeedsLogger.
func (p *plugin) SetLogger(log hclog.Logger) { p.log = log }

func parseConfig(hclConfig string) (*pluginConfig, error) {
	cfg := &pluginConfig{TPMDevice: activation.DefaultDevice}
	if err := hcl.Decode(cfg, hclConfig); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := activation.CheckDevice(cfg.TPMDevice); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (p *plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg, err := parseConfig(req.HclConfiguration)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	p.cfg.Store(cfg)
	p.log.Info("configured", "tpm_device", cmp.Or(cfg.TPMDevice, "TBS"))
	return &configv1.ConfigureResponse{}, nil
}

func (p *plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	if _, err := parseConfig(req.HclConfiguration); err != nil {
		return &configv1.ValidateResponse{Valid: false, Notes: []string{err.Error()}}, nil
	}
	return &configv1.ValidateResponse{Valid: true}, nil
}

func (p *plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	cfg := p.cfg.Load()
	if cfg == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	p.tpmMu.Lock()
	defer p.tpmMu.Unlock()
	tpm, err := activation.Open(cfg.TPMDevice)
	if err != nil {
		p.log.Error("TPM setup failed", "err", err)
		return status.Errorf(codes.Unavailable, "%v", err)
	}
	defer tpm.Close()

	pb, err := json.Marshal(activation.AttestPayload{Version: activation.AttestVersion, Cert: tpm.Cert, AKPublic: tpm.AKPublic})
	if err != nil {
		return status.Errorf(codes.Internal, "payload: %v", err)
	}
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{Payload: pb},
	}); err != nil {
		return err
	}

	ch, err := stream.Recv()
	if err != nil {
		return err
	}
	var c activation.Challenge
	if err := json.Unmarshal(ch.Challenge, &c); err != nil {
		return status.Errorf(codes.InvalidArgument, "malformed challenge: %v", err)
	}
	secret, err := tpm.ActivateCredential(c.IDObject, c.EncSecret)
	if err != nil {
		p.log.Error("ActivateCredential failed", "kind", tpm.Claims.Kind, "err", err)
		return status.Errorf(codes.Internal, "ActivateCredential: %v", err)
	}
	rb, err := json.Marshal(activation.ChallengeResponse{Secret: secret})
	if err != nil {
		return status.Errorf(codes.Internal, "challenge response: %v", err)
	}
	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{ChallengeResponse: rb},
	})
}

func main() {
	p := &plugin{log: hclog.NewNullLogger()}
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
