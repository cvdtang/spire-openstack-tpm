//go:build !windows

package main

import (
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Ensures the agent plugin's config defaults the TPM device and refuses invalid values.
func TestParseConfig(t *testing.T) {
	// The plugin needs no configuration.
	cfg, err := parseConfig("")
	if err != nil || cfg.TPMDevice != "/dev/tpmrm0" {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	if cfg, err = parseConfig(`tpm_device = "/dev/tpm0"`); err != nil || cfg.TPMDevice != "/dev/tpm0" {
		t.Fatalf("tpm_device: %+v %v", cfg, err)
	}
	for _, bad := range []string{`tpm_device = ""`, `tpm_device = ["/dev/tpm0"]`, `bogus {`} {
		if cfg, err := parseConfig(bad); err == nil {
			t.Errorf("%q accepted as %+v", bad, cfg)
		}
	}
}

// Ensures the agent plugin attests only once configured and reports config and TPM errors with the right gRPC codes.
func TestConfigure(t *testing.T) {
	ctx := t.Context()
	p := &plugin{log: hclog.NewNullLogger()}

	// Without configuration it does not attest and touches no TPM.
	if err := p.AidAttestation(nil); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("attestation before Configure: %v", err)
	}

	if r, err := p.Validate(ctx, &configv1.ValidateRequest{HclConfiguration: `tpm_device = ""`}); err != nil || r.Valid || len(r.Notes) != 1 {
		t.Errorf("Validate of a bad config: %+v %v", r, err)
	}
	if r, err := p.Validate(ctx, &configv1.ValidateRequest{}); err != nil || !r.Valid {
		t.Errorf("Validate of the empty config: %+v %v", r, err)
	}
	if p.cfg.Load() != nil {
		t.Error("Validate configured the plugin")
	}

	if _, err := p.Configure(ctx, &configv1.ConfigureRequest{HclConfiguration: `tpm_device = ""`}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("Configure with a bad config: %v", err)
	}
	device := filepath.Join(t.TempDir(), "no-tpm")
	if _, err := p.Configure(ctx, &configv1.ConfigureRequest{HclConfiguration: `tpm_device = "` + device + `"`}); err != nil {
		t.Fatal(err)
	}
	if c := p.cfg.Load(); c == nil || c.TPMDevice != device {
		t.Errorf("configured %+v", c)
	}

	// A refused reconfiguration keeps the config, and a valid one replaces it.
	if _, err := p.Configure(ctx, &configv1.ConfigureRequest{HclConfiguration: `tpm_device = ""`}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("reconfigure with a bad config: %v", err)
	}
	if c := p.cfg.Load(); c.TPMDevice != device {
		t.Errorf("a refused reconfiguration changed the device to %q", c.TPMDevice)
	}
	device = filepath.Join(t.TempDir(), "other-tpm")
	if _, err := p.Configure(ctx, &configv1.ConfigureRequest{HclConfiguration: `tpm_device = "` + device + `"`}); err != nil {
		t.Fatal(err)
	}
	if c := p.cfg.Load(); c.TPMDevice != device {
		t.Errorf("reconfigured %+v", c)
	}

	// A TPM that cannot be opened is a retryable failure, before anything is sent.
	if err := p.AidAttestation(nil); status.Code(err) != codes.Unavailable {
		t.Errorf("attestation without a TPM device: %v", err)
	}
}
