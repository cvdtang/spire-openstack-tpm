//go:build !windows

package activation

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// DefaultDevice is the kernel's TPM resource manager.
const DefaultDevice = "/dev/tpmrm0"

// CheckDevice requires a device path.
func CheckDevice(device string) error {
	if device == "" {
		return errors.New("tpm_device must not be empty")
	}
	return nil
}

func openTPM(device string) (transport.TPMCloser, error) {
	t, err := linuxtpm.Open(device)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", device, err)
	}
	return t, nil
}
