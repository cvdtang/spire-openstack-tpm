package activation

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// DefaultDevice is empty, since TBS has no device path.
const DefaultDevice = ""

// CheckDevice refuses a device path.
func CheckDevice(device string) error {
	if device != "" {
		return errors.New("tpm_device is not supported on Windows, where the TPM is reached through TBS")
	}
	return nil
}

func openTPM(string) (transport.TPMCloser, error) {
	t, err := windowstpm.Open()
	if err != nil {
		return nil, fmt.Errorf("open the TPM through TBS: %w", err)
	}
	return t, nil
}
