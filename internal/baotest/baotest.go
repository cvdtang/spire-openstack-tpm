// Package baotest runs the lab's OpenBao image in dev mode in a container, with Transit mounted at "transit".
package baotest

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cvdtang/openstack-tpm/internal/labenv"
	"github.com/moby/moby/api/types/container"
	"github.com/openbao/openbao/api/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// RootToken is the dev server's root token.
const RootToken = "root"

const port = "8200/tcp"

// Bao is a dev-mode OpenBao and a client with its root token.
type Bao struct {
	Addr   string
	Client *api.Client
}

// Start runs a new OpenBao for the test and removes it when the test ends.
func Start(t *testing.T) *Bao {
	t.Helper()
	if testing.Short() {
		t.Skip("OpenBao runs in a container")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()
	ctr, err := testcontainers.Run(ctx, image(t),
		testcontainers.WithEnv(map[string]string{"BAO_DEV_ROOT_TOKEN_ID": RootToken, "BAO_DEV_LISTEN_ADDRESS": "0.0.0.0:8200"}),
		testcontainers.WithExposedPorts(port),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) { hc.CapAdd = []string{"IPC_LOCK"} }),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/v1/sys/health").WithPort(port).WithStartupTimeout(30*time.Second)),
	)
	testcontainers.CleanupContainer(t, ctr, testcontainers.StopTimeout(0))
	if err != nil {
		t.Fatalf("OpenBao container: %v", err)
	}
	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := ctr.MappedPort(ctx, port)
	if err != nil {
		t.Fatal(err)
	}
	b := &Bao{Addr: "http://" + net.JoinHostPort(host, mapped.Port())}

	cfg := api.DefaultConfig()
	cfg.Address = b.Addr
	if b.Client, err = api.NewClient(cfg); err != nil {
		t.Fatal(err)
	}
	b.Client.SetToken(RootToken)
	if err := b.Client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatal(err)
	}
	return b
}

// image is OPENBAO_IMAGE of lab/lab.env, the image the lab runs.
func image(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for ; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		if dir == filepath.Dir(dir) {
			t.Fatal("no go.mod above the test's directory")
		}
	}
	var c struct {
		Image string `env:"OPENBAO_IMAGE"`
	}
	if err := labenv.Load(filepath.Join(dir, "lab", "lab.env"), &c); err != nil {
		t.Fatal(err)
	}
	return c.Image
}

// Key creates the Transit key name of type typ, such as "ecdsa-p384".
func (b *Bao) Key(t testing.TB, name, typ string, exportable bool) {
	t.Helper()
	if _, err := b.Client.Logical().Write("transit/keys/"+name, map[string]any{"type": typ, "exportable": exportable}); err != nil {
		t.Fatal(err)
	}
}

// Rotate adds a new version of the Transit key name.
func (b *Bao) Rotate(t testing.TB, name string) {
	t.Helper()
	if _, err := b.Client.Logical().Write("transit/keys/"+name+"/rotate", nil); err != nil {
		t.Fatal(err)
	}
}
