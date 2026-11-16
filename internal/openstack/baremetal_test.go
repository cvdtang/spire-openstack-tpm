package openstack

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

// Ensures a node is read from Ironic with its state and instance, telling missing, hidden and absent endpoints apart.
func TestNode(t *testing.T) {
	f := newFakeCloud(t)
	c := f.client(Credentials{Username: "issuer", Password: "x", ProjectName: "service"})
	ctx := context.Background()

	n, err := c.GetNode(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if want := (Node{UUID: "node-1", ProvisionState: "wait call-back", InstanceUUID: "bm"}); *n != want {
		t.Errorf("node %+v, want %+v", *n, want)
	}
	// The inventory API needs a recent API version.
	for h, want := range map[string]string{"X-OpenStack-Ironic-API-Version": "1.81", "OpenStack-API-Version": "baremetal 1.81"} {
		if got := f.header("/baremetal/v1/nodes/node-1", h); got != want {
			t.Errorf("%s: %q, want %q", h, got, want)
		}
	}
	if got := f.header("/baremetal/v1/nodes/node-1", "X-Auth-Token"); got != "token-for-id-of-service" {
		t.Errorf("token %q", got)
	}
	if _, err := c.GetNode(ctx, "none"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown node: %v", err)
	}
	if _, err := c.GetNode(ctx, "hidden"); !errors.Is(err, ErrForbidden) {
		t.Errorf("node the policy hides: %v", err)
	}
	// A catalog endpoint that ends in /v1 is the same API.
	if n, err := c.WithRegion("RegionTwo").GetNode(ctx, "node-1"); err != nil || n.UUID != "node-1" {
		t.Errorf("endpoint with /v1: %+v, %v", n, err)
	}
	if _, err := c.WithRegion("RegionThree").GetNode(ctx, "node-1"); !errors.Is(err, ErrNoEndpoint) {
		t.Errorf("region without Ironic: %v", err)
	}
}

// Ensures a node's inspection plugin data is read from its inventory.
func TestNodePluginData(t *testing.T) {
	f := newFakeCloud(t)
	c := f.client(Credentials{Username: "issuer", Password: "x", ProjectName: "service"})
	ctx := context.Background()

	data, err := c.GetNodePluginData(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]string
	if err := json.Unmarshal(data["openstack_tpm"], &report); err != nil || report["tpm_ek_sha256"] != "abc" || len(data) != 2 {
		t.Errorf("plugin data %s: %v", data, err)
	}
	if got := f.header("/baremetal/v1/nodes/node-1/inventory", "X-OpenStack-Ironic-API-Version"); got != "1.81" {
		t.Errorf("API version %q", got)
	}
	if data, err := c.GetNodePluginData(ctx, "bare"); err != nil || len(data) != 0 {
		t.Errorf("inventory without plugin data: %s, %v", data, err)
	}
	if _, err := c.GetNodePluginData(ctx, "never-inspected"); !errors.Is(err, ErrNotFound) {
		t.Errorf("node without inspection data: %v", err)
	}
}

// Ensures allocations give the consumer's project and resource providers, and a consumer without them is not found.
func TestAllocationProviders(t *testing.T) {
	f := newFakeCloud(t)
	c := f.client(Credentials{Username: "issuer", Password: "x", ProjectName: "service"})
	ctx := context.Background()
	al, err := c.GetAllocations(ctx, "bm")
	if err != nil || al.ProjectID != "p1" || !slices.Equal(al.Providers, []string{"node-1"}) {
		t.Fatalf("allocations %+v, %v", al, err)
	}
	if got := f.header("/placement/allocations/bm", "OpenStack-API-Version"); got != "placement 1.38" {
		t.Errorf("API version %q", got)
	}
	if _, err := c.GetAllocations(ctx, "none"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no allocations: %v", err)
	}
}

// Ensures a bare-metal server is read with its host and node, also through another region.
func TestServerOnNode(t *testing.T) {
	f := newFakeCloud(t)
	c := f.client(Credentials{AppCredID: "id", AppCredSecret: "s"})
	ctx := context.Background()
	s, err := c.GetServer(ctx, "bm")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "in RegionOne" || s.Node != "node-1" || s.Host != "ironic-host" || s.Task() != "spawning" || s.ImageID() != "" {
		t.Errorf("server %+v", s)
	}
	s.TaskState = nil
	if s.Task() != "" {
		t.Error("Task of an idle server")
	}

	// WithRegion reads the same catalog's other region, with a token of its own.
	two := c.WithRegion("RegionTwo")
	if s, err = two.GetServer(ctx, "bm"); err != nil || s.Name != "in RegionTwo" {
		t.Errorf("RegionTwo: %+v, %v", s, err)
	}
	if s, err = c.GetServer(ctx, "bm"); err != nil || s.Name != "in RegionOne" {
		t.Errorf("RegionOne after WithRegion: %+v, %v", s, err)
	}
	if n := f.auths.Load(); n != 2 {
		t.Errorf("%d authentications, want one per client", n)
	}
	// The region survives a change of project.
	user := f.client(Credentials{Username: "spire", Password: "x", ProjectName: "service"})
	if s, err = user.WithRegion("RegionTwo").WithProject("p9").GetServer(ctx, "bm"); err != nil || s.Name != "in RegionTwo" {
		t.Errorf("WithRegion then WithProject: %+v, %v", s, err)
	}
	if got := f.header("/two/v2.1/servers/bm", "X-Auth-Token"); got != "token-for-p9" {
		t.Errorf("token %q", got)
	}
}
