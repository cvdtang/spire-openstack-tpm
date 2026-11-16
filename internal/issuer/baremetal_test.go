package issuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/issuerapi"
	"github.com/cvdtang/openstack-tpm/internal/openstack"
	"github.com/cvdtang/openstack-tpm/internal/tpmprov"
)

const (
	nodeID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	otherNode  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	bmID       = "33333333-3333-4333-8333-333333333333"
	bmID2      = "44444444-4444-4444-8444-444444444444"
	projectID2 = "00000000000000000000000000000002"
)

// addBaremetal adds a node that Ironic is deploying for an instance of project.
func (f *fixture) addBaremetal(node, instance, project, ekHash string) {
	f.cloud.mu.Lock()
	defer f.cloud.mu.Unlock()
	f.cloud.nodes[node] = &openstack.Node{UUID: node, ProvisionState: "wait call-back", InstanceUUID: instance}
	f.cloud.eks[node] = ekHash
	f.cloud.allocs[instance] = &openstack.Allocations{ProjectID: project, Providers: []string{node}}
	f.cloud.servers[instance] = &openstack.Server{
		ID: instance, Name: "bm", Status: "BUILD", TenantID: project, UserID: userID, Created: f.now,
		Host: "ironic-conductor", Node: node, VMState: "building", TaskState: new("spawning"),
	}
	if _, ok := f.cloud.projects[project]; !ok {
		f.cloud.projects[project] = &openstack.Project{ID: project, DomainID: "default", ParentID: "default"}
	}
}

// softwareKeys stand in for a TPM where only the issuer's checks matter, with an RSA-2048 EK and a bare-metal instance key.
var softwareKeys = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

func softwareRequest(t *testing.T, node, instance string) (*issuerapi.BaremetalCertificateRequest, string) {
	t.Helper()
	ekKey, err := softwareKeys()
	if err != nil {
		t.Fatal(err)
	}
	ek := tpm2.RSAEKTemplate
	ek.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: ekKey.N.Bytes()})
	ekHash, err := tpmprov.EKHash(&ek)
	if err != nil {
		t.Fatal(err)
	}
	key, err := contract.KeyPublic(contract.KindBaremetal, &p384(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &issuerapi.BaremetalCertificateRequest{Node: node, Instance: instance, EKPublic: tpm2.Marshal(ek), KeyPublic: tpm2.Marshal(key)}, ekHash
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Ensures a bare-metal certificate is issued only for a deploying node with its recorded EK and the instance OpenStack places there.
func TestBaremetalCertificateChecks(t *testing.T) {
	down := errors.New("connection refused")
	type mod func(f *fixture, req *issuerapi.BaremetalCertificateRequest)
	cloud := func(m func(c *fakeCloud)) mod {
		return func(f *fixture, _ *issuerapi.BaremetalCertificateRequest) { m(f.cloud) }
	}
	vmKey, _ := contract.KeyPublic(contract.KindVM, &p384(t).PublicKey)
	unique, _ := contract.Template(contract.KindBaremetal, nil, nil)

	for name, c := range map[string]struct {
		mod    mod
		status int
		code   string
	}{
		"deploying": {cloud(func(c *fakeCloud) { c.nodes[nodeID].ProvisionState = "deploying" }), 200, ""},
		"rebuild": {cloud(func(c *fakeCloud) {
			c.servers[bmID].VMState, c.servers[bmID].TaskState = "active", new("rebuild_spawning")
		}), 200, ""},
		"with a client cert":   {nil, 200, ""},
		"node active":          {cloud(func(c *fakeCloud) { c.nodes[nodeID].ProvisionState = "active" }), 403, issuerapi.CodeRefused},
		"node available":       {cloud(func(c *fakeCloud) { c.nodes[nodeID].ProvisionState = "available" }), 403, issuerapi.CodeRefused},
		"node cleaning":        {cloud(func(c *fakeCloud) { c.nodes[nodeID].ProvisionState = "clean wait" }), 403, issuerapi.CodeRefused},
		"deploy failed":        {cloud(func(c *fakeCloud) { c.nodes[nodeID].ProvisionState = "deploy failed" }), 403, issuerapi.CodeRefused},
		"maintenance":          {cloud(func(c *fakeCloud) { c.nodes[nodeID].Maintenance = true }), 403, issuerapi.CodeRefused},
		"another instance":     {cloud(func(c *fakeCloud) { c.nodes[nodeID].InstanceUUID = bmID2 }), 403, issuerapi.CodeRefused},
		"no instance on node":  {cloud(func(c *fakeCloud) { c.nodes[nodeID].InstanceUUID = "" }), 403, issuerapi.CodeRefused},
		"no node":              {cloud(func(c *fakeCloud) { delete(c.nodes, nodeID) }), 403, issuerapi.CodeRefused},
		"another EK":           {cloud(func(c *fakeCloud) { c.eks[nodeID] = strings.Repeat("0", 64) }), 403, issuerapi.CodeRefused},
		"no recorded EK":       {cloud(func(c *fakeCloud) { c.eks[nodeID] = "" }), 403, issuerapi.CodeRefused},
		"no inspection data":   {cloud(func(c *fakeCloud) { c.fail["ek"] = fmt.Errorf("%w: inventory", openstack.ErrNotFound) }), 403, issuerapi.CodeRefused},
		"allocation elsewhere": {cloud(func(c *fakeCloud) { c.allocs[bmID].Providers = []string{otherNode} }), 403, issuerapi.CodeRefused},
		"no allocation":        {cloud(func(c *fakeCloud) { delete(c.allocs, bmID) }), 403, issuerapi.CodeRefused},
		"Nova's node":          {cloud(func(c *fakeCloud) { c.servers[bmID].Node = otherNode }), 403, issuerapi.CodeRefused},
		"Nova's project":       {cloud(func(c *fakeCloud) { c.servers[bmID].TenantID = projectID2 }), 403, issuerapi.CodeRefused},
		"instance active":      {cloud(func(c *fakeCloud) { c.servers[bmID].VMState, c.servers[bmID].TaskState = "active", nil }), 403, issuerapi.CodeRefused},
		"instance scheduling":  {cloud(func(c *fakeCloud) { c.servers[bmID].TaskState = new("scheduling") }), 403, issuerapi.CodeRefused},
		"ironic down":          {cloud(func(c *fakeCloud) { c.fail["node"] = down }), 503, issuerapi.CodeUnavailable},
		"inventory down":       {cloud(func(c *fakeCloud) { c.fail["ek"] = down }), 503, issuerapi.CodeUnavailable},
		"ironic forbids":       {cloud(func(c *fakeCloud) { c.fail["ek"] = fmt.Errorf("%w: inventory", openstack.ErrForbidden) }), 503, issuerapi.CodeForbidden},
		"placement down":       {cloud(func(c *fakeCloud) { c.fail["allocations"] = down }), 503, issuerapi.CodeUnavailable},
		"nova forbids":         {cloud(func(c *fakeCloud) { c.fail["server"] = fmt.Errorf("%w: server", openstack.ErrForbidden) }), 503, issuerapi.CodeForbidden},
		"keystone down":        {cloud(func(c *fakeCloud) { c.fail["project"] = down }), 503, issuerapi.CodeUnavailable},
		"signer fails": {func(f *fixture, _ *issuerapi.BaremetalCertificateRequest) {
			f.Issuing = failingSigner{Signer: f.issuing.Key}
		}, 503, issuerapi.CodeUnavailable},
		"node not a UUID":       {func(_ *fixture, r *issuerapi.BaremetalCertificateRequest) { r.Node = "bm-1" }, 400, issuerapi.CodeInvalid},
		"instance not a UUID":   {func(_ *fixture, r *issuerapi.BaremetalCertificateRequest) { r.Instance = "" }, 400, issuerapi.CodeInvalid},
		"no EK":                 {func(_ *fixture, r *issuerapi.BaremetalCertificateRequest) { r.EKPublic = nil }, 400, issuerapi.CodeInvalid},
		"EK junk":               {func(_ *fixture, r *issuerapi.BaremetalCertificateRequest) { r.EKPublic = []byte("junk") }, 400, issuerapi.CodeInvalid},
		"no key":                {func(_ *fixture, r *issuerapi.BaremetalCertificateRequest) { r.KeyPublic = nil }, 400, issuerapi.CodeInvalid},
		"key is the EK":         {func(_ *fixture, r *issuerapi.BaremetalCertificateRequest) { r.KeyPublic = r.EKPublic }, 400, issuerapi.CodeInvalid},
		"key of the vm kind":    {func(_ *fixture, r *issuerapi.BaremetalCertificateRequest) { r.KeyPublic = tpm2.Marshal(vmKey) }, 400, issuerapi.CodeInvalid},
		"key without a point":   {func(_ *fixture, r *issuerapi.BaremetalCertificateRequest) { r.KeyPublic = tpm2.Marshal(unique) }, 400, issuerapi.CodeInvalid},
		"key that can be moved": {movable, 400, issuerapi.CodeInvalid},
	} {
		f := newFixture(t)
		req, ekHash := softwareRequest(t, nodeID, bmID)
		f.addBaremetal(nodeID, bmID, projectID, ekHash)
		if c.mod != nil {
			c.mod(f, req)
		}
		host := ""
		if name == "with a client cert" {
			host = "compute-1"
		}
		rec := f.call(http.MethodPost, issuerapi.PathBaremetalCertificate, host, mustJSON(t, req))
		if c.code != "" {
			wantError(t, name, rec, c.status, c.code)
			continue
		}
		var out issuerapi.BaremetalCertificateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK ||
			len(out.IDObject) == 0 || len(out.EncSecret) == 0 || len(out.Nonce) != 12 || len(out.Ciphertext) == 0 {
			t.Errorf("%s: status %d: %s", name, rec.Code, rec.Body)
		}
		// The certificate leaves the issuer only encrypted.
		if bytes.Contains(rec.Body.Bytes(), []byte(bmID)) {
			t.Errorf("%s: the answer names the instance in the clear", name)
		}
	}

	// The lookups stop at the first refusal, so an unknown EK reads nothing else.
	f := newFixture(t)
	req, _ := softwareRequest(t, nodeID, bmID)
	f.addBaremetal(nodeID, bmID, projectID, strings.Repeat("0", 64))
	wantError(t, "unknown EK", f.call(http.MethodPost, issuerapi.PathBaremetalCertificate, "", mustJSON(t, req)), 403, issuerapi.CodeRefused)
	if calls := f.cloud.called(); len(calls) != 1 || calls[0] != "ek "+nodeID {
		t.Errorf("lookups for an unknown EK: %q", calls)
	}

	// Strict JSON, and POST only.
	body := strings.Replace(string(mustJSON(t, req)), "{", `{"host":"compute-1",`, 1)
	wantError(t, "unknown member", f.call(http.MethodPost, issuerapi.PathBaremetalCertificate, "", []byte(body)), 400, issuerapi.CodeInvalid)
	if rec := f.call(http.MethodGet, issuerapi.PathBaremetalCertificate, "", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
}

// movable makes the request's key one the tenant could have imported, the template without fixedTPM.
func movable(_ *fixture, r *issuerapi.BaremetalCertificateRequest) {
	pub, _ := tpm2.Unmarshal[tpm2.TPMTPublic](r.KeyPublic)
	pub.ObjectAttributes.FixedTPM = false
	r.KeyPublic = tpm2.Marshal(pub)
}

// Ensures a clear authorization is signed only while the node is cleaning or deploying, and the clear key is served to anyone.
func TestBaremetalClear(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, 32)
	request := func(node string, nonce []byte) []byte {
		return mustJSON(t, issuerapi.ClearRequest{Node: node, Nonce: nonce})
	}

	// The provider's ramdisk runs in these states, and the tenant in no other.
	for state, ok := range map[string]bool{
		"cleaning": true, "clean wait": true, "deploying": true, "wait call-back": true,
		"active": false, "available": false, "manageable": false, "deploy failed": false, "clean failed": false,
		"rescue": false, "inspecting": false, "inspect wait": false, "enroll": false, "": false,
	} {
		f := newFixture(t)
		f.cloud.nodes[nodeID] = &openstack.Node{UUID: nodeID, ProvisionState: state}
		rec := f.call(http.MethodPost, issuerapi.PathBaremetalClear, "", request(nodeID, nonce))
		if !ok {
			wantError(t, "node "+state, rec, 403, issuerapi.CodeRefused)
			continue
		}
		var out issuerapi.ClearResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
			t.Errorf("node %s: status %d: %s", state, rec.Code, rec.Body)
			continue
		}
		// The signature is by the clear key over this nonce, the command TPM2_Clear and this node.
		b, _ := f.clearKey.PublicKey.Bytes()
		if !bytes.Equal(out.Key.X, b[1:33]) || !bytes.Equal(out.Key.Y, b[33:]) || len(out.R) != 32 || len(out.S) != 32 {
			t.Errorf("node %s: key %x %x", state, out.Key.X, out.Key.Y)
		}
		r, s := new(big.Int).SetBytes(out.R), new(big.Int).SetBytes(out.S)
		if !ecdsa.Verify(&f.clearKey.PublicKey, tpmprov.ClearDigest(nonce, nodeID), r, s) {
			t.Errorf("node %s: the signature does not verify", state)
		}
		if ecdsa.Verify(&f.clearKey.PublicKey, tpmprov.ClearDigest(bytes.Repeat([]byte{8}, 32), nodeID), r, s) {
			t.Errorf("node %s: the signature verifies for another nonce", state)
		}
		if ecdsa.Verify(&f.clearKey.PublicKey, tpmprov.ClearDigest(nonce, otherNode), r, s) {
			t.Errorf("node %s: the signature verifies for another node", state)
		}
	}

	down := errors.New("connection refused")
	for name, c := range map[string]struct {
		mod    func(f *fixture)
		body   []byte
		status int
		code   string
	}{
		"node not a UUID":     {nil, request("bm-1", nonce), 400, issuerapi.CodeInvalid},
		"no nonce":            {nil, request(nodeID, nil), 400, issuerapi.CodeInvalid},
		"short nonce":         {nil, request(nodeID, nonce[:15]), 400, issuerapi.CodeInvalid},
		"long nonce":          {nil, request(nodeID, bytes.Repeat(nonce, 3)), 400, issuerapi.CodeInvalid},
		"unknown member":      {nil, []byte(`{"node":"` + nodeID + `","nonce":"BwcHBwcHBwcHBwcHBwcHBw==","command":"TPM2_Clear"}`), 400, issuerapi.CodeInvalid},
		"not JSON":            {nil, []byte("clear"), 400, issuerapi.CodeInvalid},
		"unknown node":        {nil, request(otherNode, nonce), 403, issuerapi.CodeRefused},
		"ironic down":         {func(f *fixture) { f.cloud.fail["node"] = down }, request(nodeID, nonce), 503, issuerapi.CodeUnavailable},
		"ironic forbids":      {func(f *fixture) { f.cloud.fail["node"] = fmt.Errorf("%w: node", openstack.ErrForbidden) }, request(nodeID, nonce), 503, issuerapi.CodeForbidden},
		"signer fails":        {func(f *fixture) { f.ClearSigner = failingSigner{Signer: f.clearKey} }, request(nodeID, nonce), 503, issuerapi.CodeUnavailable},
		"malformed signature": {func(f *fixture) { f.ClearSigner = failingSigner{Signer: f.clearKey, sig: []byte("junk")} }, request(nodeID, nonce), 503, issuerapi.CodeUnavailable},
	} {
		f := newFixture(t)
		f.cloud.nodes[nodeID] = &openstack.Node{UUID: nodeID, ProvisionState: "clean wait"}
		if c.mod != nil {
			c.mod(f)
		}
		wantError(t, name, f.call(http.MethodPost, issuerapi.PathBaremetalClear, "", c.body), c.status, c.code)
	}
	f := newFixture(t)
	if rec := f.call(http.MethodGet, issuerapi.PathBaremetalClear, "", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}

	// The clear key is served without any lookup; e2e checks that deployed nodes lock to it.
	if rec := f.call(http.MethodGet, issuerapi.PathBaremetalClearKey, "", nil); rec.Code != http.StatusOK {
		t.Errorf("clear key: status %d: %s", rec.Code, rec.Body)
	}
	if calls := f.cloud.called(); len(calls) != 0 {
		t.Errorf("lookups for the clear key: %q", calls)
	}
	if rec := f.call(http.MethodPost, issuerapi.PathBaremetalClearKey, "", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST to the clear key: %d", rec.Code)
	}
}
