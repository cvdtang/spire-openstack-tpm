// Package issuer is the provider's issuer.
// It checks every request against the control plane before it signs, and keeps no records.
package issuer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"slices"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/issuerapi"
	"github.com/cvdtang/openstack-tpm/internal/openstack"
	"github.com/cvdtang/openstack-tpm/internal/tpmprov"
)

// Cloud is the control plane as the issuer reads it with its least-privilege identity.
type Cloud interface {
	// Allocations names the project that owns an instance and the resource providers it is placed on.
	Allocations(ctx context.Context, instance string) (*openstack.Allocations, error)
	// Server reads an instance from inside its project.
	Server(ctx context.Context, project, instance string) (*openstack.Server, error)
	// Actions lists an instance's actions, newest first, from inside its project.
	Actions(ctx context.Context, project, instance string) ([]openstack.InstanceAction, error)
	// Project reads a project from inside it.
	Project(ctx context.Context, project string) (*openstack.Project, error)
	// Node reads an Ironic node.
	Node(ctx context.Context, node string) (*openstack.Node, error)
	// NodeEK is the hash of the EK that inspection recorded for a node, or "" if there is none.
	NodeEK(ctx context.Context, node string) (string, error)
}

// Service serves the issuer's endpoints.
type Service struct {
	Region      string // the Keystone region ID, a claim of every certificate
	Cloud       Cloud
	IssuingCert *x509.Certificate // the issuing key's CA certificate
	Issuing     crypto.Signer     // its key (OpenBao Transit)
	ClearSigner crypto.Signer     // the provider's clear key, ECDSA P-256 (OpenBao Transit)
	Log         *slog.Logger
	Now         func() time.Time
}

// Handler routes the issuer's endpoints; only the VM endpoint requires a client certificate.
func (is *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+issuerapi.PathVMCertificate, is.serve("vm", "issued", is.vmCertificate))
	mux.HandleFunc("POST "+issuerapi.PathBaremetalCertificate, is.serve("baremetal", "issued", is.baremetalCertificate))
	mux.HandleFunc("POST "+issuerapi.PathBaremetalClear, is.serve("clear", "authorized", is.baremetalClear))
	mux.HandleFunc("GET "+issuerapi.PathBaremetalClearKey, is.serve("clear-key", "served", is.clearKey))
	return mux
}

// call is one request with the compute host that sent it, if any, and its log attributes.
type call struct {
	r     *http.Request
	host  string
	attrs []any
}

func (c *call) log(kv ...any) { c.attrs = append(c.attrs, kv...) }

// A handler returns the response body, DER for []byte and JSON otherwise.
type handler func(c *call) (any, error)

type httpError struct {
	status int
	code   string
	msg    string
}

func (e *httpError) Error() string { return e.code + ": " + e.msg }

func invalid(format string, a ...any) error {
	return &httpError{http.StatusBadRequest, issuerapi.CodeInvalid, fmt.Sprintf(format, a...)}
}

func refused(format string, a ...any) error {
	return &httpError{http.StatusForbidden, issuerapi.CodeRefused, fmt.Sprintf(format, a...)}
}

func unavailable(format string, a ...any) error {
	return &httpError{http.StatusServiceUnavailable, issuerapi.CodeUnavailable, fmt.Sprintf(format, a...)}
}

// serve wraps a handler and logs every decision, which is the issuer's audit trail.
func (is *Service) serve(kind, msg string, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &call{r: r, host: clientHost(r), attrs: []any{"request", kind, "remote", r.RemoteAddr}}
		if c.host != "" {
			c.log("host", c.host)
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		out, err := h(c)
		var body []byte
		var contentType string
		if err == nil {
			body, contentType, err = encode(out)
		}
		if err != nil {
			is.refuse(w, c, err)
			return
		}
		is.Log.Info(msg, c.attrs...)
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	}
}

// clientHost is the compute host named by the verified client certificate, never by the request, or "" without one.
func clientHost(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return ""
	}
	if names := r.TLS.VerifiedChains[0][0].DNSNames; len(names) == 1 {
		return names[0]
	}
	return ""
}

// encode returns a handler's response body, DER as is and anything else as JSON.
func encode(out any) (body []byte, contentType string, err error) {
	if der, ok := out.([]byte); ok {
		return der, "application/pkix-cert", nil
	}
	body, err = json.Marshal(out)
	return body, "application/json", err
}

// refuse logs a refusal and answers with its issuerapi.Error; an error that is not an httpError is an unavailable dependency.
func (is *Service) refuse(w http.ResponseWriter, c *call, err error) {
	var he *httpError
	if !errors.As(err, &he) {
		he = &httpError{http.StatusServiceUnavailable, issuerapi.CodeUnavailable, err.Error()}
	}
	is.Log.Warn("refused", append(c.attrs, "reason", he.code, "detail", he.msg)...)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(he.status)
	_ = json.NewEncoder(w).Encode(issuerapi.Error{Code: he.code, Message: he.msg})
}

// decode parses a JSON request without unknown members.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("%v", err)
	}
	return nil
}

// lookupError maps a control-plane error to a refusal.
// A 403 or a refused token is the issuer's own missing permission and must not look like a missing object.
func lookupError(what string, err error) error {
	switch {
	case errors.Is(err, openstack.ErrNotFound):
		return refused("%s not found", what)
	case errors.Is(err, openstack.ErrForbidden) || errors.Is(err, openstack.ErrAuth):
		return &httpError{http.StatusServiceUnavailable, issuerapi.CodeForbidden, fmt.Sprintf("%s: %v", what, err)}
	default:
		return unavailable("%s: %v", what, err)
	}
}

// instance is what the control plane says about an instance being built.
type instance struct {
	allocations *openstack.Allocations
	server      *openstack.Server
	project     *openstack.Project
}

// lookup reads an instance from Placement, then from Nova and Keystone inside its project.
func (is *Service) lookup(ctx context.Context, id string) (*instance, error) {
	al, err := is.Cloud.Allocations(ctx, id)
	if err != nil {
		return nil, lookupError("instance "+id, err)
	}
	s, err := is.Cloud.Server(ctx, al.ProjectID, id)
	if err != nil {
		return nil, lookupError("instance "+id, err)
	}
	if s.TenantID != al.ProjectID {
		return nil, refused("Nova's project %q is not Placement's %q", s.TenantID, al.ProjectID)
	}
	p, err := is.Cloud.Project(ctx, al.ProjectID)
	if err != nil {
		return nil, lookupError("project "+al.ProjectID, err)
	}
	return &instance{al, s, p}, nil
}

// sign issues the certificate of an instance's key with claims that never change for the instance.
func (is *Service) sign(c *call, i *instance, kind string, key *ecdsa.PublicKey) ([]byte, error) {
	cl := contract.Claims{
		Region: is.Region, DomainID: i.project.DomainID, ProjectID: i.server.TenantID, InstanceID: i.server.ID,
		Ancestors: i.project.Ancestors, Kind: kind, UserID: i.server.UserID,
	}
	if err := cl.Validate(); err != nil {
		return nil, refused("%v", err)
	}
	der, err := contract.Build(cl, key, is.Now(), is.IssuingCert, is.Issuing)
	if err != nil {
		return nil, unavailable("sign: %v", err)
	}
	hash, _ := contract.KeyHash(key)
	c.log("key_sha256", hash, "claims", cl.URI())
	return der, nil
}

// vmCertificate is POST /v1/vm/certificates.
func (is *Service) vmCertificate(c *call) (any, error) {
	if c.host == "" {
		return nil, refused("no client certificate of a compute host")
	}
	var req issuerapi.VMCertificateRequest
	if err := decode(c.r, &req); err != nil {
		return nil, err
	}
	c.log("instance_uuid", req.InstanceUUID)
	if !contract.ValidUUID(req.InstanceUUID) {
		return nil, invalid("instance_uuid is not a canonical UUID")
	}
	key, err := contract.ParsePoint(req.Key)
	if err != nil {
		return nil, invalid("key: %v", err)
	}
	i, err := is.lookup(c.r.Context(), req.InstanceUUID)
	if err != nil {
		return nil, err
	}
	s := i.server
	if s.Host != c.host {
		return nil, refused("instance host %q is not the caller %q", s.Host, c.host)
	}
	if err := s.VTPMFlavor(); err != nil {
		return nil, refused("%v", err)
	}
	event, err := is.vtpmCreation(c.r.Context(), s)
	if err != nil {
		return nil, err
	}
	c.log("event", event)
	return is.sign(c, i, contract.KindVM, key)
}

// vtpmCreation reports why libvirt creates the instance's vTPM now, refusing anything but a build, a resize or the first start after one.
func (is *Service) vtpmCreation(ctx context.Context, s *openstack.Server) (string, error) {
	switch s.State() {
	case "building/spawning":
		return "build", nil
	case "active/resize_finish":
		// A cold migration also ends in resize_finish but moves the vTPM, so the operation must be a resize.
		acts, err := is.actions(ctx, s)
		if err != nil {
			return "", err
		}
		if acts[0].Action != "resize" {
			return "", refused("instance is finishing a %s, want a resize", acts[0].Action)
		}
		return "resize", nil
	case "stopped/powering-on":
		return is.firstStartAfterResize(ctx, s, "start")
	case "stopped/reboot_started_hard":
		return is.firstStartAfterResize(ctx, s, "reboot")
	}
	return "", refused("instance is %s, want building/spawning, active/resize_finish or the first start after a resize", s.State())
}

// firstStartAfterResize checks that a stopped instance is started for the first time since a resize, when libvirt creates its vTPM.
// Only a confirmation and failed operations may lie between the resize and this start.
func (is *Service) firstStartAfterResize(ctx context.Context, s *openstack.Server, action string) (string, error) {
	acts, err := is.actions(ctx, s)
	if err != nil {
		return "", err
	}
	if acts[0].Action != action {
		return "", refused("instance is %s for a %s", s.State(), acts[0].Action)
	}
	for _, a := range acts[1:] {
		if a.Failed() || a.Action == "confirmResize" {
			continue
		}
		if a.Action == "resize" {
			return "first-start-after-resize", nil
		}
		return "", refused("instance is %s, want the first start after a resize; found a %s before it", s.State(), a.Action)
	}
	return "", refused("instance is %s, want the first start after a resize; found none", s.State())
}

// actions reads the instance's actions, newest first, so the first is the one in progress.
func (is *Service) actions(ctx context.Context, s *openstack.Server) ([]openstack.InstanceAction, error) {
	acts, err := is.Cloud.Actions(ctx, s.TenantID, s.ID)
	if err != nil {
		return nil, lookupError("actions of instance "+s.ID, err)
	}
	if len(acts) == 0 {
		return nil, refused("instance %s has no actions", s.ID)
	}
	return acts, nil
}

// deploying and cleaning report Ironic's provision states while the provider's ramdisk runs, including the wait states of in-band steps.
func deploying(state string) bool { return state == "deploying" || state == "wait call-back" }
func cleaning(state string) bool  { return state == "cleaning" || state == "clean wait" }

// baremetalCertificate is POST /v1/baremetal/certificates.
func (is *Service) baremetalCertificate(c *call) (any, error) {
	ctx := c.r.Context()
	var req issuerapi.BaremetalCertificateRequest
	if err := decode(c.r, &req); err != nil {
		return nil, err
	}
	c.log("node", req.Node, "instance_uuid", req.Instance)
	if !contract.ValidUUID(req.Node) || !contract.ValidUUID(req.Instance) {
		return nil, invalid("node and instance must be canonical UUIDs")
	}
	ekPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](req.EKPublic)
	if err != nil {
		return nil, invalid("ek_public: %v", err)
	}
	ekHash, err := tpmprov.EKHash(ekPub)
	if err != nil {
		return nil, invalid("ek_public: %v", err)
	}
	c.log("ek_sha256", ekHash)
	// The key must be exactly the bare-metal template, since the credential is bound to its name.
	keyPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](req.KeyPublic)
	if err != nil {
		return nil, invalid("key_public: %v", err)
	}
	key, keyName, err := templateKey(keyPub)
	if err != nil {
		return nil, invalid("key_public: %v", err)
	}

	if err := is.nodeDeploying(ctx, req.Node, req.Instance, ekHash); err != nil {
		return nil, err
	}
	// Placement and Nova must show the instance being built or rebuilt on this node.
	i, err := is.lookup(ctx, req.Instance)
	if err != nil {
		return nil, err
	}
	s := i.server
	switch {
	case !slices.Contains(i.allocations.Providers, req.Node):
		return nil, refused("the instance's allocation is not on node %s", req.Node)
	case s.Node != req.Node:
		return nil, refused("Nova places the instance on %q", s.Node)
	case s.State() != "building/spawning" && s.Task() != "rebuild_spawning":
		return nil, refused("instance is %s, want building/spawning or a rebuild", s.State())
	}

	der, err := is.sign(c, i, contract.KindBaremetal, key)
	if err != nil {
		return nil, err
	}
	return tpmprov.SealCertificate(ekPub, keyName, der)
}

// nodeDeploying checks that the EK is the one inspection recorded and that Ironic is deploying the instance on the node.
func (is *Service) nodeDeploying(ctx context.Context, nodeID, instance, ekHash string) error {
	recorded, err := is.Cloud.NodeEK(ctx, nodeID)
	switch {
	case err != nil:
		return lookupError("inspection data of node "+nodeID, err)
	case recorded == "":
		return refused("node %s has no recorded EK; inspect it with the collector", nodeID)
	case recorded != ekHash:
		return refused("the EK is not the one recorded for node %s", nodeID)
	}
	node, err := is.Cloud.Node(ctx, nodeID)
	switch {
	case err != nil:
		return lookupError("node "+nodeID, err)
	case !deploying(node.ProvisionState):
		return refused("node is %q, not deploying", node.ProvisionState)
	case node.Maintenance:
		return refused("node is in maintenance")
	case node.InstanceUUID != instance:
		return refused("node is deploying instance %q", node.InstanceUUID)
	}
	return nil
}

// templateKey checks that a public area is the bare-metal template and returns its point and name.
func templateKey(pub *tpm2.TPMTPublic) (*ecdsa.PublicKey, []byte, error) {
	k, err := contract.PublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	key, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("not an ECC key")
	}
	want, err := contract.KeyPublic(contract.KindBaremetal, key)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(tpm2.Marshal(want), tpm2.Marshal(pub)) {
		return nil, nil, errors.New("not the bare-metal key template")
	}
	name, err := tpm2.ObjectName(&want)
	if err != nil {
		return nil, nil, err
	}
	return key, name.Buffer, nil
}

// baremetalClear is POST /v1/baremetal/clear.
func (is *Service) baremetalClear(c *call) (any, error) {
	var req issuerapi.ClearRequest
	if err := decode(c.r, &req); err != nil {
		return nil, err
	}
	c.log("node", req.Node)
	if !contract.ValidUUID(req.Node) || len(req.Nonce) < 16 || len(req.Nonce) > 64 {
		return nil, invalid("node must be a canonical UUID and nonce 16 to 64 bytes")
	}
	// The node must be in the provider's hands, cleaning or deploying before the tenant's image boots.
	node, err := is.Cloud.Node(c.r.Context(), req.Node)
	if err != nil {
		return nil, lookupError("node "+req.Node, err)
	}
	c.log("provision_state", node.ProvisionState)
	if !cleaning(node.ProvisionState) && !deploying(node.ProvisionState) {
		return nil, refused("node is %q, not cleaning or deploying", node.ProvisionState)
	}
	sig, err := is.ClearSigner.Sign(rand.Reader, tpmprov.ClearDigest(req.Nonce, req.Node), crypto.SHA256)
	if err != nil {
		return nil, unavailable("sign: %v", err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		return nil, unavailable("the clear key returned a malformed signature")
	}
	return issuerapi.ClearResponse{Key: is.clearPublic(), R: rs.R.FillBytes(make([]byte, 32)), S: rs.S.FillBytes(make([]byte, 32))}, nil
}

// clearKey is GET /v1/baremetal/clear-key, the public clear key the deploy step puts into the lockout policy.
func (is *Service) clearKey(*call) (any, error) { return is.clearPublic(), nil }

func (is *Service) clearPublic() issuerapi.ClearKey {
	b, _ := is.ClearSigner.Public().(*ecdsa.PublicKey).Bytes() // 0x04 || X || Y; P-256, checked at start
	return issuerapi.ClearKey{X: b[1:33], Y: b[33:]}
}
