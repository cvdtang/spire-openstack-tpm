// Package openstack is the read-only view of Keystone, Nova, Placement and Ironic that the issuer and the server plugin need, on gophercloud.
package openstack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	gcopenstack "github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/instanceactions"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/v2/openstack/placement/v1/allocations"
)

// Error kinds; every error from a lookup wraps at most one of them.
var (
	// ErrNotFound is a 404, or a server Nova reports as deleted.
	ErrNotFound = errors.New("not found")
	// ErrForbidden is a 403 on a lookup, from a missing role or policy rule or, for a tenant, an object it cannot see.
	ErrForbidden = errors.New("forbidden")
	// ErrAuth means Keystone refused a token (401 or 403), from a wrong credential or no role on the scope.
	ErrAuth = errors.New("keystone refused a token")
	// ErrNoEndpoint means the token's catalog has no endpoint for a service in the configured region and interface.
	ErrNoEndpoint = errors.New("no endpoint in the catalog")
)

// Service types in the Keystone catalog.
const (
	Identity  = "identity"
	Compute   = "compute"
	Placement = "placement"
	Baremetal = "baremetal"
)

// ComputeMicroversion is the Nova API version of server lookups, the first that embeds the flavor's extra specs.
const ComputeMicroversion = "2.47"

// microversions are the API versions requested per service; Placement 1.38 names the consumer's project and Ironic 1.81 has the inventory API.
var microversions = map[string]string{Compute: ComputeMicroversion, Placement: "1.38", Baremetal: "1.81"}

// API is the Nova and Keystone lookups that the server plugin needs.
type API interface {
	GetServer(ctx context.Context, id string) (*Server, error)
	GetProject(ctx context.Context, id string) (*Project, error)
}

// Credentials authenticate one Keystone principal.
type Credentials struct {
	AuthURL string // .../v3
	// Password auth, scoped to ProjectID or else ProjectName; both domains default to "Default".
	Username, Password, UserDomainName        string
	ProjectName, ProjectID, ProjectDomainName string
	// Application credential auth (scope is fixed by the credential).
	AppCredID, AppCredSecret string
}

// Endpoints selects the catalog endpoints by Keystone region ID and interface (public, internal or admin).
type Endpoints struct {
	Region, Interface string
}

// Client authenticates one principal at its first lookup and keeps the token, which gophercloud renews on a 401.
type Client struct {
	creds     Credentials
	endpoints Endpoints
	timeout   time.Duration

	mu       sync.Mutex                  // serialises the first authentication
	provider *gophercloud.ProviderClient // nil until authenticated
	project  string                      // the project the token is scoped to
	services map[string]*gophercloud.ServiceClient
}

// New returns a client for creds that finds services in its token's catalog by ep, with a request timeout.
func New(creds Credentials, ep Endpoints, timeout time.Duration) *Client {
	return &Client{creds: creds, endpoints: ep, timeout: timeout}
}

// WithProject returns a client with its own token for the same user scoped to another project.
func (c *Client) WithProject(projectID string) *Client {
	creds := c.creds
	creds.ProjectID = projectID
	return New(creds, c.endpoints, c.timeout)
}

// WithRegion returns a client with its own token for the same principal and scope in another region.
func (c *Client) WithRegion(region string) *Client {
	ep := c.endpoints
	ep.Region = region
	return New(c.creds, ep, c.timeout)
}

func orDefault(s string) string {
	if s == "" {
		return "Default"
	}
	return s
}

func (c *Client) authOptions() *gophercloud.AuthOptions {
	cr := c.creds
	if cr.AppCredID != "" {
		return &gophercloud.AuthOptions{
			IdentityEndpoint:        cr.AuthURL,
			ApplicationCredentialID: cr.AppCredID, ApplicationCredentialSecret: cr.AppCredSecret,
			AllowReauth: true,
		}
	}
	o := &gophercloud.AuthOptions{
		IdentityEndpoint: cr.AuthURL,
		Username:         cr.Username, Password: cr.Password, DomainName: orDefault(cr.UserDomainName),
		AllowReauth: true,
	}
	switch {
	case cr.ProjectID != "":
		o.Scope = &gophercloud.AuthScope{ProjectID: cr.ProjectID}
	case cr.ProjectName != "":
		o.Scope = &gophercloud.AuthScope{ProjectName: cr.ProjectName, DomainName: orDefault(cr.ProjectDomainName)}
	}
	return o
}

// authenticated returns the provider client, authenticating at the first call and again after a failure.
func (c *Client) authenticated(ctx context.Context) (*gophercloud.ProviderClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.provider, nil
	}
	p, err := gcopenstack.NewClient(c.creds.AuthURL)
	if err != nil {
		return nil, err
	}
	p.HTTPClient = http.Client{Timeout: c.timeout}
	if err := gcopenstack.AuthenticateV3(ctx, p, c.authOptions(), gophercloud.EndpointOpts{}); err != nil {
		return nil, authError(err)
	}
	if p.Token() == "" {
		return nil, errors.New("keystone auth: no X-Subject-Token")
	}
	if r, ok := p.GetAuthResult().(tokens.CreateResult); ok {
		project, err := r.ExtractProject()
		if err != nil {
			return nil, fmt.Errorf("keystone auth response: %w", err)
		}
		if project != nil {
			c.project = project.ID
		}
	}
	c.provider, c.services = p, map[string]*gophercloud.ServiceClient{}
	return p, nil
}

// ProjectID is the project the client's token is scoped to, which an application credential fixes.
func (c *Client) ProjectID(ctx context.Context) (string, error) {
	if _, err := c.authenticated(ctx); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.project, nil
}

// service is the client of a catalog service in the configured region and interface, at the API version requested from it.
// Catalog URLs are used without version discovery; Nova's gets /v2.1 and Ironic's /v1 when they have no version.
func (c *Client) service(ctx context.Context, typ string) (*gophercloud.ServiceClient, error) {
	p, err := c.authenticated(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if sc, ok := c.services[typ]; ok {
		return sc, nil
	}
	ep := c.endpoints
	u, err := p.EndpointLocator(gophercloud.EndpointOpts{Type: typ, Region: ep.Region, Availability: gophercloud.Availability(ep.Interface)})
	if err != nil {
		return nil, fmt.Errorf("%w: %s in region %q, interface %q", ErrNoEndpoint, typ, ep.Region, ep.Interface)
	}
	sc := &gophercloud.ServiceClient{ProviderClient: p, Endpoint: u, Type: typ, Microversion: microversions[typ]}
	switch {
	case typ == Compute && !strings.Contains(u, "/v2"):
		sc.ResourceBase = u + "v2.1/"
	case typ == Baremetal && !strings.HasSuffix(u, "/v1/"):
		sc.ResourceBase = u + "v1/"
	}
	c.services[typ] = sc
	return sc, nil
}

// identity is Keystone at the auth URL.
func (c *Client) identity(ctx context.Context) (*gophercloud.ServiceClient, error) {
	p, err := c.authenticated(ctx)
	if err != nil {
		return nil, err
	}
	return &gophercloud.ServiceClient{ProviderClient: p, Endpoint: p.IdentityEndpoint, Type: Identity}, nil
}

// authError is a failed token request, ErrAuth when Keystone refused it.
func authError(err error) error {
	if code := statusCode(err); code == http.StatusUnauthorized || code == http.StatusForbidden {
		return fmt.Errorf("%w: %w", ErrAuth, err)
	}
	return fmt.Errorf("keystone: %w", err)
}

// lookupError reduces a gophercloud error to the kinds of this package.
// An expired or revoked token is replaced once, and Keystone refusing the new one is the error.
func lookupError(err error) error {
	if reauth, ok := errors.AsType[*gophercloud.ErrUnableToReauthenticate](err); ok {
		return authError(reauth.ErrReauth)
	}
	switch statusCode(err) {
	case http.StatusNotFound:
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case http.StatusForbidden:
		return fmt.Errorf("%w: %w", ErrForbidden, err)
	}
	return err
}

// statusCode is the HTTP status of a gophercloud response error, or 0 for any other error.
func statusCode(err error) int {
	var e interface{ GetStatusCode() int }
	if errors.As(err, &e) {
		return e.GetStatusCode()
	}
	return 0
}

// Server holds the fields of GET /servers/{id} that this package reads; admin-only fields are empty for tenant tokens.
type Server struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Status   string    `json:"status"`
	TenantID string    `json:"tenant_id"`
	UserID   string    `json:"user_id"`
	Created  time.Time `json:"created"`
	AZ       string    `json:"OS-EXT-AZ:availability_zone"`
	Host     string    `json:"OS-EXT-SRV-ATTR:host"`
	// Node is the hypervisor host name, which for a bare-metal instance is the Ironic node's UUID.
	Node      string          `json:"OS-EXT-SRV-ATTR:hypervisor_hostname"`
	VMState   string          `json:"OS-EXT-STS:vm_state"`
	TaskState *string         `json:"OS-EXT-STS:task_state"`
	Image     json.RawMessage `json:"image"` // {"id":...} or "" (boot from volume)
	Tags      []string        `json:"tags"`
	Flavor    struct {
		OriginalName string            `json:"original_name"`
		ExtraSpecs   map[string]string `json:"extra_specs"`
	} `json:"flavor"`
}

// Task is the task state, "" for none.
func (s *Server) Task() string {
	if s.TaskState == nil {
		return ""
	}
	return *s.TaskState
}

// State is "<vm_state>/<task_state>", such as building/spawning.
func (s *Server) State() string { return s.VMState + "/" + s.Task() }

// ImageID is the instance's image, or "" when it boots from volume.
func (s *Server) ImageID() string {
	var img struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(s.Image, &img) == nil {
		return img.ID
	}
	return ""
}

// VTPMFlavor checks that the embedded flavor is TPM 2.0 with a host secret.
func (s *Server) VTPMFlavor() error {
	if v := s.Flavor.ExtraSpecs["hw:tpm_version"]; v != "2.0" {
		return fmt.Errorf("flavor hw:tpm_version=%q, want 2.0", v)
	}
	if v := s.Flavor.ExtraSpecs["hw:tpm_secret_security"]; v != "host" {
		return fmt.Errorf("flavor hw:tpm_secret_security=%q, want host", v)
	}
	return nil
}

// GetServer fetches one instance from Nova; a deleted instance is ErrNotFound.
func (c *Client) GetServer(ctx context.Context, id string) (*Server, error) {
	sc, err := c.service(ctx, Compute)
	if err != nil {
		return nil, err
	}
	var s Server
	if err := servers.Get(ctx, sc, id).ExtractInto(&s); err != nil {
		return nil, lookupError(err)
	}
	if s.Status == "DELETED" || s.Status == "SOFT_DELETED" {
		return nil, fmt.Errorf("%w: server %s is %s", ErrNotFound, id, s.Status)
	}
	return &s, nil
}

// InstanceAction is one API operation on an instance, from GET /servers/{id}/os-instance-actions.
type InstanceAction struct {
	Action    string
	RequestID string
	UserID    string
	// Message is "Error" once the operation failed and empty otherwise.
	Message   string
	StartTime time.Time
}

// Failed reports whether the operation failed.
func (a InstanceAction) Failed() bool { return a.Message != "" }

// GetInstanceActions lists an instance's actions, newest first.
func (c *Client) GetInstanceActions(ctx context.Context, id string) ([]InstanceAction, error) {
	sc, err := c.service(ctx, Compute)
	if err != nil {
		return nil, err
	}
	pages, err := instanceactions.List(sc, id, nil).AllPages(ctx)
	if err != nil {
		return nil, lookupError(err)
	}
	all, err := instanceactions.ExtractInstanceActions(pages)
	if err != nil {
		return nil, err
	}
	acts := make([]InstanceAction, len(all))
	for i, a := range all {
		acts[i] = InstanceAction{Action: a.Action, RequestID: a.RequestID, UserID: a.UserID, Message: a.Message, StartTime: a.StartTime}
	}
	// Nova sorts them newest first; do not rely on it.
	slices.SortStableFunc(acts, func(a, b InstanceAction) int { return b.StartTime.Compare(a.StartTime) })
	return acts, nil
}

// Project holds the fields of a Keystone project that this package reads; Ancestors are the projects above it, root first, without the domain.
type Project struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	DomainID  string          `json:"domain_id"`
	ParentID  string          `json:"parent_id"`
	Tags      []string        `json:"tags"`
	Parents   json.RawMessage `json:"parents"`
	Ancestors []string        `json:"-"`
}

// GetProject fetches one Keystone project with its ancestors in one request.
func (c *Client) GetProject(ctx context.Context, id string) (*Project, error) {
	sc, err := c.identity(ctx)
	if err != nil {
		return nil, err
	}
	var out struct {
		Project Project `json:"project"`
	}
	if _, err := sc.Get(ctx, sc.ServiceURL("projects", id)+"?parents_as_ids", &out, nil); err != nil {
		return nil, lookupError(err)
	}
	p := &out.Project
	if p.Ancestors, err = ancestors(p); err != nil {
		return nil, fmt.Errorf("keystone project %s: %w", id, err)
	}
	return p, nil
}

// ancestors flattens Keystone's nested parents_as_ids into the chain root first, without the domain.
// The chain must start at the project's parent and end at its domain.
func ancestors(p *Project) ([]string, error) {
	if len(p.Parents) == 0 {
		return nil, errors.New("no parents in the answer")
	}
	var up []string // parent first
	for cur := p.Parents; ; {
		var level map[string]json.RawMessage
		if err := json.Unmarshal(cur, &level); err != nil {
			return nil, fmt.Errorf("parents: %w", err)
		}
		if level == nil {
			break
		}
		if len(level) != 1 {
			return nil, fmt.Errorf("parents: %d projects at one level, want 1", len(level))
		}
		for id, next := range level {
			if slices.Contains(up, id) {
				return nil, fmt.Errorf("parents: %s repeats", id)
			}
			up, cur = append(up, id), next
		}
	}
	if len(up) == 0 || up[0] != p.ParentID || up[len(up)-1] != p.DomainID {
		return nil, fmt.Errorf("parents %v: want the chain from parent %q to domain %q", up, p.ParentID, p.DomainID)
	}
	if len(up) == 1 {
		return nil, nil // a top-level project
	}
	up = up[:len(up)-1]
	slices.Reverse(up)
	return up, nil
}

// Scoped takes one user's tokens scoped to each project it is asked about, typically with a role inherited from the domain.
// Nova limits non-admin lookups to the token's project, so this reads servers across projects without admin.
type Scoped struct {
	base *Client

	mu       sync.Mutex
	projects map[string]*Client // token cache per project
}

// NewScoped returns a Scoped for base's user and endpoints.
func NewScoped(base *Client) *Scoped {
	return &Scoped{base: base, projects: map[string]*Client{}}
}

// Base is the client Scoped was created with.
func (s *Scoped) Base() *Client { return s.base }

// Project returns the client scoped to project id.
func (s *Scoped) Project(id string) *Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.projects[id]
	if !ok {
		c = s.base.WithProject(id)
		s.projects[id] = c
	}
	return c
}

// Allocations is the project a Placement consumer belongs to and the resource providers it holds allocations on.
type Allocations struct {
	ProjectID string
	Providers []string // resource provider UUIDs
}

// GetAllocations reads a consumer's allocations from Placement; for bare metal the provider is the Ironic node.
func (c *Client) GetAllocations(ctx context.Context, consumer string) (*Allocations, error) {
	sc, err := c.service(ctx, Placement)
	if err != nil {
		return nil, err
	}
	al, err := allocations.Get(ctx, sc, consumer).Extract()
	if err != nil {
		return nil, lookupError(err)
	}
	if al.ProjectID == nil || *al.ProjectID == "" {
		return nil, fmt.Errorf("%w: no allocations for %s", ErrNotFound, consumer)
	}
	return &Allocations{ProjectID: *al.ProjectID, Providers: slices.Collect(maps.Keys(al.Allocations))}, nil
}

// Node holds the fields of Ironic's GET /v1/nodes/{uuid} that this package reads.
type Node struct {
	UUID           string `json:"uuid"`
	ProvisionState string `json:"provision_state"`
	InstanceUUID   string `json:"instance_uuid"`
	Maintenance    bool   `json:"maintenance"`
}

// GetNode fetches one node from the Ironic endpoint in the token's catalog.
func (c *Client) GetNode(ctx context.Context, id string) (*Node, error) {
	sc, err := c.service(ctx, Baremetal)
	if err != nil {
		return nil, err
	}
	var n Node
	if err := nodes.Get(ctx, sc, id).ExtractInto(&n); err != nil {
		return nil, lookupError(err)
	}
	return &n, nil
}

// GetNodePluginData fetches what the inspection collectors reported for a node besides its inventory.
func (c *Client) GetNodePluginData(ctx context.Context, id string) (map[string]json.RawMessage, error) {
	sc, err := c.service(ctx, Baremetal)
	if err != nil {
		return nil, err
	}
	var out struct {
		PluginData map[string]json.RawMessage `json:"plugin_data"`
	}
	if err := nodes.GetInventory(ctx, sc, id).ExtractInto(&out); err != nil {
		return nil, lookupError(err)
	}
	return out.PluginData, nil
}
