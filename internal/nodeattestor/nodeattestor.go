// Package nodeattestor is the attestation logic of the openstack_tpm SPIRE Server plugin.
// It checks the certificate and allowlists before any TPM work, and builds selectors from the claims and optionally Nova and Keystone.
package nodeattestor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hashicorp/hcl"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/openstack"
)

// Error kinds. Every error from Verify and Selectors wraps one of them.
var (
	// ErrRefused is a policy refusal (permission denied).
	ErrRefused = errors.New("refused")
	// ErrMismatch is a refusal where Nova or Keystone contradicts a valid certificate.
	ErrMismatch = errors.New("mismatch")
	// ErrUnavailable means Nova or Keystone could not be asked or refused the credential; the agent retries.
	ErrUnavailable = errors.New("unavailable")
)

// Wildcard in domains accepts every domain the bundle covers.
const Wildcard = "*"

// Credential is an application credential, serving its own project, or a user, serving every project it can get a token for.
type Credential struct {
	AppCredID         string `hcl:"application_credential_id"`
	AppCredSecretFile string `hcl:"application_credential_secret_file"`
	Username          string `hcl:"username"`
	UserDomainName    string `hcl:"user_domain_name"`
	PasswordFile      string `hcl:"password_file"`
}

func (c Credential) validate() error {
	app := c.AppCredID != "" || c.AppCredSecretFile != ""
	user := c.Username != "" || c.PasswordFile != "" || c.UserDomainName != ""
	switch {
	case app && user:
		return errors.New("an application credential or a user, not both")
	case app && (c.AppCredID == "" || c.AppCredSecretFile == ""):
		return errors.New("application_credential_id and application_credential_secret_file go together")
	case user && (c.Username == "" || c.PasswordFile == ""):
		return errors.New("username and password_file go together")
	case !app && !user:
		return errors.New("empty credential")
	}
	return nil
}

func (c Credential) secretFile() string {
	if c.AppCredID != "" {
		return c.AppCredSecretFile
	}
	return c.PasswordFile
}

// OpenStackConfig is where and as whom the server reads Nova and Keystone.
type OpenStackConfig struct {
	AuthURL     string       `hcl:"auth_url"`
	Credentials []Credential `hcl:"credentials"`
}

// Config is the plugin's HCL configuration.
type Config struct {
	CABundle          string           `hcl:"ca_bundle"`
	Projects          []string         `hcl:"projects"`
	Domains           []string         `hcl:"domains"`
	NovaSelectors     bool             `hcl:"nova_selectors"`
	KeystoneSelectors bool             `hcl:"keystone_selectors"`
	OpenStack         *OpenStackConfig `hcl:"openstack"`
}

// ParseConfig decodes and validates the HCL configuration without reading any file.
func ParseConfig(hclConfig string) (*Config, error) {
	cfg := &Config{}
	if err := hcl.Decode(cfg, hclConfig); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.CABundle == "" {
		return nil, errors.New("ca_bundle is required")
	}
	if len(cfg.Projects) == 0 && len(cfg.Domains) == 0 {
		return nil, errors.New("projects or domains is required: list the projects or domains whose instances may attest")
	}
	for _, p := range cfg.Projects {
		if p == "" || p == Wildcard {
			return nil, fmt.Errorf(`projects: %q is not a project ID (domains = ["*"] accepts every project)`, p)
		}
	}
	if slices.Contains(cfg.Domains, "") {
		return nil, errors.New("domains: empty domain ID")
	}
	reads := cfg.NovaSelectors || cfg.KeystoneSelectors
	switch {
	case reads && cfg.OpenStack == nil:
		return nil, errors.New("nova_selectors and keystone_selectors need an openstack block with credentials")
	case !reads && cfg.OpenStack != nil:
		return nil, errors.New("an openstack block without nova_selectors or keystone_selectors holds credentials that nothing uses")
	}
	if osc := cfg.OpenStack; osc != nil {
		if osc.AuthURL == "" {
			return nil, errors.New("openstack: auth_url is required")
		}
		if len(osc.Credentials) == 0 {
			return nil, errors.New("openstack: credentials is required")
		}
		for i := range osc.Credentials {
			c := &osc.Credentials[i]
			if err := c.validate(); err != nil {
				return nil, fmt.Errorf("openstack: credentials[%d]: %w", i, err)
			}
			if c.Username != "" && c.UserDomainName == "" {
				c.UserDomainName = "Default"
			}
		}
	}
	return cfg, nil
}

// Check reads the bundle and every secret file the configuration names.
func (cfg *Config) Check() error {
	if _, err := contract.LoadBundle(cfg.CABundle); err != nil {
		return fmt.Errorf("ca_bundle: %w", err)
	}
	if cfg.OpenStack != nil {
		for i, c := range cfg.OpenStack.Credentials {
			if _, err := readSecret(c.secretFile()); err != nil {
				return fmt.Errorf("openstack: credentials[%d]: %w", i, err)
			}
		}
	}
	return nil
}

func readSecret(file string) (string, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", file)
	}
	return s, nil
}

// Clouds gives the OpenStack view for an instance's project and region.
type Clouds interface {
	// For returns the client for project in region, or an error wrapping ErrRefused or ErrUnavailable.
	For(ctx context.Context, project, region string) (openstack.API, error)
}

// credential is a configured credential and its base client.
type credential struct {
	cfg    Credential
	client *openstack.Client // scoped for an application credential, an unscoped template for a user

	mu      sync.Mutex
	project string // an application credential's project, once known
}

// projectID is an application credential's project, learned when it first authenticates.
func (cr *credential) projectID(ctx context.Context) (string, error) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if cr.project == "" {
		p, err := cr.client.ProjectID(ctx)
		if err != nil {
			return "", err
		}
		cr.project = p
	}
	return cr.project, nil
}

// configClouds picks a project's application credential if there is one, else the first user credential.
type configClouds struct {
	creds []*credential

	mu     sync.Mutex
	scoped map[scope]openstack.API // client with its own token
}

// scope identifies a cached client by credential index, project and region.
type scope struct {
	cred            int
	project, region string
}

// requestTimeout limits one request to Nova or Keystone.
var requestTimeout = 5 * time.Second

func newClouds(cfg *Config) (*configClouds, error) {
	c := &configClouds{scoped: map[scope]openstack.API{}}
	if cfg.OpenStack == nil {
		return c, nil
	}
	for i, cc := range cfg.OpenStack.Credentials {
		secret, err := readSecret(cc.secretFile())
		if err != nil {
			return nil, fmt.Errorf("openstack: credentials[%d]: %w", i, err)
		}
		creds := openstack.Credentials{AuthURL: cfg.OpenStack.AuthURL}
		if cc.AppCredID != "" {
			creds.AppCredID, creds.AppCredSecret = cc.AppCredID, secret
		} else {
			creds.Username, creds.Password, creds.UserDomainName = cc.Username, secret, cc.UserDomainName
		}
		c.creds = append(c.creds, &credential{cfg: cc,
			client: openstack.New(creds, openstack.Endpoints{Interface: "public"}, requestTimeout)})
	}
	return c, nil
}

func (c *configClouds) For(ctx context.Context, project, region string) (openstack.API, error) {
	var unavailable error
	for i, cr := range c.creds {
		if cr.cfg.AppCredID == "" {
			continue
		}
		p, err := cr.projectID(ctx)
		if err != nil {
			unavailable = fmt.Errorf("%w: keystone refused or did not answer for application credential %s: %w", ErrUnavailable, cr.cfg.AppCredID, err)
			continue
		}
		if p == project {
			return c.client(scope{i, project, region}, func() *openstack.Client { return cr.client.WithRegion(region) }), nil
		}
	}
	for i, cr := range c.creds {
		if cr.cfg.Username != "" {
			return c.client(scope{i, project, region}, func() *openstack.Client { return cr.client.WithProject(project).WithRegion(region) }), nil
		}
	}
	if unavailable != nil {
		return nil, unavailable
	}
	return nil, fmt.Errorf("%w: no configured credential serves project %s", ErrRefused, project)
}

// client returns the cached client of a scope, made by mk the first time.
func (c *configClouds) client(sc scope, mk func() *openstack.Client) openstack.API {
	c.mu.Lock()
	defer c.mu.Unlock()
	cl, ok := c.scoped[sc]
	if !ok {
		cl = mk()
		c.scoped[sc] = cl
	}
	return cl
}

// Attestor verifies certificates and builds selectors.
type Attestor struct {
	cfg    *Config
	bundle *contract.Bundle
	clouds Clouds
}

// New loads the bundle; a nil clouds builds clients from the configured credentials.
func New(cfg *Config, clouds Clouds) (*Attestor, error) {
	bundle, err := contract.LoadBundle(cfg.CABundle)
	if err != nil {
		return nil, fmt.Errorf("ca_bundle: %w", err)
	}
	if clouds == nil {
		if clouds, err = newClouds(cfg); err != nil {
			return nil, err
		}
	}
	return &Attestor{cfg: cfg, bundle: bundle, clouds: clouds}, nil
}

// allowed reports whether the claims' project or domain is on an allowlist.
func (a *Attestor) allowed(c contract.Claims) bool {
	return slices.Contains(a.cfg.Projects, c.ProjectID) ||
		slices.Contains(a.cfg.Domains, c.DomainID) || slices.Contains(a.cfg.Domains, Wildcard)
}

// AgentPath is the agent ID path after /spire/agent/openstack_tpm/, from the verified claims.
func AgentPath(v *contract.Verified) string {
	return v.Claims.Region + "/" + v.Claims.ProjectID + "/" + v.Claims.InstanceID
}

// Verify checks the chain, the claims and the allowlists, before any TPM or API work.
func (a *Attestor) Verify(der []byte) (*contract.Verified, error) {
	v, err := a.bundle.Verify(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if !a.allowed(v.Claims) {
		return nil, fmt.Errorf("%w: project %s (domain %s) is not on the allowlists of this server",
			ErrRefused, v.Claims.ProjectID, v.Claims.DomainID)
	}
	return v, nil
}

// Selectors returns the certificate's selectors and, when configured, those from Nova and Keystone.
// Call it only after credential activation.
func (a *Attestor) Selectors(ctx context.Context, v *contract.Verified) ([]string, error) {
	sel := certSelectors(v)
	if !a.cfg.NovaSelectors && !a.cfg.KeystoneSelectors {
		return sel, nil
	}
	c := v.Claims
	api, err := a.clouds.For(ctx, c.ProjectID, c.Region)
	if err != nil {
		return nil, err
	}
	var live []string
	if a.cfg.NovaSelectors {
		if live, err = novaSelectors(ctx, api, c, live); err != nil {
			return nil, err
		}
	}
	if a.cfg.KeystoneSelectors {
		if live, err = keystoneSelectors(ctx, api, c, live); err != nil {
			return nil, err
		}
	}
	slices.Sort(live)
	return append(sel, live...), nil
}

// certSelectors are the selectors of the certificate's claims and key.
func certSelectors(v *contract.Verified) []string {
	c := v.Claims
	keyHash := sha256.Sum256(v.Cert.RawSubjectPublicKeyInfo)
	sel := []string{
		"region:" + c.Region,
		"domain:id:" + c.DomainID,
		"project:id:" + c.ProjectID,
		"project:parent:id:" + c.ParentID(),
		"instance:id:" + c.InstanceID,
		"instance:kind:" + c.Kind,
		"instance:user:id:" + c.UserID,
		"tpm:key:sha256:" + hex.EncodeToString(keyHash[:]),
	}
	for _, id := range c.Ancestors {
		sel = append(sel, "project:ancestor:id:"+id)
	}
	return sel
}

// novaSelectors appends the instance's selectors from Nova after checking that Nova agrees with the certificate.
func novaSelectors(ctx context.Context, api openstack.API, c contract.Claims, sel []string) ([]string, error) {
	s, err := api.GetServer(ctx, c.InstanceID)
	switch {
	case notVisible(err):
		return nil, fmt.Errorf("%w: instance %s not found in project %s", ErrRefused, c.InstanceID, c.ProjectID)
	case err != nil:
		return nil, unavailable("nova", c, err)
	case s.TenantID != c.ProjectID:
		return nil, fmt.Errorf("%w: project: nova %q, certificate %q", ErrMismatch, s.TenantID, c.ProjectID)
	case s.UserID != c.UserID:
		return nil, fmt.Errorf("%w: user: nova %q, certificate %q", ErrMismatch, s.UserID, c.UserID)
	}
	sel = appendValid(sel, "instance:name:", s.Name)
	sel = appendValid(sel, "instance:flavor:", s.Flavor.OriginalName)
	sel = appendValid(sel, "instance:az:", s.AZ)
	sel = appendValid(sel, "instance:image:id:", s.ImageID()) // none for boot from volume
	return appendValid(sel, "instance:tag:", s.Tags...), nil
}

// keystoneSelectors appends the project's selectors from Keystone after checking that Keystone agrees with the certificate.
func keystoneSelectors(ctx context.Context, api openstack.API, c contract.Claims, sel []string) ([]string, error) {
	p, err := api.GetProject(ctx, c.ProjectID)
	switch {
	case notVisible(err):
		return nil, fmt.Errorf("%w: project %s not found", ErrRefused, c.ProjectID)
	case err != nil:
		return nil, unavailable("keystone", c, err)
	case p.DomainID != c.DomainID:
		return nil, fmt.Errorf("%w: domain: keystone %q, certificate %q", ErrMismatch, p.DomainID, c.DomainID)
	case !slices.Equal(p.Ancestors, c.Ancestors):
		return nil, fmt.Errorf("%w: ancestors: keystone %q, certificate %q", ErrMismatch, p.Ancestors, c.Ancestors)
	}
	sel = appendValid(sel, "project:name:", p.Name)
	return appendValid(sel, "project:tag:", p.Tags...), nil
}

// notVisible reports a lookup the project's token cannot see, where a 403 means the same as a 404.
func notVisible(err error) bool {
	return errors.Is(err, openstack.ErrNotFound) || errors.Is(err, openstack.ErrForbidden)
}

// unavailable wraps a Nova or Keystone error as ErrUnavailable and names a refused credential as such.
func unavailable(what string, c contract.Claims, err error) error {
	if errors.Is(err, openstack.ErrAuth) {
		return fmt.Errorf("%w: keystone refused a token for project %s (domain %s): the credential is gone, or its user lacks reader there: %w",
			ErrUnavailable, c.ProjectID, c.DomainID, err)
	}
	return fmt.Errorf("%w: %s: %w", ErrUnavailable, what, err)
}

// appendValid appends a selector for each value that validValue accepts.
func appendValid(sel []string, prefix string, values ...string) []string {
	for _, v := range values {
		if validValue(v) {
			sel = append(sel, prefix+v)
		}
	}
	return sel
}

// validValue accepts non-empty UTF-8 of at most 255 bytes without control or format characters.
func validValue(s string) bool {
	if s == "" || len(s) > 255 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
