//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// scope is the Keystone scope of a CLI call as the Kolla admin, a project by name or ID or the system.
type scope struct {
	project, projectID string
	system             bool
}

var (
	adminScope  = scope{project: "admin"}
	systemScope = scope{system: true}
)

func tenantScope() scope { return scope{project: lab.Tenant} }

// cli runs the openstack CLI as the Kolla admin in s, at Nova's latest microversion.
func cli(s scope, args ...string) ([]byte, error) {
	pw, err := os.ReadFile(path(adminPasswordFile))
	if err != nil {
		return nil, err
	}
	env := []string{"OS_AUTH_URL=" + lab.KeystoneURL, "OS_IDENTITY_API_VERSION=3", "OS_REGION_NAME=" + lab.Region,
		"OS_INTERFACE=internal", "OS_USERNAME=admin", "OS_PASSWORD=" + strings.TrimSpace(string(pw)),
		"OS_USER_DOMAIN_NAME=Default", "OS_COMPUTE_API_VERSION=2.latest",
		"OS_PROJECT_NAME=", "OS_PROJECT_ID=", "OS_PROJECT_DOMAIN_NAME=", "OS_SYSTEM_SCOPE="}
	switch {
	case s.system:
		env = append(env, "OS_SYSTEM_SCOPE=all")
	case s.projectID != "":
		env = append(env, "OS_PROJECT_ID="+s.projectID)
	default:
		env = append(env, "OS_PROJECT_NAME="+s.project, "OS_PROJECT_DOMAIN_NAME=Default")
	}
	out, err := runEnv(env, nil, "openstack", args...)
	return []byte(out), err
}

// cliJSON runs a CLI command with `-f json` and decodes its output.
func cliJSON(v any, s scope, args ...string) error {
	out, err := cli(s, append(args, "-f", "json")...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("openstack %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// os_ runs a CLI command and fails the test on an error.
func os_(t testing.TB, s scope, args ...string) string {
	t.Helper()
	out, err := cli(s, args...)
	must(t, err, "openstack "+strings.Join(args, " "))
	return string(out)
}

func osJSON(t testing.TB, v any, s scope, args ...string) {
	t.Helper()
	must(t, cliJSON(v, s, args...), "openstack "+strings.Join(args, " "))
}

// notFound reports whether a CLI error says the resource does not exist.
func notFound(err error) bool {
	return err != nil && regexp.MustCompile(`(?i)no .* (found|exists)|not found|could not be found|404`).MatchString(err.Error())
}

// server is `openstack server show -f json` of the fields the tests read.
type server struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Status    string          `json:"status"`
	TaskState *string         `json:"OS-EXT-STS:task_state"`
	Host      string          `json:"OS-EXT-SRV-ATTR:host"`
	ProjectID string          `json:"project_id"`
	UserID    string          `json:"user_id"`
	AZ        string          `json:"OS-EXT-AZ:availability_zone"`
	Image     json.RawMessage `json:"image"`
	Fault     json.RawMessage `json:"fault"`
	Addresses json.RawMessage `json:"addresses"`
	Tags      []string        `json:"tags"`
}

func (s *server) task() string {
	if s.TaskState == nil {
		return ""
	}
	return *s.TaskState
}

var uuidRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// imageID is the ID of the server's image ("name (id)" or an object).
func (s *server) imageID() string {
	var o struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(s.Image, &o) == nil && o.ID != "" {
		return o.ID
	}
	return uuidRE.FindString(string(s.Image))
}

// fault is the message of the server's fault, if any.
func (s *server) fault() string {
	var o struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(s.Fault, &o) == nil && o.Message != "" {
		return o.Message
	}
	return string(s.Fault)
}

// addresses lists the server's IP addresses on every network.
func (s *server) addresses() []string {
	var m map[string][]string
	if json.Unmarshal(s.Addresses, &m) == nil {
		var all []string
		for _, a := range m {
			all = append(all, a...)
		}
		return all
	}
	return regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`).FindAllString(string(s.Addresses), -1)
}

// getServer returns the server, or nil once Nova no longer knows it.
func getServer(t testing.TB, id string) *server {
	t.Helper()
	var s server
	err := cliJSON(&s, adminScope, "server", "show", id)
	if notFound(err) {
		return nil
	}
	must(t, err, "server show "+id)
	return &s
}

func showServer(t testing.TB, id string) *server {
	t.Helper()
	s := getServer(t, id)
	if s == nil {
		t.Fatalf("server %s not found", id)
	}
	return s
}

// serverID returns the ID of the server named name in any project, or "".
func serverID(t testing.TB, name string) string {
	t.Helper()
	var l []struct {
		ID string `json:"ID"`
	}
	osJSON(t, &l, adminScope, "server", "list", "--all-projects", "--name", "^"+name+"$")
	if len(l) == 0 {
		return ""
	}
	return l[0].ID
}

type serverSpec struct {
	name, flavor, image, network, securityGroup string
	scope                                       scope
	configDrive                                 bool // metadata on a config drive (bare metal)
	noNetwork                                   bool
}

// createServer starts a build and returns the server ID.
func createServer(t testing.TB, s serverSpec) string {
	t.Helper()
	args := []string{"server", "create", s.name, "--flavor", s.flavor, "--image", s.image, "--key-name", lab.Keypair}
	if s.noNetwork {
		args = append(args, "--no-network")
	} else {
		args = append(args, "--network", s.network)
	}
	if s.securityGroup != "" {
		args = append(args, "--security-group", s.securityGroup)
	}
	if s.configDrive {
		args = append(args, "--config-drive", "true")
	}
	var out struct {
		ID string `json:"id"`
	}
	osJSON(t, &out, s.scope, args...)
	return out.ID
}

// waitServer waits until the server leaves BUILD and has no task, and returns its status.
func waitServer(t testing.TB, id string, timeout time.Duration) string {
	t.Helper()
	var s *server
	eventually(t, timeout, "server "+id+" settled", func() bool {
		s = showServer(t, id)
		return s.Status != "BUILD" && s.task() == ""
	})
	return s.Status
}

func waitStatus(t testing.TB, id, want string, timeout time.Duration) {
	t.Helper()
	eventually(t, timeout, "server "+id+" "+want, func() bool {
		s := showServer(t, id)
		if s.Status == "ERROR" && want != "ERROR" {
			t.Fatalf("server %s is ERROR: %s", id, s.fault())
		}
		return s.Status == want && s.task() == ""
	})
}

// deleteServer deletes a server and waits until Nova no longer shows it.
func deleteServer(id string) error {
	_, err := cli(adminScope, "server", "delete", "--wait", id)
	if notFound(err) {
		return nil
	}
	return err
}

// resize resizes the server to flavor in s, confirms it and waits for the status it had before.
func resize(t testing.TB, id string, s scope, flavor string) {
	t.Helper()
	want := showServer(t, id).Status
	os_(t, s, "server", "resize", "--flavor", flavor, id)
	waitStatus(t, id, "VERIFY_RESIZE", 10*time.Minute)
	os_(t, s, "server", "resize", "confirm", id)
	waitStatus(t, id, want, 3*time.Minute)
}

func stopServer(t testing.TB, id string, s scope) {
	t.Helper()
	os_(t, s, "server", "stop", id)
	waitStatus(t, id, "SHUTOFF", 3*time.Minute)
}

func startServer(t testing.TB, id string, s scope) {
	t.Helper()
	os_(t, s, "server", "start", id)
	waitStatus(t, id, "ACTIVE", 3*time.Minute)
}

func hardReboot(t testing.TB, id string) {
	t.Helper()
	os_(t, adminScope, "server", "reboot", "--hard", id)
	waitStatus(t, id, "ACTIVE", 5*time.Minute)
}

// snapshot creates an image of the server in s and returns its ID once it is active.
func snapshot(t testing.TB, id string, s scope, name string) string {
	t.Helper()
	var img struct {
		ID string `json:"id"`
	}
	osJSON(t, &img, s, "server", "image", "create", "--name", name, "--wait", id)
	return img.ID
}

// addFloatingIP allocates a floating IP in s and binds it to the server.
func addFloatingIP(t testing.TB, serverID string, s scope) (id, addr string) {
	t.Helper()
	var fip struct {
		ID   string `json:"id"`
		Addr string `json:"floating_ip_address"`
	}
	osJSON(t, &fip, s, "floating", "ip", "create", lab.ExternalNetwork)
	os_(t, s, "server", "add", "floating", "ip", serverID, fip.Addr)
	return fip.ID, fip.Addr
}

func deleteFloatingIP(id string) error {
	_, err := cli(adminScope, "floating", "ip", "delete", id)
	if notFound(err) {
		return nil
	}
	return err
}

// providerAddress returns the server's address on the provider network.
func providerAddress(t testing.TB, id string) string {
	t.Helper()
	for _, a := range showServer(t, id).addresses() {
		if strings.HasPrefix(a, lab.FIPPrefix) {
			return a
		}
	}
	t.Fatalf("server %s has no address on the provider network", id)
	return ""
}

type bmNode struct {
	ProvisionState string  `json:"provision_state"`
	InstanceUUID   *string `json:"instance_uuid"`
	Maintenance    bool    `json:"maintenance"`
	LastError      *string `json:"last_error"`
	AutomatedClean *bool   `json:"automated_clean"`
}

func showNode(t testing.TB) *bmNode {
	t.Helper()
	var n bmNode
	osJSON(t, &n, systemScope, "baremetal", "node", "show", lab.Baremetal.Node)
	return &n
}

// waitNodeAvailable waits until Ironic has the node available and Nova no longer reserves it in Placement.
func waitNodeAvailable(t testing.TB, timeout time.Duration) {
	t.Helper()
	eventually(t, timeout, "node "+lab.Baremetal.NodeName+" available", func() bool {
		n := showNode(t)
		if strings.HasSuffix(n.ProvisionState, "failed") || n.Maintenance {
			msg := ""
			if n.LastError != nil {
				msg = *n.LastError
			}
			t.Fatalf("node %s: %s, maintenance %v: %s", lab.Baremetal.NodeName, n.ProvisionState, n.Maintenance, msg)
		}
		return n.ProvisionState == "available" && (n.InstanceUUID == nil || *n.InstanceUUID == "")
	})
	eventually(t, 10*time.Minute, "node "+lab.Baremetal.NodeName+" free in Placement", func() bool {
		var inv struct {
			Total    int `json:"total"`
			Reserved int `json:"reserved"`
		}
		err := cliJSON(&inv, adminScope, "resource", "provider", "inventory", "show", lab.Baremetal.Node, "CUSTOM_BAREMETAL")
		return err == nil && inv.Total == 1 && inv.Reserved == 0
	})
}

// setAutomatedClean sets the node's automated_clean, retrying while Ironic refuses it during a state change.
func setAutomatedClean(t testing.TB, v bool) {
	t.Helper()
	if cur := showNode(t).AutomatedClean; cur != nil && *cur == v {
		return
	}
	flag := "--automated-clean"
	if !v {
		flag = "--no-automated-clean"
	}
	eventually(t, 15*time.Minute, "set automated_clean on "+lab.Baremetal.NodeName, func() bool {
		_, err := cli(systemScope, "baremetal", "node", "set", flag, lab.Baremetal.Node)
		if err != nil && strings.Contains(err.Error(), "409") {
			return false
		}
		must(t, err, "set automated_clean")
		return true
	})
}

// ensureFlavor creates a flavor with extra specs unless it exists.
func ensureFlavor(t testing.TB, name string, vcpus, ramMiB, diskGiB int, specs map[string]string) {
	t.Helper()
	if _, err := cli(adminScope, "flavor", "show", name); err == nil {
		return
	}
	args := []string{"flavor", "create", name, "--vcpus", fmt.Sprint(vcpus), "--ram", fmt.Sprint(ramMiB), "--disk", fmt.Sprint(diskGiB)}
	for k, v := range specs {
		args = append(args, "--property", k+"="+v)
	}
	os_(t, adminScope, args...)
}

type project struct {
	ID       string   `json:"id"`
	DomainID string   `json:"domain_id"`
	ParentID string   `json:"parent_id"`
	Tags     []string `json:"tags"`
}

func showProject(t testing.TB, id string) *project {
	t.Helper()
	var p project
	osJSON(t, &p, adminScope, "project", "show", id)
	return &p
}

// ancestors returns the projects above id, root first, by following parent_id instead of the parents_as_ids the product uses.
func ancestors(t testing.TB, id string) []string {
	t.Helper()
	var up []string
	for p := showProject(t, id); p.ParentID != p.DomainID; p = showProject(t, p.ParentID) {
		up = append([]string{p.ParentID}, up...)
	}
	return up
}

// tagProject adds tags to a project and removes them when the test ends.
func tagProject(t testing.TB, id string, tags ...string) {
	t.Helper()
	args := []string{"project", "set", id}
	rm := slices.Clone(args)
	for _, tag := range tags {
		args, rm = append(args, "--tag", tag), append(rm, "--remove-tag", tag)
	}
	os_(t, adminScope, args...)
	t.Cleanup(func() { os_(t, adminScope, rm...) })
}

// throwawayProject creates the domain e2e-<name>, where no openstack-tpm principal has a role, with one project, and returns its ID.
// Both are deleted when the test ends, after the caller's servers.
func throwawayProject(t testing.TB, name string) string {
	t.Helper()
	name = "e2e-" + name
	deleteDomain := func() {
		if _, err := cli(adminScope, "domain", "show", name); err != nil {
			return
		}
		os_(t, adminScope, "domain", "set", "--disable", name)
		os_(t, adminScope, "domain", "delete", name) // and its project
	}
	deleteDomain() // a leftover from an aborted run
	os_(t, adminScope, "domain", "create", name)
	t.Cleanup(deleteDomain)
	var p project
	osJSON(t, &p, adminScope, "project", "create", "--domain", name, name)
	os_(t, adminScope, "role", "add", "--project", p.ID, "--user", "admin", "--user-domain", "Default", "admin")
	return p.ID
}

// nestedProjects creates a chain of depth projects e2e-<name>-<n> in the Default domain and returns their IDs, root first.
// The leaf gets the admin user and an SSH security group; all are deleted when the test ends, after the caller's servers.
func nestedProjects(t testing.TB, name string, depth int) []string {
	t.Helper()
	names := make([]string, depth)
	for i := range names {
		names[i] = fmt.Sprintf("e2e-%s-%d", name, i+1)
	}
	deleteProject := func(id string) {
		var sgs []struct {
			ID string `json:"ID"`
		}
		osJSON(t, &sgs, adminScope, "security", "group", "list", "--project", id)
		for _, g := range sgs { // Neutron keeps them after the project is gone
			os_(t, adminScope, "security", "group", "delete", g.ID)
		}
		os_(t, adminScope, "project", "delete", id)
	}
	for _, n := range slices.Backward(names) { // leftovers of an aborted run, children first
		var p project
		if cliJSON(&p, adminScope, "project", "show", "--domain", lab.DomainID, n) == nil {
			deleteProject(p.ID)
		}
	}
	var ids []string
	for i, n := range names {
		args := []string{"project", "create", "--domain", lab.DomainID, n}
		if i > 0 {
			args = append(args, "--parent", ids[i-1])
		}
		var p project
		osJSON(t, &p, adminScope, args...)
		t.Cleanup(func() { deleteProject(p.ID) }) // children first: cleanups run last-in first-out
		ids = append(ids, p.ID)
	}
	leaf := ids[depth-1]
	os_(t, adminScope, "role", "add", "--project", leaf, "--user", "admin", "--user-domain", "Default", "admin")
	s := scope{projectID: leaf}
	var sg struct {
		ID string `json:"id"`
	}
	osJSON(t, &sg, s, "security", "group", "create", names[depth-1]+"-ssh")
	os_(t, s, "security", "group", "rule", "create", "--ingress", "--protocol", "tcp", "--dst-port", "22", sg.ID)
	return ids
}

// bootPlain boots a Cirros server without a network in s, on the plain flavor unless flavor is given, and deletes it at the end.
func bootPlain(t testing.TB, s scope, name, flavor string) string {
	t.Helper()
	if flavor == "" {
		flavor = lab.PlainFlavor
	}
	id := createServer(t, serverSpec{name: "e2e-" + name, flavor: flavor, image: lab.CirrosImage, scope: s, noNetwork: true})
	t.Cleanup(func() { must(t, deleteServer(id), "delete server e2e-"+name) })
	waitStatus(t, id, "ACTIVE", 5*time.Minute)
	return id
}
