package issuer

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cvdtang/openstack-tpm/internal/openstack"
)

// PluginDataKey is where the IPA inspection collector reports in a node's inspection data, and EKField the EK's hash within it.
const (
	PluginDataKey = "openstack_tpm"
	EKField       = "tpm_ek_sha256"
)

// OpenStack looks up instances, projects and nodes for the issuer's authorization, through one least-privilege role
type OpenStack struct {
	scoped *openstack.Scoped
}

// NewOpenStack returns the view for base's user, scoped to the service project.
func NewOpenStack(base *openstack.Client) *OpenStack {
	return &OpenStack{scoped: openstack.NewScoped(base)}
}

func (o *OpenStack) Allocations(ctx context.Context, instance string) (*openstack.Allocations, error) {
	return o.scoped.Base().GetAllocations(ctx, instance)
}

func (o *OpenStack) Server(ctx context.Context, project, instance string) (*openstack.Server, error) {
	return o.scoped.Project(project).GetServer(ctx, instance)
}

func (o *OpenStack) Actions(ctx context.Context, project, instance string) ([]openstack.InstanceAction, error) {
	return o.scoped.Project(project).GetInstanceActions(ctx, instance)
}

func (o *OpenStack) Project(ctx context.Context, project string) (*openstack.Project, error) {
	return o.scoped.Project(project).GetProject(ctx, project)
}

func (o *OpenStack) Node(ctx context.Context, node string) (*openstack.Node, error) {
	return o.scoped.Base().GetNode(ctx, node)
}

func (o *OpenStack) NodeEK(ctx context.Context, node string) (string, error) {
	data, err := o.scoped.Base().GetNodePluginData(ctx, node)
	if err != nil {
		return "", err
	}
	ek, err := ekFromPluginData(data)
	if err != nil {
		return "", fmt.Errorf("inspection data %s of node %s: %w", PluginDataKey, node, err)
	}
	return ek, nil
}

// ekFromPluginData is the EK hash in the collector's report, or "" if there is no report or it found no EK.
func ekFromPluginData(data map[string]json.RawMessage) (string, error) {
	if data[PluginDataKey] == nil {
		return "", nil
	}
	var report map[string]string
	if err := json.Unmarshal(data[PluginDataKey], &report); err != nil {
		return "", err
	}
	return report[EKField], nil
}
