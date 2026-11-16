#!/usr/bin/env just
# The openstack-tpm lab: Kolla on compute-1, the bare-metal node in bmc, and the provider side in Compose on this host.
# Run from the flake devshell (`nix develop --command just <recipe>`).

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

version := `git describe --always --dirty 2>/dev/null || echo dev`
# Guest operating systems; the agent plugin is built into bin/<os>/ for each.
guests := "linux windows"

default:
    @just --list

# Build the lab from scratch, from the VMs to a deployed openstack-tpm with the snapshots kolla and provisioned.
lab: vms build provision

# Create the libvirt network and the VMs compute-1 and bmc (with the nested node bm-1).
vms:
    bash lab/vms.sh create

# Provision OpenStack once, with the snapshots kolla (after Kolla) and provisioned (after node enrolment).
provision:
    bash lab/provision.sh

# Revert both VMs to a snapshot (default provisioned) and start them; for provisioned, deploy. Also the way back after a host reboot.
reset snapshot="provisioned":
    bash lab/vms.sh revert "$1"
    [ "$1" != provisioned ] || just deploy

# Delete the VMs, their snapshots, the network and the Compose project.
delete:
    bash -c 'source lab/lib.sh && compose down --remove-orphans' || true
    bash lab/vms.sh delete

# VMs, containers, OpenStack services, bare-metal nodes and servers.
status:
    bash lab/ops.sh status

# Run an openstack CLI command as the Kolla admin, e.g. `just cli server list`.
cli *ARGS:
    bash lab/ops.sh cli "$@"

# Root shell on a lab VM (default compute-1).
shell vm="compute-1":
    ssh -F .state/ssh_config -t {{ vm }}

# Vet, unit-test and build the static binaries into bin/, and the issuer image (openstack-tpm-issuer:lab).
build: test
    rm -rf bin
    CGO_ENABLED=0 go build -trimpath -o bin/ ./cmd/...
    for os in {{ guests }}; do CGO_ENABLED=0 GOOS=$os GOARCH=amd64 go build -trimpath -o bin/$os/ ./cmd/openstack-tpm-spire-agent; done
    docker build -q -f deploy/issuer/Dockerfile -t openstack-tpm-issuer:lab --label org.opencontainers.image.version={{ version }} bin/ >/dev/null

# Vet and run the unit tests (the TPM simulator needs cgo).
test:
    go vet ./...
    # The plugin and this module's packages it imports, for each guest OS.
    for os in {{ guests }}; do CGO_ENABLED=0 GOOS=$os go vet $(CGO_ENABLED=0 GOOS=$os go list -deps ./cmd/openstack-tpm-spire-agent | grep ^github.com/cvdtang/openstack-tpm); done
    cd test/e2e && go vet -tags e2e ./...
    go test ./...

# Build and deploy openstack-tpm on the lab.
deploy: build
    bash lab/deploy.sh

# Build the Windows Server image from the ISO in .state/image (once, cached) and upload it with its vTPM flavor.
windows:
    bash lab/windows.sh

# End-to-end tests against the lab.
e2e *ARGS:
    cd test/e2e && go test -tags e2e -count=1 -v -timeout 180m . "$@"

# Like e2e, with a JUnit report in .state/e2e-junit.xml.
e2e-junit *ARGS:
    cd test/e2e && gotestsum --junitfile ../../.state/e2e-junit.xml --format testname -- -tags e2e -count=1 -timeout 180m . "$@"

# SPIRE agents, the bare-metal node and the last issuer decisions.
agents:
    @bash lab/ops.sh agents

# Issuer, OpenBao and SPIRE server logs.
logs:
    @bash lab/ops.sh logs

# The bare-metal node's serial console log (IPA and the instance).
console:
    @bash lab/ops.sh console

# Delete e2e instances, images, server groups and unused floating IPs.
clean:
    @bash lab/ops.sh clean
