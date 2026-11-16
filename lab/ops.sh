#!/usr/bin/env bash
# Manual lab operations; run from the repo root.
# Usage: ops.sh status | cli ARGS... | agents | logs | console | clean
set -euo pipefail
source lab/lib.sh

section() { echo "=== $* ==="; }
node_list() { os baremetal node list -c name -c instance_uuid -c power_state -c provision_state; }
# e2e_ids: the IDs of `ID Name` lines whose name starts with e2e-.
e2e_ids() { awk '$2 ~ /^e2e-/ {print $1}'; }

status() {
    bash lab/vms.sh status
    section "Compose project (this host)"
    compose ps --format '{{.Name}} {{.Status}}' || true
    section "compute-1: Kolla containers not running/healthy"
    ctl sh -c "docker ps -a --format '{{.Names}} {{.Status}}' | grep -E 'unhealthy|Exited|Restarting|Created'" || true
    section "bmc"
    node bmc sh -c 'systemctl is-active sushy-emulator; virsh domstate bm-1' || true
    section "compute services"
    os compute service list -c Binary -c Host -c State || true
    section "network agents"
    os network agent list -c "Agent Type" -c Host -c Alive || true
    section "bare-metal nodes"
    node_list || true
    section "servers"
    os server list --all-projects -c Name -c Status -c Networks || true
}

agents() {
    spire $SPIRE_CONTAINER agent list || true
    spire $CENTRAL_CONTAINER agent list || true
    node_list || true
    docker logs issuer 2>&1 | grep -E '"msg":"(issued|authorized|refused)"' | tail -10
}

logs() {
    docker logs --tail 30 issuer 2>&1
    docker logs --tail 10 openbao 2>&1
    docker logs --tail 30 $SPIRE_CONTAINER 2>&1
    docker logs --tail 10 $CENTRAL_CONTAINER 2>&1
}

# clean: leftover e2e-* instances, images and server groups in any project, and unused floating IPs.
clean() {
    local id
    for id in $(os server list --all-projects -f value -c ID -c Name | e2e_ids); do
        os server delete --wait "$id"
    done
    for id in $(os image list -f value -c ID -c Name | e2e_ids); do
        os image delete "$id"
    done
    for id in $(os server group list --all-projects -f value -c ID -c Name | e2e_ids); do
        os server group delete "$id"
    done
    for id in $(os floating ip list --status DOWN -f value -c ID); do
        os floating ip delete "$id"
    done
}

case "${1:-}" in
    status) status ;;
    cli) shift; os "$@" ;;
    agents) agents ;;
    logs) logs ;;
    console) node bmc cat /var/log/libvirt/qemu/bm-1-serial.log ;;
    clean) clean ;;
    *) sed -n '2,3p' "$0"; exit 2 ;;
esac
