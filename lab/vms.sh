#!/usr/bin/env bash
# Creates and manages the lab's libvirt network and the VMs compute-1 and bmc; run from the repo root.
# Usage: vms.sh create | snapshot NAME | revert NAME | delete | status
set -euo pipefail
source lab/lib.sh

quiet() { "$@" >/dev/null 2>&1; }

# render FILE: the template with the lab's variables substituted.
render() {
    envsubst '${PUBKEY} ${OCTET} ${BM_UUID} ${BM_MAC} ${BMC_PORT}' < "$1"
}

wait_ssh() {
    local n
    for n in $VMS; do
        wait_until 450 "$n reachable over SSH" ssh -F $STATE/ssh_config -o ConnectTimeout=3 $n true
        node $n sh -c 'cloud-init status --wait >/dev/null || true'
    done
}

# vm NAME OCTET VCPUS MEMORY_MIB DISK_SIZE TEMPLATE_DIR IMAGE_URL OSINFO: a VM on otpm-mgmt with two NICs, booted from a cloud image and cloud-init.
vm() {
    local name=$1 octet=$2 vcpus=$3 memory=$4 disk=$5 templates=$6 image_url=$7 osinfo=$8
    local dir=vm/otpm-$name base
    if quiet virsh dominfo otpm-$name; then
        echo "otpm-$name exists"
        return
    fi
    mkdir -p $dir
    PUBKEY=$(< $STATE/lab_ed25519.pub)
    export PUBKEY OCTET=$octet
    render $templates/user-data > $dir/user-data
    render $templates/network-config > $dir/network-config
    cloud-localds -N $dir/network-config $dir/seed.iso $dir/user-data
    base=vm/$(basename $image_url)
    [ -s $base ] || curl -fL -o $base $image_url
    qemu-img create -q -f qcow2 -F qcow2 -b "$PWD/$base" $dir/disk.qcow2 $disk
    virt-install --name otpm-$name --vcpus $vcpus --memory $memory --cpu host-passthrough --osinfo $osinfo \
        --disk $dir/disk.qcow2,bus=virtio --disk $dir/seed.iso,device=cdrom \
        --network network=otpm-mgmt,mac=52:54:00:96:00:$octet,model=virtio \
        --network network=otpm-mgmt,mac=52:54:00:96:01:$octet,model=virtio \
        --graphics none --import --noautoconsole >/dev/null
    echo "created otpm-$name (192.168.150.$octet)"
}

# bmc_setup: the node's domain, sushy-tools and its unit on bmc.
bmc_setup() {
    local f
    export BM_UUID BM_MAC BMC_PORT
    for f in bm-1.xml sushy.conf; do
        render lab/bmc/$f | put bmc /root/$f
    done
    put bmc /root/sushy-emulator.service < lab/bmc/sushy-emulator.service
    put bmc /root/setup.sh 0755 < lab/bmc/setup.sh
    node bmc sh -c 'cd /root && ./setup.sh'
    wait_until 60 "Redfish on bmc" ctl curl -fsS -o /dev/null "http://$BMC_IP:$BMC_PORT/redfish/v1/Systems/$BM_UUID"
}

# check_firewall: compute-1 must reach this host's lab ports; a refused connection passes, a dropped one times out.
check_firewall() {
    local rc
    rc=$(ctl sh -c "curl -s -o /dev/null -m 5 http://$HOST_IP:9443; echo \$?")
    case $rc in
        0|7) ;;
        *) die "compute-1 cannot reach $HOST_IP:9443 (curl exit $rc): the host firewall must accept TCP 9443 8081 18082 18083 from virbr-otpm0" ;;
    esac
}

create() {
    install -d -m 0700 $STATE
    mkdir -p vm
    [ -f $STATE/lab_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C openstack-tpm-lab -f $STATE/lab_ed25519
    quiet virsh net-info otpm-mgmt || virsh net-define lab/vm/otpm-mgmt.xml >/dev/null
    virsh net-autostart otpm-mgmt >/dev/null
    quiet virsh net-start otpm-mgmt || true
    #  name      octet vcpus memory disk templates image                osinfo
    vm compute-1 11    8     24576  100G lab/vm    $NOBLE_IMAGE_URL     ubuntu24.04
    vm bmc       13    4     8192   40G  lab/bmc   $RESOLUTE_IMAGE_URL  ubuntu26.04
    PWD=$PWD envsubst '${PWD}' < lab/vm/ssh_config > $STATE/ssh_config
    wait_ssh
    bmc_setup
    check_firewall
}

shutdown_all() {
    local n
    for n in $VMS; do
        quiet virsh shutdown otpm-$n || true
    done
    for n in $VMS; do
        wait_until 300 "otpm-$n shut off" sh -c "virsh domstate otpm-$n | grep -qx 'shut off'" ||
            quiet virsh destroy otpm-$n || true
    done
}

start_all() {
    local n
    for n in $VMS; do
        quiet virsh start otpm-$n || true
    done
    wait_ssh
}

# diskspecs DOMAIN: --diskspec options that snapshot the disks internally and leave out the cloud-init seed (a raw CD-ROM).
diskspecs() {
    virsh domblklist "$1" --details | awk '
        $1 == "file" && $2 == "disk"  { printf " --diskspec %s,snapshot=internal", $3 }
        $1 == "file" && $2 == "cdrom" { printf " --diskspec %s,snapshot=no", $3 }'
}

# snapshot NAME: internal snapshots of the shut-off VMs.
snapshot() {
    local name=$1 n
    shutdown_all
    for n in $VMS; do
        quiet virsh snapshot-delete otpm-$n "$name" || true
        # shellcheck disable=SC2046
        virsh snapshot-create-as otpm-$n "$name" --description "openstack-tpm lab: $name" $(diskspecs otpm-$n) >/dev/null
        echo "otpm-$n: snapshot $name"
    done
    start_all
}

revert() {
    local name=$1 n
    for n in $VMS; do
        virsh snapshot-info otpm-$n "$name" >/dev/null || die "otpm-$n has no snapshot $name"
    done
    for n in $VMS; do
        quiet virsh destroy otpm-$n || true
        virsh snapshot-revert otpm-$n "$name"
        echo "otpm-$n: reverted to $name"
    done
    start_all
}

delete() {
    local n
    # otpm-compute-2 and otpm-bm-1 are from the lab before the bmc VM.
    for n in $VMS compute-2; do
        quiet virsh destroy otpm-$n || true
        quiet virsh undefine otpm-$n --snapshots-metadata || true
        rm -rf vm/otpm-$n
    done
    quiet virsh destroy otpm-bm-1 || true
    quiet virsh undefine otpm-bm-1 --nvram --tpm || true
    rm -rf vm/otpm-bm-1
    quiet virsh net-destroy otpm-mgmt || true
    quiet virsh net-undefine otpm-mgmt || true
    # Derived from the deleted OpenStack.
    rm -rf $STATE/admin.password $STATE/provision $STATE/spire $STATE/issuer $STATE/agent $STATE/lab.json
}

status() {
    local n
    virsh list --all | grep -E 'Name|otpm-'
    for n in $VMS; do
        virsh snapshot-list otpm-$n --name 2>/dev/null | sed "/^$/d; s/^/otpm-$n snapshot: /"
    done
}

case "${1:-}" in
    create) create ;;
    snapshot) snapshot "${2:?snapshot NAME}" ;;
    revert) revert "${2:?revert NAME}" ;;
    delete) delete ;;
    status) status ;;
    *) sed -n '2,3p' "$0"; exit 2 ;;
esac
