# shellcheck shell=bash disable=SC2034
# Shared helpers for the lab scripts, sourced from the repo root; the OpenStack CLI and Compose run here, Kolla on compute-1 over SSH.
set -a
source lab/lab.env
set +a
export LIBVIRT_DEFAULT_URI=${LIBVIRT_DEFAULT_URI:-qemu:///system}

STATE=.state
BIN=bin                             # `just build` output
VMS="compute-1 bmc"                 # libvirt domains otpm-<name>
BINARIES="openstack-tpm-swtpm openstack-tpm-issuer openstack-tpm-spire-server openstack-tpm-ipa linux/openstack-tpm-spire-agent windows/openstack-tpm-spire-agent.exe"
# Stock IPA kernel and ramdisk, cached in $STATE/image; Kolla needs a copy on compute-1 and the deploy appends the overlay.
IPA_IMAGE=ipa-centos10-stable-2026.2
IPA_URL=https://tarballs.opendev.org/openstack/ironic-python-agent/dib/files/$IPA_IMAGE
# Ubuntu 24.04 for compute-1 (the newest host Kolla-Ansible 2026.2 supports) and 26.04 for bmc and instances.
NOBLE_IMAGE_URL=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
RESOLUTE_IMAGE_URL=https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img

die() { echo "$*" >&2; exit 1; }

# node HOST CMD...: run a command as root on a lab VM (arguments are quoted).
node() { local host=$1; shift; ssh -n -F $STATE/ssh_config "$host" "$(printf '%q ' "$@")"; }
# node_in HOST CMD...: the same with this shell's stdin.
node_in() { local host=$1; shift; ssh -F $STATE/ssh_config "$host" "$(printf '%q ' "$@")"; }
ctl()    { node compute-1 "$@"; }
ctl_in() { node_in compute-1 "$@"; }
# put HOST FILE [MODE]: write stdin to a file on a VM.
put() { node_in "$1" sh -c 'umask 077; cat > "$1" && chmod "$2" "$1"' sh "$2" "${3:-0644}"; }
# kolla ARGS...: kolla-ansible on compute-1 with the lab's inventory.
kolla() { ctl sh -c 'PATH=/opt/kolla-venv/bin:$PATH exec kolla-ansible "$@" -i /etc/kolla/multinode' kolla "$@"; }

# os ARGS...: the OpenStack CLI as the Kolla admin; the password is fetched from compute-1 once.
os() {
    if [ ! -s $STATE/admin.password ]; then
        (umask 077; ctl sh -c '. /etc/kolla/admin-openrc.sh && printf %s "$OS_PASSWORD"' > $STATE/admin.password)
    fi
    OS_AUTH_URL=$KEYSTONE_URL OS_IDENTITY_API_VERSION=3 OS_REGION_NAME=$REGION OS_INTERFACE=internal \
        OS_USERNAME=admin OS_PASSWORD="$(< $STATE/admin.password)" OS_USER_DOMAIN_NAME=Default \
        OS_PROJECT_NAME=admin OS_PROJECT_DOMAIN_NAME=Default OS_COMPUTE_API_VERSION=2.latest \
        openstack "$@"
}

# compose ARGS...: the provider's Compose project on this host.
compose() {
    LAB_UID=$(id -u) LAB_GID=$(id -g) docker compose -p otpm -f lab/compose/docker-compose.yml --project-directory . "$@"
}
# spire CONTAINER ARGS...: the spire-server CLI in a SPIRE server container.
spire() { local container=$1; shift; docker exec "$container" /opt/spire/bin/spire-server "$@" -socketPath $SPIRE_SOCKET; }

require_binaries() {
    local f
    for f in $BINARIES; do
        [ -x $BIN/$f ] || die "$BIN/$f missing; run just build"
    done
}

# download URL FILE: fetch once into the cache.
download() {
    [ -s "$2" ] && return
    install -d -m 0700 "$(dirname "$2")"
    curl -fsSL -o "$2.tmp" "$1" && mv "$2.tmp" "$2"
}

ipa_images() {
    download $IPA_URL.kernel $STATE/image/$IPA_IMAGE.kernel
    download $IPA_URL.initramfs $STATE/image/$IPA_IMAGE.initramfs
}

# wait_until SECONDS DESCRIPTION CMD...: poll CMD every 5 seconds.
wait_until() {
    local tries=$(( $1 / 5 )) what=$2
    shift 2
    for _ in $(seq 1 $tries); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 5
    done
    echo "timed out after $tries*5s: $what" >&2
    return 1
}
