#!/usr/bin/env bash
# Installs the hypervisor hook into /etc/openstack-tpm/hv, which Kolla mounts into nova_libvirt, on one compute host as root.
# TSS_UID:TSS_GID are the ids of tss inside nova_libvirt, which runs swtpm_setup and so openstack-tpm-swtpm.
set -euo pipefail
[ $# -eq 3 ] || { echo "usage: $0 DIR ISSUER_URL TSS_UID:TSS_GID" >&2; exit 2; }
SRC=$1
ISSUER_URL=$2
TSS_GID=${3#*:}
DEST=/etc/openstack-tpm/hv

install -d -m 0755 "$DEST"
install -m 0755 "$SRC/openstack-tpm-swtpm" "$DEST/openstack-tpm-swtpm"
install -m 0644 "$SRC/client.crt" "$DEST/client.crt"
install -m 0644 "$SRC/ca.pem" "$DEST/ca.pem"
install -m 0440 -o 0 -g "$TSS_GID" "$SRC/client.key" "$DEST/client.key"

# Paths as nova_libvirt sees them.
cat > "$DEST/openstack-tpm-swtpm.conf" <<CONF
url = "$ISSUER_URL"
cert = "/etc/openstack-tpm/client.crt"
key = "/etc/openstack-tpm/client.key"
ca = "/etc/openstack-tpm/ca.pem"
CONF
# Rewrite in place: a single-file bind mount keeps the original inode.
cat "$SRC/swtpm_setup.conf" > "$DEST/swtpm_setup.conf"
