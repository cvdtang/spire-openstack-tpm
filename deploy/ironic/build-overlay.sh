#!/usr/bin/env bash
# Builds the IPA ramdisk overlay with openstack-tpm-ipa, its config and the hardware manager.
# The overlay is a cpio archive to append to a stock ramdisk; IPA_SITE_PACKAGES overrides IPA's site-packages path.
set -euo pipefail
[ $# -eq 4 ] || { echo "usage: $0 TOOL ISSUER_URL ISSUER_CA OUT" >&2; exit 2; }
TOOL=$1 URL=$2 CA=$3 OUT=$4
SITE=${IPA_SITE_PACKAGES:-/opt/ironic-python-agent/lib/python3.12/site-packages}
HERE=$(cd "$(dirname "$0")" && pwd)
[[ $URL == https://* ]] || { echo "ISSUER_URL must be https" >&2; exit 2; }

umask 022
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

install -D -m 0755 "$TOOL" "$ROOT/usr/local/bin/openstack-tpm-ipa"
install -D -m 0644 "$CA" "$ROOT/etc/openstack-tpm/issuer-ca.pem"
cat > "$ROOT/etc/openstack-tpm/ipa.conf" <<EOF
url = "${URL%/}"
ca = "/etc/openstack-tpm/issuer-ca.pem"
EOF

# The hardware manager, with the package metadata through which IPA finds its entry points.
install -D -m 0644 "$HERE/openstack_tpm_hwm.py" "$ROOT$SITE/openstack_tpm_hwm.py"
DIST_INFO="$ROOT$SITE/openstack_tpm_hwm-1.dist-info"
mkdir -p "$DIST_INFO"
printf 'Metadata-Version: 2.1\nName: openstack-tpm-hwm\nVersion: 1\n' > "$DIST_INFO/METADATA"
echo openstack_tpm_hwm > "$DIST_INFO/top_level.txt"
cat > "$DIST_INFO/entry_points.txt" <<EOF
[ironic_python_agent.hardware_managers]
openstack_tpm = openstack_tpm_hwm:OpenStackTPMHardwareManager

[ironic_python_agent.inspector.collectors]
openstack_tpm = openstack_tpm_hwm:collect
EOF

# The kernel applies each entry's owner and mode, also to the ramdisk's existing directories, so all are root's.
(cd "$ROOT" && find . -mindepth 1 | LC_ALL=C sort | cpio --quiet -o -H newc -R 0:0) | gzip -9 > "$OUT"
