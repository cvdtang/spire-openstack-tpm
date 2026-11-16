#!/usr/bin/env bash
# Sets up sushy-tools and the node bm-1 on bmc; runs as root with its files in the current directory.
set -euo pipefail

SUSHY_TOOLS=2.2.0
DISK=/var/lib/libvirt/images/bm-1.qcow2

if [ ! -x /opt/sushy/bin/sushy-emulator ]; then
    python3 -m venv --system-site-packages /opt/sushy
    /opt/sushy/bin/pip install -q "sushy-tools==$SUSHY_TOOLS"
fi
install -D -m 0644 sushy.conf /etc/sushy/sushy.conf
install -m 0644 sushy-emulator.service /etc/systemd/system/sushy-emulator.service

[ -e $DISK ] || qemu-img create -q -f qcow2 $DISK 20G
virsh dominfo bm-1 >/dev/null 2>&1 || virsh define bm-1.xml >/dev/null
# libvirt's default NAT network is not needed here.
virsh net-autostart default --disable >/dev/null 2>&1 || true
virsh net-destroy default >/dev/null 2>&1 || true

systemctl daemon-reload
systemctl enable -q sushy-emulator
systemctl restart sushy-emulator
