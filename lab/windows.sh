#!/usr/bin/env bash
# Builds the lab's Windows image once, an unattended install of the Windows Server evaluation ISO in a VM on this host, cached in .state/image.
# upload puts it in Glance with a vTPM flavor; provisioning runs it when the image is cached.
#   lab/windows.sh [image|upload|all]   (default all)
set -euo pipefail
cd "$(dirname "$0")/.."
source lab/lib.sh

WORK=vm/winbuild
DOMAIN=otpm-winbuild
QCOW=$STATE/image/$WINDOWS_IMAGE.qcow2
DISK_GB=18 # the flavor's disk is 20 GB
SERIAL_PORT=45550
VIRTIO_URL=https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
CLOUDBASE_URL=https://cloudbase.it/downloads/CloudbaseInitSetup_Stable_x64.msi

find_iso() {
    local iso=${WINDOWS_ISO:-}
    [ -n "$iso" ] || iso=$(ls $STATE/image/*SERVER_EVAL_x64FRE_en-us.iso 2>/dev/null | tail -1)
    [ -s "$iso" ] || die "no Windows Server evaluation ISO in $STATE/image (or set WINDOWS_ISO)"
    echo "$iso"
}

drop_domain() {
    virsh destroy $DOMAIN >/dev/null 2>&1 || true
    virsh undefine --nvram $DOMAIN >/dev/null 2>&1 || true
}

config_iso() {
    local pw
    install -d $WORK/config
    # The build's Administrator password, used only for the autologon that runs setup.ps1; instances are reached with the keypair.
    pw="Lab-$(openssl rand -hex 12)"
    sed "s|__ADMIN_PASSWORD__|$pw|" lab/windows/autounattend.xml > $WORK/config/autounattend.xml
    cp lab/windows/setup.ps1 lab/windows/ssh-keys.ps1 $STATE/image/CloudbaseInitSetup_Stable_x64.msi $WORK/config/
    xorriso -as mkisofs -quiet -J -r -V OTPM_CONFIG -o $WORK/config.iso $WORK/config
}

# start_build ISO: the build VM, booting Windows Setup from ISO, with COM1 copied to $WORK/serial.log until it stops.
start_build() {
    qemu-img create -q -f qcow2 $WORK/disk.qcow2 ${DISK_GB}G
    virt-install --name $DOMAIN --vcpus 4 --memory 4096 --cpu host-passthrough --osinfo win2k25 --machine q35 \
        --boot uefi,hd,cdrom --import \
        --disk $WORK/disk.qcow2,bus=virtio \
        --disk "$1",device=cdrom,bus=sata,readonly=on \
        --disk $WORK/config.iso,device=cdrom,bus=sata,readonly=on \
        --disk $STATE/image/virtio-win.iso,device=cdrom,bus=sata,readonly=on \
        --network network=default,model=virtio \
        --graphics vnc,listen=127.0.0.1 --serial tcp,host=127.0.0.1:$SERIAL_PORT,mode=bind,protocol.type=raw \
        --noautoconsole >/dev/null
    (while [ "$(virsh domstate $DOMAIN 2>/dev/null)" = running ]; do
        cat < /dev/tcp/127.0.0.1/$SERIAL_PORT >> $WORK/serial.log 2>/dev/null || sleep 1
    done) &
    # The ISO's UEFI loader waits for a key press before it boots Windows Setup.
    for _ in $(seq 20); do
        virsh send-key $DOMAIN KEY_ENTER >/dev/null 2>&1 || true
        sleep 1
    done
    echo "Windows Setup is running (virsh screenshot $DOMAIN shows its screen; setup.ps1 logs to $WORK/serial.log)"
}

# wait_build: until setup.ps1 has run sysprep, which shuts the VM down; a failure of setup.ps1 leaves the VM running.
wait_build() {
    local state
    for _ in $(seq 540); do
        state=$(virsh domstate $DOMAIN 2>/dev/null || echo gone)
        [ "$state" = "shut off" ] && break
        if grep -q 'setup: FAILED' $WORK/serial.log 2>/dev/null; then
            grep -a 'setup:' $WORK/serial.log >&2
            die "setup.ps1 failed; $DOMAIN is left running"
        fi
        sleep 10
    done
    [ "$state" = "shut off" ] || die "$DOMAIN did not shut down within 90 minutes"
    grep -a 'setup:' $WORK/serial.log || true
    grep -q 'setup: sysprep' $WORK/serial.log || die "$DOMAIN shut down before setup.ps1 reached sysprep"
}

image() {
    local iso
    if [ -s $QCOW ]; then
        echo "$QCOW exists"
        return
    fi
    iso=$(find_iso)
    download $VIRTIO_URL $STATE/image/virtio-win.iso
    download $CLOUDBASE_URL $STATE/image/CloudbaseInitSetup_Stable_x64.msi
    echo "=== $WINDOWS_IMAGE: unattended install from $(basename "$iso") ==="
    drop_domain
    rm -rf $WORK
    config_iso
    start_build "$iso"
    wait_build
    drop_domain
    qemu-img convert -O qcow2 $WORK/disk.qcow2 $QCOW.part
    mv $QCOW.part $QCOW
    rm -rf $WORK
    echo "$QCOW: $(du -h $QCOW | cut -f1)"
}

upload() {
    [ -s $QCOW ] || die "$QCOW missing; run lab/windows.sh image"
    if ! os image show $WINDOWS_IMAGE >/dev/null 2>&1; then
        echo "=== Glance image $WINDOWS_IMAGE ==="
        os image create $WINDOWS_IMAGE --public --disk-format qcow2 --container-format bare --file $QCOW \
            --min-disk 20 --min-ram 2048 --property os_type=windows --property os_distro=windows \
            --property hw_machine_type=q35 --property hw_firmware_type=uefi \
            --property hw_disk_bus=virtio --property hw_vif_model=virtio >/dev/null
    fi
    if ! os flavor show $WINDOWS_FLAVOR >/dev/null 2>&1; then
        os flavor create $WINDOWS_FLAVOR --vcpus 2 --ram 4096 --disk 20 \
            --property hw:tpm_version=2.0 --property hw:tpm_model=tpm-crb --property hw:tpm_secret_security=host >/dev/null
    fi
    echo "$WINDOWS_IMAGE and $WINDOWS_FLAVOR are in the lab"
}

case ${1:-all} in
image) image ;;
upload) upload ;;
all) image && upload ;;
*) die "usage: $0 [image|upload|all]" ;;
esac
