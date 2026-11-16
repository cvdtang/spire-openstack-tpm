#!/usr/bin/env bash
# Deploys openstack-tpm on the lab, from the Kolla config and a new Compose project to the hypervisor hook and the IPA ramdisk.
# `deploy.sh kolla-config` only copies the Kolla config; the host PKI in .state/pki is made once and kept.
set -euo pipefail
source lab/lib.sh

KOLLA_SERVICES=nova,placement,ironic
PROVISION=$STATE/provision
PKI=$STATE/pki

sha256() { sha256sum "$@" | cut -d' ' -f1; }
# short_hash: a short digest of stdin, used to detect changed inputs.
short_hash() { sha256sum | cut -c1-16; }
reproducible_tar() { tar -cf - --sort=name --mtime=@0 --owner=0 --group=0 "$@"; }

# kolla_config copies the Kolla config to compute-1 and returns non-zero when it is unchanged.
kolla_config() {
    local sum
    sum=$( (reproducible_tar -C deploy/kolla globals.d config; reproducible_tar -C lab/kolla config) | short_hash)
    if [ "$(ctl cat /etc/kolla/.openstack-tpm.sum 2>/dev/null || true)" = "$sum" ]; then
        return 1
    fi
    tar -C deploy/kolla -cf - globals.d config |
        ctl_in sh -c 'rm -rf /etc/kolla/config /etc/kolla/globals.d && tar -C /etc/kolla --no-same-owner -xf -'
    tar -C lab/kolla -cf - config |
        ctl_in sh -c 'tar -C /etc/kolla --no-same-owner -xf - && ln -f /opt/ipa/ironic-agent.kernel /opt/ipa/ironic-agent.initramfs /etc/kolla/config/ironic/'
    echo "$sum" | put compute-1 /etc/kolla/.openstack-tpm.sum
}

preflight() {
    require_binaries
    docker image inspect $ISSUER_IMAGE >/dev/null 2>&1 || die "$ISSUER_IMAGE missing; run just build"
    [ -s $PROVISION/appcred-id ] || die "not provisioned; run just provision"
    wait_until 600 "Keystone" os token issue
}

step_kolla() {
    echo "=== [1/5] Kolla config ==="
    if kolla_config; then
        echo "deploy/kolla or lab/kolla/config changed: kolla-ansible reconfigure --tags $KOLLA_SERVICES"
        kolla reconfigure --tags $KOLLA_SERVICES
    else
        echo "unchanged"
    fi
}

# leaf NAME SUBJECT SAN EKU: a certificate from the host CA, made once.
leaf() {
    local name=$1 subject=$2 san=$3 eku=$4
    [ -s $PKI/$name.crt ] && return
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "$subject" \
        -keyout $PKI/$name.key -out $PKI/$name.csr 2>/dev/null
    openssl x509 -req -in $PKI/$name.csr -CA $PKI/ca.crt -CAkey $PKI/ca.key -days 3650 \
        -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' "$san" "$eku") -out $PKI/$name.crt 2>/dev/null
    rm -f $PKI/$name.csr
}

# host_pki: the host CA with the issuer's server certificate and compute-1's client certificate, kept across deploys.
host_pki() {
    if [ ! -s $PKI/ca.crt ]; then
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
            -subj "/O=openstack-tpm lab/CN=openstack-tpm lab host CA" \
            -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
            -keyout $PKI/ca.key -out $PKI/ca.crt 2>/dev/null
        rm -f $PKI/server.* $PKI/compute-1.*
    fi
    leaf server /CN=issuer IP:$HOST_IP serverAuth
    leaf compute-1 /CN=compute-1 DNS:compute-1 clientAuth
}

bao() { docker exec -i -e BAO_ADDR=$OPENBAO_ADDR -e BAO_TOKEN=$OPENBAO_TOKEN openbao bao "$@"; }

# start_openbao: a fresh OpenBao with the Transit keys and the issuer's policy; sets ISSUER_TOKEN.
start_openbao() {
    compose up -d openbao
    wait_until 60 "OpenBao" bao status
    bao secrets enable transit >/dev/null </dev/null
    # Non-exportable Transit keys; the clear key is P-256 because a node's TPM verifies its signatures.
    bao write transit/keys/$ISSUING_KEY type=ecdsa-p384 exportable=false allow_plaintext_backup=false >/dev/null </dev/null
    bao write transit/keys/$CLEAR_KEY type=ecdsa-p256 exportable=false allow_plaintext_backup=false >/dev/null </dev/null
    # The issuer may only sign with the keys and read them.
    bao policy write issuer - >/dev/null <<EOF
path "transit/sign/$ISSUING_KEY" { capabilities = ["update"] }
path "transit/keys/$ISSUING_KEY" { capabilities = ["read"] }
path "transit/sign/$CLEAR_KEY" { capabilities = ["update"] }
path "transit/keys/$CLEAR_KEY" { capabilities = ["read"] }
EOF
    ISSUER_TOKEN=$(bao token create -orphan -period=768h -policy=issuer -display-name=issuer -field=token </dev/null)
}

issuer_config() {
    # The trust anchor is the issuing key's self-signed CA certificate, made with the issuer's own token.
    docker run --rm --network host -e BAO_ADDR=$OPENBAO_ADDR -e BAO_TOKEN="$ISSUER_TOKEN" -e ISSUER_ISSUING_KEY=$ISSUING_KEY \
        $ISSUER_IMAGE ca -cn "openstack-tpm lab issuing ($REGION)" > $STATE/issuer/ca.pem
    cp $STATE/issuer/ca.pem $STATE/issuer/etc/issuing.crt
    cp $PKI/server.crt $PKI/server.key $STATE/issuer/etc/
    cp $PKI/ca.crt $STATE/issuer/etc/host-ca.pem
    (umask 077; cat > $STATE/issuer/issuer.env <<EOF
ISSUER_TLS_CERT=/etc/issuer/server.crt
ISSUER_TLS_KEY=/etc/issuer/server.key
ISSUER_CLIENT_CA=/etc/issuer/host-ca.pem
ISSUER_REGION=$REGION
ISSUER_ISSUING_KEY=$ISSUING_KEY
ISSUER_ISSUING_CERT=/etc/issuer/issuing.crt
ISSUER_CLEAR_KEY=$CLEAR_KEY
BAO_ADDR=$OPENBAO_ADDR
BAO_TOKEN=$ISSUER_TOKEN
OS_AUTH_URL=$KEYSTONE_URL
OS_USERNAME=openstack-tpm-issuer
OS_PASSWORD=$(< $PROVISION/openstack-tpm-issuer.password)
OS_PROJECT_NAME=service
EOF
    )
}

# spire_config: the variables of the SPIRE server configs, expanded with -expandEnv, and the files they reference.
spire_config() {
    local plugin_sum project_id user
    plugin_sum=$(sha256 $BIN/openstack-tpm-spire-server)
    project_id=$(os project show $TENANT -f value -c id)
    cp $STATE/issuer/ca.pem $STATE/spire/tenant/ca.pem
    cp $STATE/issuer/ca.pem $STATE/spire/central/ca.pem
    cp $PROVISION/appcred-secret $STATE/spire/tenant/os-appcred
    for user in $CENTRAL_USER $NOROLE_USER; do
        cp $PROVISION/$user.password $STATE/spire/central/os-password-$user
    done
    cat > $STATE/spire/tenant.env <<EOF
BIND_PORT=$SPIRE_PORT
TRUST_DOMAIN=$SPIRE_TRUST_DOMAIN
LOG_LEVEL=DEBUG
PLUGIN_SUM=$plugin_sum
PROJECT_ID=$project_id
KEYSTONE_URL=$KEYSTONE_URL
APPCRED_ID=$(< $PROVISION/appcred-id)
EOF
    cat > $STATE/spire/central.env <<EOF
BIND_PORT=$CENTRAL_PORT
TRUST_DOMAIN=$CENTRAL_TRUST_DOMAIN
LOG_LEVEL=DEBUG
PLUGIN_SUM=$plugin_sum
DOMAIN_ID=$DOMAIN_ID
EOF
}

# spire_agent OS: spire-agent from SPIRE's release archive for OS, cached in .state/image.
spire_agent() {
    local name=spire-$SPIRE_VERSION
    local url=https://github.com/spiffe/spire/releases/download/v$SPIRE_VERSION
    case $1 in
    linux)
        download $url/$name-linux-amd64-musl.tar.gz $STATE/image/$name-linux-amd64-musl.tar.gz
        tar -xOzf $STATE/image/$name-linux-amd64-musl.tar.gz $name/bin/spire-agent
        ;;
    windows)
        download $url/$name-windows-amd64.zip $STATE/image/$name-windows-amd64.zip
        unzip -p $STATE/image/$name-windows-amd64.zip $name/bin/spire-agent.exe
        ;;
    esac
}

agent_files() {
    local dir os exe
    for dir in $BIN/*/; do
        os=$(basename $dir)
        exe=
        if [ $os = windows ]; then exe=.exe; fi
        install -d $STATE/agent/$os
        spire_agent $os > $STATE/agent/$os/spire-agent$exe
        install -m 0755 $BIN/$os/openstack-tpm-spire-agent$exe $STATE/agent/$os/
    done
}

step_compose() {
    local c
    echo "=== [2/5] Compose project: OpenBao, CA certificate, issuer, SPIRE servers ==="
    install -d -m 0700 $PKI $STATE/issuer $STATE/issuer/etc $STATE/spire $STATE/spire/tenant $STATE/spire/central
    host_pki
    compose down --remove-orphans -t 5 >/dev/null 2>&1 || true
    start_openbao
    issuer_config
    spire_config
    agent_files
    compose up -d issuer spire-server spire-server-central
    wait_until 60 "issuer healthy" curl -fsS $ISSUER_HEALTH_URL
    for c in $SPIRE_CONTAINER $CENTRAL_CONTAINER; do
        wait_until 60 "$c healthy" spire $c healthcheck
    done
}

step_hypervisor_hook() {
    local tss
    echo "=== [3/5] hypervisor hook on compute-1 ==="
    install -d $WORK/hv
    cp $PKI/compute-1.crt $WORK/hv/client.crt
    cp $PKI/compute-1.key $WORK/hv/client.key
    cp $PKI/ca.crt $WORK/hv/ca.pem
    cp $BIN/openstack-tpm-swtpm deploy/hypervisor/swtpm_setup.conf deploy/hypervisor/install.sh $WORK/hv/
    tar -C $WORK/hv -cf - . | ctl_in sh -c 'rm -rf /tmp/hv && mkdir -m 0700 /tmp/hv && tar -C /tmp/hv -xf -'
    tss=$(ctl docker exec nova_libvirt sh -c 'echo $(id -u tss):$(id -g tss)')
    ctl bash /tmp/hv/install.sh /tmp/hv $ISSUER_URL/v1/vm/certificates "$tss"
    ctl rm -rf /tmp/hv
    ctl docker exec -u tss nova_libvirt sh -c \
        'grep -q "^create_certs_tool = /etc/openstack-tpm/openstack-tpm-swtpm" /etc/swtpm_setup.conf && test -r /etc/openstack-tpm/client.key' \
        || die "nova_libvirt does not see the hypervisor hook"
}

# step_ipa_ramdisk: nodes boot the stock ramdisk with the overlay appended, uploaded again when any of its inputs changes.
step_ipa_ramdisk() {
    local build kernel ramdisk old i
    echo "=== [4/5] IPA ramdisk with the openstack-tpm overlay ==="
    ipa_images
    build=$(cat $BIN/openstack-tpm-ipa deploy/ironic/openstack_tpm_hwm.py deploy/ironic/build-overlay.sh $PKI/ca.crt \
        <(echo $ISSUER_URL) $STATE/image/$IPA_IMAGE.kernel | short_hash)
    kernel=$(os image list --name ipa-kernel --property openstack_tpm_build=$build -f value -c ID)
    ramdisk=$(os image list --name ipa-ramdisk --property openstack_tpm_build=$build -f value -c ID)
    if [ -n "$kernel" ] && [ -n "$ramdisk" ]; then
        echo "up to date ($build)"
        return
    fi
    old=$(os image list --name ipa-ramdisk -f value -c ID; os image list --name ipa-kernel -f value -c ID)
    bash deploy/ironic/build-overlay.sh $BIN/openstack-tpm-ipa $ISSUER_URL $PKI/ca.crt $WORK/overlay.cpio.gz
    cat $STATE/image/$IPA_IMAGE.initramfs $WORK/overlay.cpio.gz > $WORK/ipa-ramdisk
    kernel=$(os image create ipa-kernel --public --disk-format aki --container-format aki \
        --file $STATE/image/$IPA_IMAGE.kernel --property openstack_tpm_build=$build -f value -c id)
    ramdisk=$(os image create ipa-ramdisk --public --disk-format ari --container-format ari \
        --file $WORK/ipa-ramdisk --property openstack_tpm_build=$build -f value -c id)
    if os baremetal node show $BM_NODE >/dev/null 2>&1; then
        os baremetal node set $BM_NODE --driver-info deploy_kernel=$kernel --driver-info deploy_ramdisk=$ramdisk
    fi
    for i in $old; do
        os image delete "$i"
    done
    echo "uploaded ipa-kernel and ipa-ramdisk ($build)"
}

# issuer_mtls_ok: compute-1 reaches the issuer over mTLS when an empty request gets a 400 from the service.
issuer_mtls_ok() {
    local code
    code=$(ctl curl -s -o /dev/null -w '%{http_code}' --cacert /etc/openstack-tpm/hv/ca.pem \
        --cert /etc/openstack-tpm/hv/client.crt --key /etc/openstack-tpm/hv/client.key -d '{}' $ISSUER_URL/v1/vm/certificates)
    [ "$code" = 400 ] || die "compute-1 -> issuer mTLS check: HTTP $code"
}
# compute_up: every nova-compute service (libvirt and Ironic) reports up.
compute_up() {
    local states
    states=$(os compute service list --service nova-compute -f value -c State)
    [ -n "$states" ] && ! grep -qvx up <<<"$states"
}
hypervisor_up() { os hypervisor list -f value -c "Hypervisor Hostname" -c State | grep -qx "compute-1 up"; }

step_health() {
    echo "=== [5/5] health ==="
    issuer_mtls_ok
    echo "compute-1 -> issuer mTLS: ok"
    # After a start or reset Nova schedules nothing until both nova-compute services report again.
    wait_until 600 "nova-compute up" compute_up
    wait_until 300 "hypervisor compute-1 reported" hypervisor_up
    compose ps --format '{{.Name}} {{.Status}}'
}

if [ "${1:-}" = kolla-config ]; then
    kolla_config || true
    exit 0
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

preflight
step_kolla
step_compose
step_hypervisor_hook
step_ipa_ramdisk
step_health
echo "openstack-tpm deployed"
