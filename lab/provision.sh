#!/usr/bin/env bash
# Provisions the lab once after `just vms` and `just build`, from Kolla (snapshot kolla) to the enrolled node (snapshot provisioned).
# It only creates, so a failed run is retried with `just reset kolla && just provision`.
set -euo pipefail
source lab/lib.sh

KOLLA_BRANCH=stable/2026.2
CIRROS=0.6.3
PROVISION=$STATE/provision          # passwords and the application credential

has_snapshot() { virsh snapshot-info otpm-compute-1 "$1" >/dev/null 2>&1; }
# password NAME: a generated password, stored in $PROVISION on first use.
password() {
    [ -s $PROVISION/$1.password ] || (umask 077; openssl rand -hex 24 > $PROVISION/$1.password)
    cat $PROVISION/$1.password
}
# allow_ping_ssh GROUP: ICMP and SSH ingress rules in a security group.
allow_ping_ssh() {
    os security group rule create --ingress --protocol icmp "$1" >/dev/null
    os security group rule create --ingress --protocol tcp --dst-port 22 "$1" >/dev/null
}
bm() { os baremetal "$@"; }

install_kolla_ansible() {
    ctl_in bash -s -- "$KOLLA_BRANCH" <<'EOS'
set -euo pipefail
[ ! -x /opt/kolla-venv/bin/kolla-ansible ] || exit 0
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-venv python3-dev gcc git libffi-dev libssl-dev >/dev/null
python3 -m venv /opt/kolla-venv
/opt/kolla-venv/bin/pip install -q -U pip
/opt/kolla-venv/bin/pip install -q "git+https://opendev.org/openstack/kolla-ansible@$1"
PATH=/opt/kolla-venv/bin:$PATH kolla-ansible install-deps >/dev/null
share=/opt/kolla-venv/share/kolla-ansible
install -d -m 0755 /etc/kolla
cp $share/etc_examples/kolla/passwords.yml /etc/kolla/passwords.yml
/opt/kolla-venv/bin/kolla-genpwd >/dev/null
# All-in-one inventory with the real host name, which Kolla writes to /etc/hosts, and Nova compute in the baremetal group.
sed -e 's/^localhost .*ansible_connection=local$/compute-1 ansible_connection=local ansible_python_interpreter=\/usr\/bin\/python3/' \
    $share/ansible/inventory/all-in-one > /etc/kolla/multinode
sed -i '/^\[baremetal:children\]$/a compute' /etc/kolla/multinode
EOS
}

deploy_kolla() {
    local f
    echo "=== Kolla-Ansible $KOLLA_BRANCH on compute-1 ==="
    install_kolla_ansible
    # With Ironic enabled Kolla requires the IPA images in its config, although nodes boot the ones in Glance.
    ipa_images
    ctl install -d -m 0755 /opt/ipa
    for f in kernel initramfs; do
        ctl test -s /opt/ipa/ironic-agent.$f || put compute-1 /opt/ipa/ironic-agent.$f < $STATE/image/$IPA_IMAGE.$f
    done
    put compute-1 /etc/kolla/globals.yml < lab/kolla/globals.yml
    bash lab/deploy.sh kolla-config
    # bootstrap-servers installs Docker CE.
    kolla bootstrap-servers
    kolla prechecks
    kolla deploy
    kolla post-deploy
    bash lab/vms.sh snapshot kolla
}

create_networks() {
    local sg
    echo "=== networks and Cirros ==="
    # public1 is a flat network on otpm-mgmt's L2 with libvirt as gateway and Neutron's DHCP, which the node boots from.
    os network create public1 --external --share --provider-network-type flat --provider-physical-network physnet1 >/dev/null
    os subnet create public1-subnet --network public1 --dhcp --subnet-range 192.168.150.0/24 \
        --gateway $HOST_IP --dns-nameserver 1.1.1.1 --allocation-pool start=192.168.150.150,end=192.168.150.199 >/dev/null
    os network create $OTHER_NETWORK >/dev/null
    os subnet create demo-subnet --network $OTHER_NETWORK --subnet-range 10.0.0.0/24 --dns-nameserver 1.1.1.1 >/dev/null
    os router create demo-router >/dev/null
    os router set --external-gateway public1 demo-router
    os router add subnet demo-router demo-subnet
    download "https://download.cirros-cloud.net/$CIRROS/cirros-$CIRROS-x86_64-disk.img" $STATE/image/cirros.img
    os image create $CIRROS_IMAGE --public --disk-format qcow2 --container-format bare --file $STATE/image/cirros.img >/dev/null
    # Ping and SSH in the admin project's default security group.
    sg=$(os security group list --project admin -f value -c ID -c Name | awk '$2 == "default" {print $1}')
    allow_ping_ssh "$sg"
}

create_identities() {
    local rules
    echo "=== Keystone: issuer, $TENANT and its application credential, central server users ==="
    # The issuer holds only the role openstack_tpm_issuer, on the service project and inherited on the domain; its reads are defined in the Nova, Placement and Ironic policies.
    os user create --domain default --password "$(password openstack-tpm-issuer)" openstack-tpm-issuer >/dev/null
    os role create openstack_tpm_issuer >/dev/null
    os role add --project service --user openstack-tpm-issuer openstack_tpm_issuer
    os role add --domain default --user openstack-tpm-issuer --inherited openstack_tpm_issuer
    TENANT_ID=$(os project create --domain default --tag env-lab $TENANT -f value -c id)
    # The admin user boots tenant instances and must be in the tenant to snapshot them, since Nova reads the vTPM secret as the requester.
    os role add --project $TENANT --user admin member
    os role add --project $TENANT --user admin admin

    # The tenant's SPIRE user owns an application credential limited to the server plugin's two reads.
    os user create --domain default --password "$(password $TENANT-spire)" $TENANT-spire >/dev/null
    os role add --project $TENANT --user $TENANT-spire reader
    rules=$(jq -nc --arg project "$TENANT_ID" '[
        {service: "compute",  method: "GET", path: "/v2.1/servers/*"},
        {service: "identity", method: "GET", path: "/v3/projects/\($project)"}]')
    os --os-username $TENANT-spire --os-password "$(password $TENANT-spire)" --os-project-name $TENANT \
        application credential create spire-openstack-tpm --role reader --access-rules "$rules" -f json > $PROVISION/appcred.json
    (umask 077
     jq -r .ID < $PROVISION/appcred.json > $PROVISION/appcred-id
     jq -r .Secret < $PROVISION/appcred.json > $PROVISION/appcred-secret)
    rm -f $PROVISION/appcred.json

    # Users for the central SPIRE servers the e2e tests start, one with reader inherited on the Default domain and one without roles.
    os user create --domain default --password "$(password $CENTRAL_USER)" $CENTRAL_USER >/dev/null
    os role add --domain default --user $CENTRAL_USER --inherited reader
    os user create --domain default --password "$(password $NOROLE_USER)" $NOROLE_USER >/dev/null
}

create_tenant_network() {
    local sg
    echo "=== $NETWORK, router to public1, security groups ==="
    os network create --project $TENANT_ID $NETWORK >/dev/null
    os subnet create --project $TENANT_ID --network $NETWORK --subnet-range 10.0.20.0/24 --dns-nameserver 1.1.1.1 $TENANT-subnet >/dev/null
    os router create --project $TENANT_ID $TENANT-router >/dev/null
    os router set --external-gateway public1 $TENANT-router
    os router add subnet $TENANT-router $TENANT-subnet
    sg=$(os security group create --project $TENANT_ID $SECURITY_GROUP -f value -c id)
    allow_ping_ssh "$sg"
}

create_flavors_and_images() {
    echo "=== flavors, keypair, $LINUX_IMAGE ==="
    os flavor create $LINUX_FLAVOR --vcpus 2 --ram 2048 --disk 10 \
        --property hw:tpm_version=2.0 --property hw:tpm_model=tpm-crb --property hw:tpm_secret_security=host >/dev/null
    os flavor create $PLAIN_FLAVOR --vcpus 2 --ram 2048 --disk 10 >/dev/null
    # Bare metal: the flavor asks Placement for one node of the resource class.
    os flavor create $BM_FLAVOR --vcpus 2 --ram 6144 --disk 20 \
        --property resources:CUSTOM_BAREMETAL=1 --property resources:VCPU=0 \
        --property resources:MEMORY_MB=0 --property resources:DISK_GB=0 >/dev/null
    [ -f $STATE/openstack-tpm ] || ssh-keygen -q -t ed25519 -N '' -C openstack-tpm -f $STATE/openstack-tpm
    os keypair create --public-key $STATE/openstack-tpm.pub $KEYPAIR >/dev/null
    # The stock Ubuntu 26.04 cloud image boots virtual machines and the node; guests install the agent at first boot.
    download $RESOLUTE_IMAGE_URL $STATE/image/resolute-server-cloudimg-amd64.img
    os image create $LINUX_IMAGE --public --disk-format qcow2 --container-format bare \
        --file $STATE/image/resolute-server-cloudimg-amd64.img >/dev/null

    if [ -s $STATE/image/$WINDOWS_IMAGE.qcow2 ]; then
        bash lab/windows.sh upload
    else
        echo "warning: no $WINDOWS_IMAGE image in $STATE/image, so no Windows guests (just windows builds and uploads it)" >&2
    fi
}

# node_unreserved UUID: Nova keeps a cleaned node reserved in Placement until its next periodic run.
node_unreserved() {
    [ "$(os resource provider inventory show "$1" CUSTOM_BAREMETAL -f value -c reserved)" = 0 ]
}

enrol_node() {
    local uuid ek
    echo "=== node $BM_NODE: enrolment, inspection, cleaning ==="
    # The conductor reaches sushy-tools on bmc.
    uuid=$(bm node create --driver redfish --name $BM_NODE \
        --driver-info redfish_address=http://$BMC_IP:$BMC_PORT \
        --driver-info redfish_system_id=/redfish/v1/Systems/$BM_UUID \
        --driver-info redfish_username=admin --driver-info redfish_password=password \
        --driver-info deploy_kernel="$(os image show ipa-kernel -f value -c id)" \
        --driver-info deploy_ramdisk="$(os image show ipa-ramdisk -f value -c id)" \
        --boot-interface ipxe --deploy-interface direct --inspect-interface agent \
        --resource-class baremetal \
        --property cpus=2 --property memory_mb=6144 --property local_gb=20 --property cpu_arch=x86_64 \
        --property capabilities=boot_mode:uefi -f value -c uuid)
    bm port create $BM_MAC --node $uuid --physical-network physnet1 >/dev/null
    # Inspection records the node's EK, and cleaning runs the clean step once, which checks the path to the issuer.
    bm node manage --wait 300 $BM_NODE
    bm node inspect --wait 900 $BM_NODE
    ek=$(bm node inventory save $BM_NODE | jq -r '.plugin_data.openstack_tpm.tpm_ek_sha256 // empty')
    [ -n "$ek" ] || die "$BM_NODE has no EK record after inspection"
    bm node provide --wait 1200 $BM_NODE
    wait_until 600 "$BM_NODE free in Placement" node_unreserved $uuid
    echo "$BM_NODE: $(bm node show $BM_NODE -f value -c provision_state), EK $ek"
}

require_binaries
if has_snapshot kolla; then
    echo "=== Kolla: snapshot kolla exists, skipped ==="
else
    deploy_kolla
fi

# Keystone takes a few minutes after the VMs boot.
wait_until 600 "Keystone" os token issue
rm -rf $PROVISION && install -d -m 0700 $PROVISION

create_networks
create_identities
create_tenant_network
create_flavors_and_images

echo "=== provider side (lab/deploy.sh) ==="
bash lab/deploy.sh

enrol_node
bash lab/vms.sh snapshot provisioned
echo "provisioned; snapshots kolla and provisioned of $VMS"
