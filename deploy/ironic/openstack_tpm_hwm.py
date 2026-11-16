"""IPA hardware manager and inspection collector of openstack-tpm, which run openstack-tpm-ipa."""
import json
import subprocess

from ironic_python_agent import errors
from ironic_python_agent import hardware
from oslo_log import log

LOG = log.getLogger(__name__)
TOOL = '/usr/local/bin/openstack-tpm-ipa'
# After Ironic's deploy.deploy (100), before write_image (80) and the disk erase steps of cleaning (10 and less).
PRIORITY = 95


def _tool(*args):
    """Run the tool; it prints one JSON object and exits non-zero on failure."""
    try:
        p = subprocess.run([TOOL] + list(args), capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, {'error': str(e)}
    LOG.info('%s %s: rc=%s stdout=%s stderr=%s', TOOL, ' '.join(args), p.returncode,
             p.stdout.strip(), p.stderr.strip())
    try:
        out = json.loads(p.stdout)
    except ValueError:
        out = {'error': (p.stderr or p.stdout).strip()}
    return p.returncode, out


class OpenStackTPMHardwareManager(hardware.HardwareManager):
    HARDWARE_MANAGER_NAME = 'OpenStackTPMHardwareManager'
    HARDWARE_MANAGER_VERSION = '1'

    def evaluate_hardware_support(self):
        return hardware.HardwareSupport.SERVICE_PROVIDER

    def get_deploy_steps(self, node, ports):
        return [{'step': 'openstack_tpm_provision', 'priority': PRIORITY, 'interface': 'deploy',
                 'reboot_requested': False, 'argsinfo': None}]

    def get_clean_steps(self, node, ports):
        return [{'step': 'openstack_tpm_clear', 'priority': PRIORITY, 'interface': 'deploy',
                 'reboot_requested': False, 'abortable': True}]

    def openstack_tpm_provision(self, node, ports):
        rc, out = _tool('deploy', '-node', node['uuid'], '-instance', node.get('instance_uuid') or '')
        if rc:
            raise errors.DeploymentError('openstack_tpm_provision: %s' % out.get('error', out))
        return out

    def openstack_tpm_clear(self, node, ports):
        rc, out = _tool('clean', '-node', node['uuid'])
        if rc:
            raise errors.CleaningError('openstack_tpm_clear: %s' % out.get('error', out))
        return out


def collect(data, failures):
    """Inspection collector that reports the TPM's EK hash as openstack_tpm.tpm_ek_sha256."""
    rc, out = _tool('ek')
    if rc or not out.get('tpm_ek_sha256'):
        failures.add('openstack_tpm: cannot read the EK: %s', out.get('error', out))
        return
    data['openstack_tpm'] = {'tpm_ek_sha256': out['tpm_ek_sha256']}
