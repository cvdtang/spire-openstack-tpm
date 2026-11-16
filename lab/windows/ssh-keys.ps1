# Installs the instance's keypair for administrators at first boot, as a cloudbase-init local script.
$ErrorActionPreference = 'Stop'
Start-Service sshd
$md = (Invoke-WebRequest -UseBasicParsing http://169.254.169.254/openstack/latest/meta_data.json).Content | ConvertFrom-Json
Set-Content -Encoding ascii C:\ProgramData\ssh\administrators_authorized_keys @($md.public_keys.PSObject.Properties.Value)
