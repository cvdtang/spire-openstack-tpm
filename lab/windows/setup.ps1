# Prepares the lab's Windows image at the build VM's first logon: cloudbase-init, OpenSSH, then sysprep and shutdown.
# Progress goes to COM1, which lab/windows.sh follows; a failure leaves the VM running for inspection.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$com = New-Object System.IO.Ports.SerialPort COM1, 115200, None, 8, One
$com.Open()
function Log($m) { $com.WriteLine("setup: $m") }
trap { Log "FAILED: $_ at $($_.InvocationInfo.PositionMessage)"; $com.Close(); exit 1 }

Log 'cloudbase-init'
# Its default configuration reads the OpenStack metadata service; its log also goes to COM1, which Nova's console log shows.
$cb = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init'
$msi = Join-Path $here CloudbaseInitSetup_Stable_x64.msi
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$msi`" /qn /norestart LOGGINGSERIALPORTNAME=COM1"
if ($p.ExitCode -notin 0, 3010) { throw "msiexec exited with $($p.ExitCode)" }
# Its SSH key plugin writes to the user's profile, which sshd ignores for administrators, so ssh-keys.ps1 installs the keypair.
Copy-Item (Join-Path $here 'ssh-keys.ps1') "$cb\LocalScripts\" -Force
# Started at boot, it would race sysprep's specialize pass and break it with its hostname reboot, so SetupComplete.cmd starts it.
Set-Service cloudbase-init -StartupType Manual
New-Item -ItemType Directory -Force C:\Windows\Setup\Scripts | Out-Null
Set-Content -Encoding ascii C:\Windows\Setup\Scripts\SetupComplete.cmd 'sc.exe config cloudbase-init start= auto', 'net start cloudbase-init'

Log 'OpenSSH server'
# Windows Server 2025 ships sshd set to Manual and its firewall rule for the Private profile only; an instance's network is Public.
Set-Service sshd -StartupType Automatic
Set-NetFirewallRule -Name OpenSSH-Server-In-TCP -Enabled True -Profile Any

Log 'sysprep'
$unattend = 'C:\Windows\Temp\cloudbase-init-unattend.xml'
Copy-Item "$cb\conf\Unattend.xml" $unattend -Force
$com.Close()
$p = Start-Process C:\Windows\System32\Sysprep\sysprep.exe -Wait -PassThru -ArgumentList "/generalize /oobe /shutdown /unattend:$unattend"
# Sysprep shuts the VM down when it succeeds; still running a minute later means it failed.
Start-Sleep 60
$com.Open()
Log "sysprep exited with $($p.ExitCode)"
Get-Content C:\Windows\System32\Sysprep\Panther\setuperr.log -ErrorAction SilentlyContinue | ForEach-Object { Log $_ }
Log 'FAILED: sysprep'
$com.Close()
