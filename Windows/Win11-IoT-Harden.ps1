<# 
.SYNOPSIS
  Hardens a Windows 11 IoT (non-domain) VM on ESXi to a CIS-like baseline, enables RDP (with NLA),
  and can open firewall for FileZilla Server (FTP control + passive TCP range).

.DESCRIPTION
  - Verifies elevation
  - Sets safe execution policy
  - Enables PowerShell logging (Script Block + Transcript policy)
  - Disables SMBv1, Guest, Remote Assistance, Autorun, NetBIOS over TCP/IP
  - Tightens LSA policies and password complexity
  - Enables/sets Windows Firewall across profiles
  - Applies useful auditpol categories
  - Sets Windows Update AU policy (download & notify)
  - Enables RDP + NLA and opens firewall
  - (Optional) Hardens Microsoft Defender
  - (Optional) Configures firewall rules for FileZilla Server: TCP 21 + passive TCP range (UDP optional)
  - Outputs verification artifacts in C:\Logs and transcripts in C:\PowerShellTranscripts

.PARAMETER HardenDefender
  Apply stronger Defender/SmartScreen preferences.

.PARAMETER FtsFtpServer
  Configure firewall rules for FileZilla Server (TCP 21 + passive range on TCP; UDP optional).

.PARAMETER FtpPassiveStart
  Start of passive range (default: 50000).

.PARAMETER FtpPassiveEnd
  End of passive range (default: 58000).

.PARAMETER FtpIncludeUdp
  Also open UDP for the passive range (off by default).

.NOTES
  - Test in a lab first; some changes may require reboot.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [switch]$HardenDefender,
  [switch]$FtsFtpServer,
  [int]$FtpPassiveStart = 50000,
  [int]$FtpPassiveEnd   = 58000,
  [switch]$FtpIncludeUdp
)

# -------------------- Helpers --------------------
function Assert-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw "This script must be run as Administrator." }
}

function Ensure-Path {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path $Path)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
  }
}

function Set-RegistryValue {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][object]$Value,
    [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
  )
  if ($PSCmdlet.ShouldProcess("$Path\$Name","Set to $Value")) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
  }
}

function Invoke-Safe {
  param([scriptblock]$Script,[string]$Action)
  try { & $Script }
  catch { Write-Warning "$Action failed: $($_.Exception.Message)" }
}

function Ensure-FirewallRule {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$DisplayName,
    [Parameter(Mandatory)][ValidateSet('Inbound','Outbound')]$Direction,
    [Parameter(Mandatory)][ValidateSet('TCP','UDP')]$Protocol,
    [Parameter(Mandatory)][string]$LocalPort,
    [ValidateSet('Allow','Block')]$Action = 'Allow',
    [string]$Profile = 'Any'
  )
  $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
  if (-not $existing) {
    New-NetFirewallRule -Name $Name -DisplayName $DisplayName -Direction $Direction `
      -Protocol $Protocol -LocalPort $LocalPort -Action $Action -Profile $Profile | Out-Null
  } else {
    $filter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existing
    $needsRecreate = ($null -eq $filter) -or ($filter.Protocol -ne $Protocol) -or ($filter.LocalPort -ne $LocalPort)
    if ($needsRecreate) {
      Remove-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
      New-NetFirewallRule -Name $Name -DisplayName $DisplayName -Direction $Direction `
        -Protocol $Protocol -LocalPort $LocalPort -Action $Action -Profile $Profile | Out-Null
    } else {
      Set-NetFirewallRule -DisplayName $DisplayName -Direction $Direction -Action $Action -Profile $Profile | Out-Null
    }
  }
}

function Get-FtpPassiveRangeString {
  param(
    [Parameter(Mandatory)][int]$Start,
    [Parameter(Mandatory)][int]$End
  )
  if ($Start -lt 1 -or $End -gt 65535 -or $Start -gt $End) {
    throw "Invalid passive range: $Start-$End. Must be 1–65535 and Start <= End."
  }
  "$Start-$End"
}

$ErrorActionPreference = 'Stop'

# -------------------- Prep & Logging --------------------
Assert-Admin

$transcriptDir = 'C:\PowerShellTranscripts'
$logDir        = 'C:\Logs'
Ensure-Path $transcriptDir
Ensure-Path $logDir

$tsFile = Join-Path $transcriptDir ("IoT_Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt")
Start-Transcript -Path $tsFile -Force | Out-Null

Write-Host "== Windows 11 IoT Hardening Start =="

# Execution policy (local machine, RemoteSigned)
if ($PSCmdlet.ShouldProcess("ExecutionPolicy","Set RemoteSigned (LocalMachine)")) {
  try { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force }
  catch { Write-Warning "Execution policy set failed (may be governed by policy): $($_.Exception.Message)" }
}

# PowerShell logging: ScriptBlock + Transcription policy
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name 'EnableScriptBlockLogging' -Value 1
Set-RegistryValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Value 1
Set-RegistryValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Value $transcriptDir -Type ([Microsoft.Win32.RegistryValueKind]::String)
Set-RegistryValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'IncludeInvocationHeader' -Value 1

# -------------------- Core CIS-like Controls --------------------

# 1) Disable SMBv1
Invoke-Safe {
  if ($PSCmdlet.ShouldProcess("SMB1Protocol","Disable feature")) {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
  }
} "Disable SMBv1"

# 2) Disable Guest account (if present)
Invoke-Safe {
  $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
  if ($guest -and $guest.Enabled) {
    if ($PSCmdlet.ShouldProcess("LocalUser:Guest","Disable")) { Disable-LocalUser -Name 'Guest' }
  }
} "Disable Guest"

# 3) Enforce password complexity (Local Security Policy)
Invoke-Safe {
  $cfg = Join-Path $env:TEMP 'secpol.cfg'
  secedit /export /cfg $cfg | Out-Null
  $content = Get-Content $cfg -Raw
  $content = $content `
    -replace 'PasswordComplexity\s*=\s*0','PasswordComplexity = 1' `
    -replace 'MinimumPasswordLength\s*=\s*\d+','MinimumPasswordLength = 12' `
    -replace 'MaximumPasswordAge\s*=\s*\d+','MaximumPasswordAge = 60' `
    -replace 'MinimumPasswordAge\s*=\s*\d+','MinimumPasswordAge = 1'
  if ($PSCmdlet.ShouldProcess("Local Security Policy","Apply password policy + min length 12")) {
    $content | Set-Content -Path $cfg -Encoding Unicode
    secedit /configure /db C:\Windows\Security\local.sdb /cfg $cfg /areas SECURITYPOLICY | Out-Null
  }
} "Enforce password policy"

# 4) Enable audit categories
Invoke-Safe {
  if ($PSCmdlet.ShouldProcess("Audit Policy","Enable success/failure for Logon/AccountLogon/PrivilegeUse/ObjectAccess/PolicyChange/AccountManagement")) {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable                 | Out-Null
    auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable        | Out-Null
    auditpol /set /subcategory:"Privilege Use" /success:disable /failure:enable       | Out-Null  # success noisy
    auditpol /set /subcategory:"Object Access" /success:enable /failure:enable        | Out-Null
    auditpol /set /subcategory:"Policy Change" /success:enable /failure:enable        | Out-Null
    auditpol /set /subcategory:"Account Management" /success:enable /failure:enable   | Out-Null
  }
} "Audit policy"

# 5) LSA hardening
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1

# 6) Disable Autorun
Set-RegistryValue -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255

# -------------------- Network & Remote Access --------------------

# Disable Remote Assistance
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0

# Enable RDP + NLA + firewall
Invoke-Safe {
  if ($PSCmdlet.ShouldProcess("RDP","Enable RDP and NLA; open firewall")) {
    # Allow RDP connections
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
    # Require Network Level Authentication
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
    # Enable built-in firewall group rules
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    # Ensure explicit TCP 3389 inbound rule exists (some editions lack group)
    Ensure-FirewallRule -Name 'RDP_TCP_3389_In' -DisplayName 'RDP (TCP 3389) Inbound' -Direction Inbound -Protocol TCP -LocalPort '3389'
  }
} "Enable RDP"

# Disable NetBIOS over TCP/IP
Invoke-Safe {
  $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
  foreach ($a in $adapters) {
    if ($PSCmdlet.ShouldProcess("Adapter $($a.Description)","SetTcpipNetbios(2) Disable")) {
      [void]($a | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbios=2})
    }
  }
} "Disable NetBIOS"

# Windows Firewall: enable all profiles & defaults
Invoke-Safe {
  if ($PSCmdlet.ShouldProcess("Windows Firewall","Enable all profiles; inbound block; outbound allow; log allowed/blocked")) {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    foreach ($p in 'Domain','Private','Public') {
      Set-NetFirewallProfile -Profile $p -LogAllowed True -LogBlocked True -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.$p.log"
    }
  }
} "Configure Firewall"

# -------------------- System Integrity & Patching --------------------

# Secure Boot status (informational; VM firmware-dependent)
Invoke-Safe {
  try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    Write-Host "Secure Boot supported/enabled: $sb"
  } catch {
    Write-Host "Secure Boot not supported or not a UEFI system."
  }
} "Check Secure Boot"

# Windows Update policy: Download & notify (AUOptions=3)
Invoke-Safe {
  $wuBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
  $auKey  = Join-Path $wuBase 'AU'
  Set-RegistryValue -Path $wuBase -Name 'DoNotConnectToWindowsUpdateInternetLocations' -Value 0
  Set-RegistryValue -Path $auKey  -Name 'AUOptions' -Value 3
  Set-RegistryValue -Path $auKey  -Name 'AutoInstallMinorUpdates' -Value 1
  Set-RegistryValue -Path $auKey  -Name 'NoAutoRebootWithLoggedOnUsers' -Value 1
} "Windows Update policy"

# Disable Remote Registry service
Invoke-Safe {
  if (Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess("Service: RemoteRegistry","Disable + stop")) {
      Set-Service -Name RemoteRegistry -StartupType Disabled
      Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
    }
  }
} "Disable RemoteRegistry"

# -------------------- Optional: Defender Hardening --------------------
if ($HardenDefender) {
  Invoke-Safe {
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
      if ($PSCmdlet.ShouldProcess("Microsoft Defender","Apply stronger preferences")) {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendSafe
        Set-MpPreference -CloudBlockLevel High
        Set-MpPreference -PUAProtection Enabled

        # SmartScreen for Explorer & Edge
        Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'RequireAdmin' -Type ([Microsoft.Win32.RegistryValueKind]::String)
        Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'EnabledV9' -Value 1
      }
    }
  } "Defender hardening"
}

# -------------------- Optional: FileZilla Server (FTP) --------------------
if ($FtsFtpServer) {
  Write-Host "Configuring firewall for FileZilla Server (FTP)..."
  $rangeString = Get-FtpPassiveRangeString -Start $FtpPassiveStart -End $FtpPassiveEnd

  # Control channel (TCP 21)
  Ensure-FirewallRule -Name 'FTS_FTP_Control_TCP_21' `
    -DisplayName 'FTS FTP Control (TCP 21)' -Direction Inbound -Protocol TCP -LocalPort '21'

  # Passive data range (TCP)
  Ensure-FirewallRule -Name 'FTS_FTP_Passive_TCP_Custom' `
    -DisplayName "FTS FTP Passive Data (TCP $rangeString)" -Direction Inbound -Protocol TCP -LocalPort $rangeString

  # Optional UDP if requested
  if ($FtpIncludeUdp) {
    Ensure-FirewallRule -Name 'FTS_FTP_Passive_UDP_Custom' `
      -DisplayName "FTS FTP Passive Data (UDP $rangeString)" -Direction Inbound -Protocol UDP -LocalPort $rangeString
  }

  Write-Host "FTP firewall rules applied. Passive range (TCP): $rangeString"
}

# -------------------- Verification Artifacts --------------------
Invoke-Safe {
  $auditOut = Join-Path $logDir 'IoT_AuditPolicy.txt'
  auditpol /get /category:* | Out-File -FilePath $auditOut -Force -Encoding UTF8
  Write-Host "Audit policy exported to $auditOut"
} "Export audit policy"

Invoke-Safe {
  Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
    Format-Table | Out-String | Set-Content (Join-Path $logDir 'Firewall_Profile_Summary.txt')
} "Export firewall summary"

Write-Host "== Hardening complete. Some changes may require a restart. =="
Stop-Transcript | Out-Null
