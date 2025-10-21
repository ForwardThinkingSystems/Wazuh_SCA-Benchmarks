<# 
.SYNOPSIS
  Hardens a Windows 11 IoT (non-domain) VM on ESXi to a CIS-like baseline, enables RDP (with NLA),
  configures NXLog for GELF logging to Graylog, and can open firewall for FileZilla Server.

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
  - Installs and configures NXLog with GELF output to Graylog
  - (Optional) Hardens Microsoft Defender
  - (Optional) Configures firewall rules for FileZilla Server
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

.PARAMETER GraylogServer
  IP address or hostname of Graylog server for NXLog GELF output.

.PARAMETER GraylogPort
  GELF TCP port on Graylog server (default: 555).

.PARAMETER SkipNXLog
  Skip NXLog installation and configuration.

.NOTES
  - Test in a lab first; some changes may require reboot.
  - NXLog CE will be downloaded from official source
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [switch]$HardenDefender,
  [switch]$FtsFtpServer,
  [int]$FtpPassiveStart = 50000,
  [int]$FtpPassiveEnd   = 58000,
  [switch]$FtpIncludeUdp,
  [Parameter(Mandatory=$false)]
  [string]$GraylogServer = "",
  [int]$GraylogPort = 555,
  [switch]$SkipNXLog
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

function Install-NXLog {
  param(
    [Parameter(Mandatory)][string]$GraylogIP,
    [Parameter(Mandatory)][int]$GraylogPort
  )
  
  Write-Host "`n== Installing and Configuring NXLog for GELF ==" -ForegroundColor Cyan
  
  $nxlogPath = "C:\Program Files (x86)\nxlog"
  $nxlogExe = Join-Path $nxlogPath "nxlog.exe"
  $nxlogConfPath = Join-Path $nxlogPath "conf\nxlog.conf"
  
  # Check if already installed
  if (Test-Path $nxlogExe) {
    Write-Host "NXLog already installed at $nxlogPath" -ForegroundColor Yellow
  } else {
    Write-Host "Downloading NXLog CE..." -ForegroundColor Green
    $nxlogUrl = "https://nxlog.co/system/files/products/files/348/nxlog-ce-3.2.2329.msi"
    $installerPath = Join-Path $env:TEMP "nxlog-ce.msi"
    
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
      Invoke-WebRequest -Uri $nxlogUrl -OutFile $installerPath -UseBasicParsing
      Write-Host "Installing NXLog..." -ForegroundColor Green
      Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait -NoNewWindow
      Start-Sleep -Seconds 5
      
      if (Test-Path $nxlogExe) {
        Write-Host "NXLog installed successfully" -ForegroundColor Green
      } else {
        throw "NXLog installation failed - executable not found"
      }
    } catch {
      Write-Warning "Failed to download/install NXLog: $($_.Exception.Message)"
      return $false
    } finally {
      if (Test-Path $installerPath) { Remove-Item $installerPath -Force -ErrorAction SilentlyContinue }
    }
  }
  
  # Create NXLog configuration for GELF
  Write-Host "Configuring NXLog for GELF output to $GraylogIP`:$GraylogPort..." -ForegroundColor Green
  
  $nxlogConfig = @"
define ROOT C:\Program Files (x86)\nxlog

<Extension gelf>
    Module xm_gelf
</Extension>

<Input eventlog>
    Module im_msvistalog
    
    # Query for Error (Level=2) and Critical (Level=1) only
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Application">*[System[(Level=1 or Level=2)]]</Select>
                <Select Path="System">*[System[(Level=1 or Level=2)]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Output graylog>
    Module om_tcp
    Host $GraylogIP
    Port $GraylogPort
    OutputType GELF_TCP
    
    # Add custom FTS identification fields
    Exec `$source_type = "FTS_App_Node";
    Exec `$node_type = "media_server";
    Exec `$environment = "production";
    Exec `$application = "CommunicationServer";
    Exec `$server_role = "FleetCam";
    Exec `$gl2_source_collector = hostname();
</Output>

<Route 1>
    Path eventlog => graylog
</Route>
"@

  try {
    $nxlogConfig | Out-File -FilePath $nxlogConfPath -Encoding ASCII -Force
    Write-Host "NXLog configuration written to $nxlogConfPath" -ForegroundColor Green
    
    # Validate configuration
    Write-Host "Validating NXLog configuration..." -ForegroundColor Yellow
    $validateOutput = & $nxlogExe -v 2>&1
    if ($validateOutput -match "ERROR") {
      Write-Warning "NXLog configuration validation found errors: $validateOutput"
      return $false
    } else {
      Write-Host "NXLog configuration validated successfully" -ForegroundColor Green
    }
    
    # Test connectivity to Graylog
    Write-Host "Testing connectivity to Graylog $GraylogIP`:$GraylogPort..." -ForegroundColor Yellow
    $testConn = Test-NetConnection -ComputerName $GraylogIP -Port $GraylogPort -WarningAction SilentlyContinue
    if ($testConn.TcpTestSucceeded) {
      Write-Host "✓ Successfully connected to Graylog" -ForegroundColor Green
    } else {
      Write-Warning "✗ Cannot connect to Graylog at $GraylogIP`:$GraylogPort - check firewall and network"
    }
    
    # Configure and start NXLog service
    Write-Host "Starting NXLog service..." -ForegroundColor Green
    $service = Get-Service -Name nxlog -ErrorAction SilentlyContinue
    if ($service) {
      Set-Service -Name nxlog -StartupType Automatic
      Restart-Service -Name nxlog -Force
      Start-Sleep -Seconds 3
      
      $serviceStatus = (Get-Service -Name nxlog).Status
      if ($serviceStatus -eq 'Running') {
        Write-Host "✓ NXLog service is running" -ForegroundColor Green
      } else {
        Write-Warning "NXLog service failed to start. Status: $serviceStatus"
      }
    } else {
      Write-Warning "NXLog service not found"
      return $false
    }
    
    # Generate test event
    Write-Host "Generating test event..." -ForegroundColor Yellow
    Write-EventLog -LogName Application -Source WSH -EventId 1000 -EntryType Error `
      -Message "TEST: NXLog GELF configuration validation from $(hostname) - FTS_App_Node"
    
    Write-Host "✓ Test event generated. Check Graylog for: _source_type:FTS_App_Node" -ForegroundColor Green
    Write-Host "  Filter in Graylog: _source_type:FTS_App_Node AND message:*TEST*" -ForegroundColor Cyan
    
    return $true
    
  } catch {
    Write-Warning "Failed to configure NXLog: $($_.Exception.Message)"
    return $false
  }
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

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Windows 11 IoT Hardening + NXLog   " -ForegroundColor Cyan
Write-Host "  FTS Media Server Configuration     " -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# Execution policy (local machine, RemoteSigned)
if ($PSCmdlet.ShouldProcess("ExecutionPolicy","Set RemoteSigned (LocalMachine)")) {
  try { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force }
  catch { Write-Warning "Execution policy set failed (may be governed by policy): $($_.Exception.Message)" }
}

# PowerShell logging: ScriptBlock + Transcription policy
Write-Host "`n[*] Configuring PowerShell logging..." -ForegroundColor Yellow
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name 'EnableScriptBlockLogging' -Value 1
Set-RegistryValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Value 1
Set-RegistryValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Value $transcriptDir -Type ([Microsoft.Win32.RegistryValueKind]::String)
Set-RegistryValue -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'IncludeInvocationHeader' -Value 1

# -------------------- Core CIS-like Controls --------------------
Write-Host "`n[*] Applying CIS-like security controls..." -ForegroundColor Yellow

# 1) Disable SMBv1
Invoke-Safe {
  if ($PSCmdlet.ShouldProcess("SMB1Protocol","Disable feature")) {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
    Write-Host "  ✓ SMBv1 disabled" -ForegroundColor Green
  }
} "Disable SMBv1"

# 2) Disable Guest account (if present)
Invoke-Safe {
  $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
  if ($guest -and $guest.Enabled) {
    if ($PSCmdlet.ShouldProcess("LocalUser:Guest","Disable")) { 
      Disable-LocalUser -Name 'Guest'
      Write-Host "  ✓ Guest account disabled" -ForegroundColor Green
    }
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
    Write-Host "  ✓ Password policy enforced (complexity + 12 char min)" -ForegroundColor Green
  }
} "Enforce password policy"

# 4) Enable audit categories
Invoke-Safe {
  if ($PSCmdlet.ShouldProcess("Audit Policy","Enable success/failure for security events")) {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable                 | Out-Null
    auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable        | Out-Null
    auditpol /set /subcategory:"Privilege Use" /success:disable /failure:enable       | Out-Null
    auditpol /set /subcategory:"Object Access" /success:enable /failure:enable        | Out-Null
    auditpol /set /subcategory:"Policy Change" /success:enable /failure:enable        | Out-Null
    auditpol /set /subcategory:"Account Management" /success:enable /failure:enable   | Out-Null
    Write-Host "  ✓ Audit policies configured" -ForegroundColor Green
  }
} "Audit policy"

# 5) LSA hardening
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1
Write-Host "  ✓ LSA security hardened" -ForegroundColor Green

# 6) Disable Autorun
Set-RegistryValue -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255
Write-Host "  ✓ Autorun disabled" -ForegroundColor Green

# -------------------- Network & Remote Access --------------------
Write-Host "`n[*] Configuring network and remote access..." -ForegroundColor Yellow

# Disable Remote Assistance
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
Write-Host "  ✓ Remote Assistance disabled" -ForegroundColor Green

# Enable RDP + NLA + firewall
Invoke-Safe {
  if ($PSCmdlet.ShouldProcess("RDP","Enable RDP and NLA; open firewall")) {
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    Ensure-FirewallRule -Name 'RDP_TCP_3389_In' -DisplayName 'RDP (TCP 3389) Inbound' -Direction Inbound -Protocol TCP -LocalPort '3389'
    Write-Host "  ✓ RDP enabled with NLA" -ForegroundColor Green
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
  Write-Host "  ✓ NetBIOS over TCP/IP disabled" -ForegroundColor Green
} "Disable NetBIOS"

# Windows Firewall: enable all profiles & defaults
Invoke-Safe {
  if ($PSCmdlet.ShouldProcess("Windows Firewall","Enable all profiles")) {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    foreach ($p in 'Domain','Private','Public') {
      Set-NetFirewallProfile -Profile $p -LogAllowed True -LogBlocked True -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.$p.log"
    }
    Write-Host "  ✓ Windows Firewall configured (all profiles enabled)" -ForegroundColor Green
  }
} "Configure Firewall"

# -------------------- System Integrity & Patching --------------------
Write-Host "`n[*] Checking system integrity..." -ForegroundColor Yellow

# Secure Boot status
Invoke-Safe {
  try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    Write-Host "  ✓ Secure Boot: $sb" -ForegroundColor Green
  } catch {
    Write-Host "  - Secure Boot not supported/enabled" -ForegroundColor Yellow
  }
} "Check Secure Boot"

# Windows Update policy
Invoke-Safe {
  $wuBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
  $auKey  = Join-Path $wuBase 'AU'
  Set-RegistryValue -Path $wuBase -Name 'DoNotConnectToWindowsUpdateInternetLocations' -Value 0
  Set-RegistryValue -Path $auKey  -Name 'AUOptions' -Value 3
  Set-RegistryValue -Path $auKey  -Name 'AutoInstallMinorUpdates' -Value 1
  Set-RegistryValue -Path $auKey  -Name 'NoAutoRebootWithLoggedOnUsers' -Value 1
  Write-Host "  ✓ Windows Update policy configured" -ForegroundColor Green
} "Windows Update policy"

# Disable Remote Registry service
Invoke-Safe {
  if (Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess("Service: RemoteRegistry","Disable + stop")) {
      Set-Service -Name RemoteRegistry -StartupType Disabled
      Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
      Write-Host "  ✓ Remote Registry service disabled" -ForegroundColor Green
    }
  }
} "Disable RemoteRegistry"

# -------------------- NXLog Installation & Configuration --------------------
if (-not $SkipNXLog) {
  if ([string]::IsNullOrWhiteSpace($GraylogServer)) {
    Write-Warning "`nGraylogServer parameter not provided. Skipping NXLog configuration."
    Write-Host "  To configure NXLog later, run with -GraylogServer parameter" -ForegroundColor Yellow
  } else {
    $nxlogSuccess = Install-NXLog -GraylogIP $GraylogServer -GraylogPort $GraylogPort
    if ($nxlogSuccess) {
      Write-Host "`n  ✓ NXLog configured successfully for GELF logging" -ForegroundColor Green
    } else {
      Write-Warning "NXLog configuration encountered issues. Check logs above."
    }
  }
} else {
  Write-Host "`n[-] Skipping NXLog installation (SkipNXLog flag set)" -ForegroundColor Yellow
}

# -------------------- Optional: Defender Hardening --------------------
if ($HardenDefender) {
  Write-Host "`n[*] Applying Microsoft Defender hardening..." -ForegroundColor Yellow
  Invoke-Safe {
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
      if ($PSCmdlet.ShouldProcess("Microsoft Defender","Apply stronger preferences")) {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendSafe
        Set-MpPreference -CloudBlockLevel High
        Set-MpPreference -PUAProtection Enabled

        Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'RequireAdmin' -Type ([Microsoft.Win32.RegistryValueKind]::String)
        Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'EnabledV9' -Value 1
        Write-Host "  ✓ Defender hardening applied" -ForegroundColor Green
      }
    }
  } "Defender hardening"
}

# -------------------- Optional: FileZilla Server (FTP) --------------------
if ($FtsFtpServer) {
  Write-Host "`n[*] Configuring FileZilla Server firewall rules..." -ForegroundColor Yellow
  $rangeString = Get-FtpPassiveRangeString -Start $FtpPassiveStart -End $FtpPassiveEnd

  Ensure-FirewallRule -Name 'FTS_FTP_Control_TCP_21' `
    -DisplayName 'FTS FTP Control (TCP 21)' -Direction Inbound -Protocol TCP -LocalPort '21'

  Ensure-FirewallRule -Name 'FTS_FTP_Passive_TCP_Custom' `
    -DisplayName "FTS FTP Passive Data (TCP $rangeString)" -Direction Inbound -Protocol TCP -LocalPort $rangeString

  if ($FtpIncludeUdp) {
    Ensure-FirewallRule -Name 'FTS_FTP_Passive_UDP_Custom' `
      -DisplayName "FTS FTP Passive Data (UDP $rangeString)" -Direction Inbound -Protocol UDP -LocalPort $rangeString
  }

  Write-Host "  ✓ FTP firewall rules applied. Passive range: $rangeString" -ForegroundColor Green
}

# -------------------- Verification Artifacts --------------------
Write-Host "`n[*] Generating verification artifacts..." -ForegroundColor Yellow

Invoke-Safe {
  $auditOut = Join-Path $logDir 'IoT_AuditPolicy.txt'
  auditpol /get /category:* | Out-File -FilePath $auditOut -Force -Encoding UTF8
  Write-Host "  ✓ Audit policy exported to $auditOut" -ForegroundColor Green
} "Export audit policy"

Invoke-Safe {
  Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
    Format-Table | Out-String | Set-Content (Join-Path $logDir 'Firewall_Profile_Summary.txt')
  Write-Host "  ✓ Firewall summary exported to $logDir\Firewall_Profile_Summary.txt" -ForegroundColor Green
} "Export firewall summary"

# Export configuration summary
$summary = @"
======================================
FTS Windows 11 IoT Hardening Summary
======================================
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Hostname: $(hostname)
IP Address: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | Select-Object -First 1).IPAddress)

Configuration Applied:
- CIS-like security baseline
- RDP enabled with NLA
- Audit logging configured
- Windows Firewall enabled (all profiles)
- PowerShell logging enabled
$(if (-not $SkipNXLog -and -not [string]::IsNullOrWhiteSpace($GraylogServer)) { "- NXLog configured for GELF logging to $GraylogServer`:$GraylogPort" } else { "- NXLog not configured" })
$(if ($HardenDefender) { "- Microsoft Defender hardened" } else { "" })
$(if ($FtsFtpServer) { "- FileZilla FTP firewall rules configured" } else { "" })

Logs Location: $logDir
Transcripts: $transcriptDir

Next Steps:
1. Reboot the system to apply all changes
2. Verify NXLog is sending to Graylog: Search for _source_type:FTS_App_Node
3. Monitor application event logs for CommunicationServer.exe crashes
4. Review firewall logs in C:\Windows\System32\LogFiles\Firewall\

======================================
"@

$summaryPath = Join-Path $logDir "Hardening_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$summary | Out-File -FilePath $summaryPath -Encoding UTF8
Write-Host "`n$summary" -ForegroundColor Cyan

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Hardening Complete!                " -ForegroundColor Green
Write-Host "  Summary saved to: $summaryPath" -ForegroundColor Cyan
Write-Host "  REBOOT REQUIRED for some changes   " -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Cyan

Stop-Transcript | Out-Null
