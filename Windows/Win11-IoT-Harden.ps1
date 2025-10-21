<# 
.SYNOPSIS
  Hardens a Windows 11 IoT (non-domain) VM on ESXi to a CIS-like baseline, enables RDP (with NLA),
  and optionally configures NXLog for GELF logging to Graylog.

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
  - (Optional) Installs and configures NXLog for GELF logging to Graylog
  - (Optional) Hardens Microsoft Defender
  - (Optional) Configures firewall rules for FileZilla Server
  - Outputs verification artifacts in C:\Logs and transcripts in C:\PowerShellTranscripts

.PARAMETER ConfigureNXLog
  Install and configure NXLog for GELF logging to Graylog.

.PARAMETER SourceType
  Custom source_type identifier for Graylog filtering (e.g., FTS_App_Node, FTS_FTP_Server).
  If not provided with -ConfigureNXLog, script will prompt interactively.

.PARAMETER NodeType
  Custom node_type identifier for Graylog filtering (e.g., media_server, ftp_server).
  If not provided with -ConfigureNXLog, script will prompt interactively.

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
  - NXLog CE will be downloaded from official source if not present.

.EXAMPLE
  .\Win11-IoT-Harden.ps1 -ConfigureNXLog
  Interactive mode - will prompt for source_type and node_type

.EXAMPLE
  .\Win11-IoT-Harden.ps1 -ConfigureNXLog -SourceType "FTS_App_Node" -NodeType "media_server"
  Non-interactive mode with pre-configured identifiers

.EXAMPLE
  .\Win11-IoT-Harden.ps1 -ConfigureNXLog -SourceType "FTS_FTP_Server" -NodeType "ftp_server" -FtsFtpServer
  Full configuration with FTP server

#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [switch]$ConfigureNXLog,
  [string]$SourceType = "",
  [string]$NodeType = "",
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

function Install-ConfigureNXLog {
  param(
    [Parameter(Mandatory)][string]$SourceTypeId,
    [Parameter(Mandatory)][string]$NodeTypeId
  )
  
  Write-Host "`n======================================" -ForegroundColor Cyan
  Write-Host "  Installing & Configuring NXLog" -ForegroundColor Cyan
  Write-Host "======================================" -ForegroundColor Cyan
  
  $nxlogPath = "C:\Program Files\nxlog"
  $nxlogExe = Join-Path $nxlogPath "nxlog.exe"
  $nxlogConfPath = Join-Path $nxlogPath "conf\nxlog.conf"
  
  # Check if already installed
  if (Test-Path $nxlogExe) {
    Write-Host "✓ NXLog already installed at $nxlogPath" -ForegroundColor Green
  } else {
    Write-Host "[*] Downloading NXLog CE..." -ForegroundColor Yellow
    $nxlogUrl = "https://nxlog.co/system/files/products/files/348/nxlog-ce-3.2.2329.msi"
    $installerPath = Join-Path $env:TEMP "nxlog-ce.msi"
    
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
      Invoke-WebRequest -Uri $nxlogUrl -OutFile $installerPath -UseBasicParsing
      Write-Host "✓ Download complete" -ForegroundColor Green
      
      Write-Host "[*] Installing NXLog..." -ForegroundColor Yellow
      Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait -NoNewWindow
      Start-Sleep -Seconds 5
      
      if (Test-Path $nxlogExe) {
        Write-Host "✓ NXLog installed successfully" -ForegroundColor Green
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
  
  # Create directory structure
  Write-Host "[*] Creating NXLog directory structure..." -ForegroundColor Yellow
  Ensure-Path (Join-Path $nxlogPath "conf\nxlog.d")
  Ensure-Path (Join-Path $nxlogPath "data")
  Ensure-Path (Join-Path $nxlogPath "cert")
  
  # Create NXLog configuration
  Write-Host "[*] Configuring NXLog for GELF output to graylog.fleetcam.io:5555..." -ForegroundColor Yellow
  
  $nxlogConfig = @"
define ROOT     C:\Program Files\nxlog
define CERTDIR  %ROOT%\cert
define CONFDIR  %ROOT%\conf\nxlog.d
define LOGDIR   %ROOT%\data
include %CONFDIR%\\*.conf
define LOGFILE  %LOGDIR%\nxlog.log
LogFile %LOGFILE%
Moduledir %ROOT%\modules
CacheDir  %ROOT%\data
Pidfile   %ROOT%\data\nxlog.pid
SpoolDir  %ROOT%\data

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
                <Select Path="Security">*[System[(Level=1 or Level=2)]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Output graylog>
    Module om_udp
    Host graylog.fleetcam.io
    Port 5555
    OutputType GELF_UDP
    
    # Add custom fields (automatically prefixed with _ in GELF)
    Exec `$source_type = "$SourceTypeId";
    Exec `$node_type = "$NodeTypeId";
    Exec `$environment = "production";
    Exec `$gl2_source_collector = hostname();
</Output>

<Route 1>
    Path eventlog => graylog
</Route>
"@

  try {
    $nxlogConfig | Out-File -FilePath $nxlogConfPath -Encoding ASCII -Force
    Write-Host "✓ NXLog configuration written to $nxlogConfPath" -ForegroundColor Green
    
    # Validate configuration
    Write-Host "[*] Validating NXLog configuration..." -ForegroundColor Yellow
    $validateOutput = & $nxlogExe -v 2>&1 | Out-String
    if ($validateOutput -match "ERROR") {
      Write-Warning "NXLog configuration validation found errors:`n$validateOutput"
      return $false
    } else {
      Write-Host "✓ NXLog configuration validated successfully" -ForegroundColor Green
    }
    
    # Test connectivity to Graylog
    Write-Host "[*] Testing connectivity to graylog.fleetcam.io:5555..." -ForegroundColor Yellow
    try {
      $testConn = Test-NetConnection -ComputerName "graylog.fleetcam.io" -Port 5555 -WarningAction SilentlyContinue -ErrorAction Stop
      if ($testConn.TcpTestSucceeded) {
        Write-Host "✓ Successfully connected to Graylog" -ForegroundColor Green
      } else {
        Write-Warning "✗ Cannot connect to graylog.fleetcam.io:5555 - check firewall and network"
      }
    } catch {
      Write-Warning "✗ DNS resolution or connectivity test failed for graylog.fleetcam.io:5555"
      Write-Host "  Verify DNS and network connectivity manually" -ForegroundColor Yellow
    }
    
    # Configure and start NXLog service
    Write-Host "[*] Starting NXLog service..." -ForegroundColor Yellow
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
        Write-Host "Check logs at: C:\Program Files\nxlog\data\nxlog.log" -ForegroundColor Yellow
      }
    } else {
      Write-Warning "NXLog service not found"
      return $false
    }
    
    # Generate test event
    Write-Host "`n[*] Generating test event..." -ForegroundColor Yellow
    Write-EventLog -LogName Application -Source WSH -EventId 1000 -EntryType Error `
      -Message "TEST: NXLog GELF configuration validation from $(hostname) - Source: $SourceTypeId, Node: $NodeTypeId"
    
    Write-Host "✓ Test event generated" -ForegroundColor Green
    Write-Host "`nVerify in Graylog:" -ForegroundColor Cyan
    Write-Host "  Search: _source_type:$SourceTypeId" -ForegroundColor White
    Write-Host "  Or:     _gl2_source_collector:$(hostname) AND message:*TEST*" -ForegroundColor White
    
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
Write-Host "  Windows 11 IoT Hardening Script    " -ForegroundColor Cyan
Write-Host "  Generic Non-Domain Configuration   " -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Hostname: $(hostname)" -ForegroundColor White
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White

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
Write-Host "✓ PowerShell logging enabled" -ForegroundColor Green

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
if ($ConfigureNXLog) {
  # Prompt for identifiers if not provided
  if ([string]::IsNullOrWhiteSpace($SourceType)) {
    Write-Host "`n======================================" -ForegroundColor Cyan
    Write-Host "  NXLog Configuration - Custom Fields" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "These identifiers will be added to all log events for filtering in Graylog.`n" -ForegroundColor White
    
    do {
      $SourceType = Read-Host "Enter source_type (e.g., FTS_App_Node, FTS_FTP_Server, FTS_Media_Server)"
      if ([string]::IsNullOrWhiteSpace($SourceType)) {
        Write-Host "  ✗ source_type cannot be empty" -ForegroundColor Red
      }
    } while ([string]::IsNullOrWhiteSpace($SourceType))
  }
  
  if ([string]::IsNullOrWhiteSpace($NodeType)) {
    do {
      $NodeType = Read-Host "Enter node_type (e.g., media_server, ftp_server, app_server)"
      if ([string]::IsNullOrWhiteSpace($NodeType)) {
        Write-Host "  ✗ node_type cannot be empty" -ForegroundColor Red
      }
    } while ([string]::IsNullOrWhiteSpace($NodeType))
  }
  
  Write-Host "`nConfiguration:" -ForegroundColor Cyan
  Write-Host "  source_type: $SourceType" -ForegroundColor White
  Write-Host "  node_type:   $NodeType" -ForegroundColor White
  Write-Host "  environment: production" -ForegroundColor White
  Write-Host "  destination: graylog.fleetcam.io:5555 (GELF UDP)`n" -ForegroundColor White
  
  $nxlogSuccess = Install-ConfigureNXLog -SourceTypeId $SourceType -NodeTypeId $NodeTypeId
  
  if ($nxlogSuccess) {
    Write-Host "`n✓ NXLog configured successfully for GELF logging" -ForegroundColor Green
  } else {
    Write-Warning "NXLog configuration encountered issues. Check logs above."
  }
} else {
  Write-Host "`n[-] Skipping NXLog installation (use -ConfigureNXLog to enable)" -ForegroundColor Yellow
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
  Write-Host "  ✓ Firewall summary exported" -ForegroundColor Green
} "Export firewall summary"

# Export configuration summary
$summary = @"
======================================
Windows 11 IoT Hardening Summary
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
$(if ($ConfigureNXLog) { "- NXLog configured: source_type=$SourceType, node_type=$NodeType" } else { "- NXLog not configured" })
$(if ($HardenDefender) { "- Microsoft Defender hardened" } else { "" })
$(if ($FtsFtpServer) { "- FileZilla FTP firewall rules configured" } else { "" })

Event Logs Forwarded to Graylog:
$(if ($ConfigureNXLog) { "- Application: Error + Critical`n- System: Error + Critical`n- Security: Error + Critical (no Info)" } else { "- None (NXLog not configured)" })

Logs Location: $logDir
Transcripts: $transcriptDir
$(if ($ConfigureNXLog) { "NXLog Config: C:\Program Files\nxlog\conf\nxlog.conf`nNXLog Logs: C:\Program Files\nxlog\data\nxlog.log" } else { "" })

Next Steps:
1. Reboot the system to apply all changes
$(if ($ConfigureNXLog) { "2. Verify NXLog is sending to Graylog: Search for _source_type:$SourceType" } else { "" })
3. Review firewall logs in C:\Windows\System32\LogFiles\Firewall\

======================================
"@

$summaryPath = Join-Path $logDir "Hardening_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$summary | Out-File -FilePath $summaryPath -Encoding UTF8

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "  Hardening Complete!                " -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
Write-Host $summary -ForegroundColor White
Write-Host "Summary saved to: $summaryPath" -ForegroundColor Cyan
Write-Host "`n⚠ REBOOT REQUIRED for some changes" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Cyan

Stop-Transcript | Out-Null
