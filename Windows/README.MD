# Win11 IoT Hardening (with optional FileZilla FTP)

Harden a **Windows 11 IoT (non-domain)** system with CIS-like safe defaults, enable **RDP (with NLA)**, and optionally open the firewall for **FileZilla Server** (FTP control + passive TCP range). Designed to be **idempotent**, safe for **ESXi VMs**, and easy to audit.

---

## Contents

* [What this script does](#what-this-script-does)
* [Prereqs](#prereqs)
* [Install & Run](#install--run)
* [Parameters](#parameters)
* [Typical Usage](#typical-usage)
* [FTP / FileZilla notes](#ftp--filezilla-notes)
* [ESXi VM caveats](#esxi-vm-caveats)
* [Verification](#verification)
* [Logs & Artifacts](#logs--artifacts)
* [Troubleshooting](#troubleshooting)
* [Security considerations](#security-considerations)
* [Rollback / Undo](#rollback--undo)
* [License](#license)

---

## What this script does

* Verifies **Administrator** elevation
* Sets **ExecutionPolicy = RemoteSigned** (LocalMachine)
* Turns on **PowerShell Script Block Logging** + **Transcription policy**
* Disables: **SMBv1**, **Guest account**, **Remote Assistance**, **Autorun**, **NetBIOS over TCP/IP**
* Hardens **LSA**: restrict anonymous SAM, disable LM hash, set LM compatibility level
* Enforces local **password policy** (complexity on; min length 12; max age 60d; min age 1d)
* Enables **Windows Firewall** (Domain/Private/Public): **inbound block / outbound allow** and logging
* Applies key **auditpol** subcategories (Logon, Account Logon, Object Access, Policy Change, etc.)
* **Enables RDP** (+ **NLA**) and opens firewall for TCP 3389
* **Optional:** Defender preferences (PUA, Cloud protection, SmartScreen)
* **Optional:** FTP rules for FileZilla — **TCP 21** + passive **TCP** range (UDP optional)
* Exports verification artifacts to `C:\Logs` and transcripts to `C:\PowerShellTranscripts`

> **Explicitly removed:** BitLocker enablement (no vTPM in this VM).

---

## Prereqs

* **Windows 11 IoT** (non-domain joined)
* Run **PowerShell as Administrator**
* Network access appropriate for RDP/FTP if enabling those features
* (Optional) **FileZilla Server** installed if you plan to use FTP

---

## Install & Run

1. Copy the script to the VM as `Win11-IoT-Harden.ps1`.
2. Open **PowerShell (Admin)**.
3. *(Optional)* Dry-run:

   ```powershell
   .\Win11-IoT-Harden.ps1 -WhatIf
   ```
4. Apply with defaults:

   ```powershell
   .\Win11-IoT-Harden.ps1
   ```

---

## Parameters

| Parameter          | Type   | Default | Description                                                                      |
| ------------------ | ------ | :-----: | -------------------------------------------------------------------------------- |
| `-HardenDefender`  | switch |   off   | Apply stronger Defender/SmartScreen prefs.                                       |
| `-FtsFtpServer`    | switch |   off   | Add firewall rules for FileZilla (TCP 21 + passive **TCP** range; UDP optional). |
| `-FtpPassiveStart` | int    |  50000  | Passive range start (TCP).                                                       |
| `-FtpPassiveEnd`   | int    |  58000  | Passive range end (TCP).                                                         |
| `-FtpIncludeUdp`   | switch |   off   | Also open the passive **UDP** range (usually not required).                      |
| `-WhatIf`          | switch |    —    | Simulate actions (safe dry-run).                                                 |

> Re-running the script won’t duplicate rules or settings (idempotent).

---

## Typical Usage

**Baseline hardening (RDP is enabled by default):**

```powershell
.\Win11-IoT-Harden.ps1
```

**Add Defender hardening:**

```powershell
.\Win11-IoT-Harden.ps1 -HardenDefender
```

**Enable FTP with default passive TCP range (50000–58000):**

```powershell
.\Win11-IoT-Harden.ps1 -FtsFtpServer
```

**Enable FTP with a tight passive range (TCP only):**

```powershell
.\Win11-IoT-Harden.ps1 -FtsFtpServer -FtpPassiveStart 52000 -FtpPassiveEnd 52100
```

**Also open UDP (rare):**

```powershell
.\Win11-IoT-Harden.ps1 -FtsFtpServer -FtpPassiveStart 52000 -FtpPassiveEnd 52100 -FtpIncludeUdp
```

---

## FTP / FileZilla notes

1. In **FileZilla Server**:

   * **Control port:** `21`
   * **Passive mode range:** set **exactly** the range you chose (e.g., `52000–52100`)
   * If behind NAT, set the **external IP/NAT** in FileZilla.
2. In **Windows**: this script opens TCP 21 and the passive **TCP** range (UDP only if you ask).
3. At your **edge firewall/NAT**: forward **TCP 21** and the passive **TCP** range to the VM’s IP.
4. **Tip:** smaller passive ranges reduce attack surface and simplify firewall/NAT rules.

---

## ESXi VM caveats

* **RDP**: enabled with **NLA**; firewall opened for TCP 3389.
* **Secure Boot**: script only **reports** status; enable in VM firmware if desired.
* **Logging**: transcripts + audit logs can grow; consider rotation on thin-provisioned disks.
* **Backups/Snapshots**: no BitLocker here, so standard VM backup/snapshot flows apply.

---

## Verification

**Firewall profiles**

```powershell
Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction
```

**RDP enabled (0 = enabled)**

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
```

**Audit policy**

```powershell
auditpol /get /category:*
```

**FTP rules present**

```powershell
Get-NetFirewallRule | Where-Object DisplayName -like 'FTS FTP*' |
  Select-Object DisplayName, Enabled, Direction | Format-Table
```

---

## Logs & Artifacts

* **Transcripts:** `C:\PowerShellTranscripts\IoT_Hardening_*.txt`
* **Audit policy snapshot:** `C:\Logs\IoT_AuditPolicy.txt`
* **Firewall summary:** `C:\Logs\Firewall_Profile_Summary.txt`

**Rotate transcripts (sample scheduled task action):**

```powershell
Get-ChildItem 'C:\PowerShellTranscripts' -File |
  Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-30)} |
  Remove-Item -Force
```

---

## Troubleshooting

* **“Run as Administrator” required:** The script throws if not elevated.
* **Policy errors (execution/audit):** Some environments enforce policies; the script logs warnings and continues where safe.
* **FTP data stalls:** Ensure FileZilla passive range matches firewall/NAT forwards; prefer a tight range.
* **RDP blocked:** Confirm the “Remote Desktop” firewall group is enabled and TCP 3389 inbound rule exists; verify upstream firewalls.

---

## Security considerations

* Keep the passive FTP range **as narrow as feasible**.
* Prefer **SFTP/FTPS** if your workflow supports it.
* Audit logs and PowerShell transcripts can contain sensitive command lines and paths—**restrict access** and **rotate** regularly.
* Use **unique local admin creds** and consider adding an additional non-admin account for daily use.
* With RDP enabled, ensure **NLA** stays on and consider **account lockout** and **firewall scoping** (allow only from admin networks).

---

## Rollback / Undo

* **RDP**: disable by setting `fDenyTSConnections=1` and disabling the Remote Desktop firewall group.
* **FTP rules**: remove with `Remove-NetFirewallRule` on rules named `FTS FTP *`.
* **Execution policy / logging**: revert registry changes under `HKLM: Software/Policies/Microsoft/Windows/PowerShell/*` and `HKLM: SOFTWARE/Microsoft/PowerShell/1/ShellIds/Microsoft.PowerShell`.
* **Password policy**: export, edit, and re-apply via `secedit` with your preferred values.

> If you need an automated rollback script, ask and we’ll generate one based on your chosen settings.

---

## License

Released under the **MIT License**. Use at your own risk; test in a non-production environment first.
