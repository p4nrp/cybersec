# Windows 10 Vulnerable Endpoint - WIN10-VULN

## VM Specifications
- **OS**: Windows 10 Pro (64-bit)
- **RAM**: 4GB (minimum), 8GB (recommended)
- **Storage**: 50GB
- **Network**: NAT Network (SOC-Lab-Network)
- **CPU**: 2 cores
- **IP Address**: 192.168.1.30 (static)
- **Hostname**: WIN10-VULN

## Purpose
This VM serves as a vulnerable Windows endpoint for practicing:
- Windows event log analysis
- Malware detection and analysis
- RDP brute force detection
- SMB exploitation scenarios
- Privilege escalation attacks
- Lateral movement detection

## VirtualBox Configuration

### Create VM via VBoxManage
```powershell
# Create VM
VBoxManage createvm --name "WIN10-VULN" --ostype "Windows10_64" --register

# Configure VM
VBoxManage modifyvm "WIN10-VULN" --memory 4096 --cpus 2
VBoxManage modifyvm "WIN10-VULN" --vram 128
VBoxManage modifyvm "WIN10-VULN" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage modifyvm "WIN10-VULN" --audio none
VBoxManage modifyvm "WIN10-VULN" --clipboard bidirectional
VBoxManage modifyvm "WIN10-VULN" --draganddrop bidirectional

# Create and attach storage
VBoxManage createhd --filename "WIN10-VULN.vdi" --size 51200
VBoxManage storagectl "WIN10-VULN" --name "SATA Controller" --add sata --controller IntelAHCI
VBoxManage storageattach "WIN10-VULN" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "WIN10-VULN.vdi"
VBoxManage storageattach "WIN10-VULN" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "Win10_Pro_x64.iso"
```

## Windows 10 Installation

1. Start the VM and install Windows 10 Pro
2. Use the following during setup:
   - **Username**: `socuser`
   - **Password**: `Password123!`
   - **Computer Name**: `WIN10-VULN`

## Post-Installation Configuration

### 1. Network Configuration

Set static IP address:

```powershell
# Open PowerShell as Administrator

# Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.30 -PrefixLength 24 -DefaultGateway 192.168.1.1

# Set DNS servers
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("192.168.1.10", "8.8.8.8")

# Verify configuration
Get-NetIPAddress -InterfaceAlias "Ethernet"
Get-DnsClientServerAddress -InterfaceAlias "Ethernet"
```

### 2. Join Domain (Optional but Recommended)

```powershell
# Add computer to domain
Add-Computer -DomainName "soclab.local" -Credential (Get-Credential) -Restart

# After restart, login as domain user:
# Username: soclab\jdoe
# Password: Password123!
```

### 3. Enable Remote Desktop

```powershell
# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

# Allow RDP through firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Allow weak encryption (for testing purposes)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "SecurityLayer" -Value 0
```

### 4. Enable WinRM for Remote Management

```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Allow WinRM through firewall
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress Any

# Configure WinRM for less secure authentication (testing only)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
winrm set winrm/config/service/auth '@{Basic="true"}'
```

### 5. Disable Windows Defender (For Testing)

```powershell
# Disable Real-time Protection
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable Windows Defender completely
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisablePrivacyMode $true
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true
Set-MpPreference -DisableScanningNetworkFiles $true
```

### 6. Enable Audit Policies for Better Logging

```powershell
# Enable comprehensive audit policies
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
auditpol /set /category:"Process Tracking" /success:enable /failure:enable

# Verify audit settings
auditpol /get /category:*
```

### 7. Enable PowerShell Script Block Logging

```powershell
# Enable PowerShell logging
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts"

# Create transcript directory
New-Item -Path "C:\PSTranscripts" -ItemType Directory -Force
```

### 8. Enable SMBv1 (Vulnerable for Testing)

```powershell
# Enable SMBv1 (vulnerable to EternalBlue)
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Disable SMB signing
Set-SmbClientConfiguration -RequireSecuritySignature $false -Confirm:$false
Set-SmbServerConfiguration -RequireSecuritySignature $false -Confirm:$false
```

### 9. Install Vulnerable Software

```powershell
# Install vulnerable web server (XAMPP)
# Download and install manually from https://www.apachefriends.org/

# Install FileZilla FTP Server (vulnerable)
# Download from https://filezilla-project.org/

# Install older Java version (vulnerable)
# Download Java 8u191 or earlier
```

### 10. Install Sysmon for Enhanced Logging

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Temp\Sysmon.zip"
Expand-Archive -Path "C:\Temp\Sysmon.zip" -DestinationPath "C:\Temp\Sysmon"

# Download Sysmon config (SwiftOnSecurity config)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Temp\sysmonconfig.xml"

# Install Sysmon
C:\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Temp\sysmonconfig.xml

# Verify Sysmon is running
Get-Service Sysmon64
```

## 🔴 CRITICAL: Install Winlogbeat for Log Forwarding to SIEM

### Install Winlogbeat

```powershell
# Download Winlogbeat
$winlogbeatUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-7.17.15-windows-x86_64.zip"
Invoke-WebRequest -Uri $winlogbeatUrl -OutFile "C:\Temp\winlogbeat.zip"

# Extract
Expand-Archive -Path "C:\Temp\winlogbeat.zip" -DestinationPath "C:\Program Files"
Rename-Item "C:\Program Files\winlogbeat-7.17.15-windows-x86_64" "C:\Program Files\Winlogbeat"
```

### Configure Winlogbeat

Create comprehensive configuration file:

```powershell
# Create configuration file
$winlogbeatConfig = @"
# Winlogbeat Configuration for SOC Lab
winlogbeat.event_logs:
  # Windows Security Events
  - name: Security
    level: info
    event_id: 4624, 4625, 4648, 4672, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4735, 4738, 4740, 4756, 4767, 4776
    processors:
      - drop_event.when.not.or:
        - equals.winlog.event_id: 4624  # Successful logon
        - equals.winlog.event_id: 4625  # Failed logon
        - equals.winlog.event_id: 4648  # Explicit credential logon
        - equals.winlog.event_id: 4672  # Admin logon
        - equals.winlog.event_id: 4720  # User created
        - equals.winlog.event_id: 4726  # User deleted
        - equals.winlog.event_id: 4740  # User locked out
  
  # Windows System Events
  - name: System
    level: info
    
  # Application Events
  - name: Application
    level: error
    
  # PowerShell Events
  - name: Microsoft-Windows-PowerShell/Operational
    level: info
    event_id: 4103, 4104
    
  # Sysmon Events (all events)
  - name: Microsoft-Windows-Sysmon/Operational
    level: info
    
  # RDP Events
  - name: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    level: info
    event_id: 21, 22, 23, 24, 25
    
  # Windows Defender
  - name: Microsoft-Windows-Windows Defender/Operational
    level: warning

# Add metadata
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_fields:
      target: ''
      fields:
        log_source: 'win10-vuln'
        environment: 'soc-lab'
        asset_type: 'vulnerable_endpoint'

# Output to Logstash on SIEM server
output.logstash:
  hosts: ["192.168.1.20:5044"]
  
# Logging
logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\Logs
  name: winlogbeat
  keepfiles: 7
  permissions: 0640
"@

# Write configuration
Set-Content -Path "C:\Program Files\Winlogbeat\winlogbeat.yml" -Value $winlogbeatConfig
```

### Install Winlogbeat as Windows Service

```powershell
# Navigate to Winlogbeat directory
cd "C:\Program Files\Winlogbeat"

# Test configuration
.\winlogbeat.exe test config -c .\winlogbeat.yml

# Test output connection to SIEM
.\winlogbeat.exe test output -c .\winlogbeat.yml

# Install as service
.\install-service-winlogbeat.ps1

# Start service
Start-Service winlogbeat

# Verify service is running
Get-Service winlogbeat

# Check logs
Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat" -Tail 50
```

### Verify Log Collection

```powershell
# Generate test security events
# Failed login attempt
net user testuser wrongpassword

# Successful login
net user socuser

# Check that events are being sent
Get-WinEvent -LogName Security -MaxEvents 5 | Format-Table TimeCreated, Id, Message
```

## Vulnerable Services Configuration

### 1. Create Weak Users for Testing

```powershell
# Create local users with weak passwords
net user weakuser Password1 /add
net user admin admin /add
net user test test /add
net user guest guest /add /active:yes

# Add admin user to administrators group
net localgroup administrators admin /add
```

### 2. Configure Weak File Permissions

```powershell
# Create vulnerable directory
New-Item -Path "C:\VulnerableShare" -ItemType Directory
New-Item -Path "C:\VulnerableShare\sensitive_data.txt" -ItemType File
Set-Content -Path "C:\VulnerableShare\sensitive_data.txt" -Value "Credit Card Numbers: 4111-1111-1111-1111"

# Create SMB share with weak permissions
New-SmbShare -Name "VulnShare" -Path "C:\VulnerableShare" -FullAccess "Everyone"
Grant-SmbShareAccess -Name "VulnShare" -AccountName "Everyone" -AccessRight Full -Force

# Set weak NTFS permissions
icacls "C:\VulnerableShare" /grant Everyone:F /T
```

### 3. Create Scheduled Tasks (Privilege Escalation)

```powershell
# Create scheduled task with weak permissions
$action = New-ScheduledTaskAction -Execute "cmd.exe"
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "VulnerableTask" -Description "Vulnerable task for privilege escalation testing"

# Make task writable by everyone
icacls "C:\Windows\System32\Tasks\VulnerableTask" /grant Everyone:F
```

## Attack Scenarios for Testing

### 1. RDP Brute Force
```powershell
# From Kali Linux attacker:
# hydra -l socuser -P /usr/share/wordlists/rockyou.txt rdp://192.168.1.30

# This will generate Event ID 4625 (failed logons)
```

### 2. SMB Enumeration
```powershell
# From Kali:
# smbclient -L //192.168.1.30 -N
# enum4linux -a 192.168.1.30
```

### 3. Mimikatz Credential Dumping
```powershell
# Download Mimikatz on Windows
# This will trigger Sysmon and Windows Defender logs
# Execute: mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

## Key Event IDs to Monitor

### Security Event Logs
| Event ID | Description | Importance |
|----------|-------------|------------|
| 4624 | Successful Logon | Track normal authentication |
| 4625 | Failed Logon | Detect brute force attacks |
| 4648 | Explicit Credential Logon | Detect credential theft/pass-the-hash |
| 4672 | Special Privileges Assigned | Track admin access |
| 4688 | Process Created | Track process execution |
| 4697 | Service Installed | Detect persistence |
| 4720 | User Account Created | Detect account creation |
| 4740 | User Account Locked Out | Detect brute force |

### Sysmon Event Logs
| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | Image/DLL Loaded |
| 8 | CreateRemoteThread |
| 10 | Process Access |
| 11 | File Created |
| 13 | Registry Value Set |
| 22 | DNS Query |

### PowerShell Event Logs
| Event ID | Description |
|----------|-------------|
| 4103 | Module Logging |
| 4104 | Script Block Logging |

## Firewall Configuration

```powershell
# Allow specific ports for attack testing
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
New-NetFirewallRule -DisplayName "Allow SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
New-NetFirewallRule -DisplayName "Allow WinRM" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow

# Log dropped packets
Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
```

## Monitoring and Validation

### Check Winlogbeat Status
```powershell
# Check service
Get-Service winlogbeat

# View recent logs
Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat" -Tail 100

# Force manual event send
Restart-Service winlogbeat
```

### Verify Logs Reaching SIEM

On the SIEM server (192.168.1.20), check:
```bash
# Check Logstash is receiving logs
curl -X GET "localhost:9200/_cat/indices?v" | grep soc-lab

# Query recent Windows events
curl -X GET "localhost:9200/soc-lab-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        {"match": {"host.name": "WIN10-VULN"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "size": 10,
  "sort": [{"@timestamp": "desc"}]
}
'
```

### Test Log Generation
```powershell
# Generate security events for testing
# Failed authentication
net use \\localhost\IPC$ /user:fakeuser wrongpassword 2>$null

# Successful authentication
net use \\localhost\IPC$ /user:socuser Password123!

# Process creation
notepad.exe

# Network connection
Test-NetConnection -ComputerName 192.168.1.20 -Port 5044

# Registry modification
New-ItemProperty -Path "HKCU:\Software\Test" -Name "TestValue" -Value "123" -Force

# File creation
New-Item -Path "C:\Temp\test.txt" -ItemType File -Force

# Wait a moment then check SIEM
Start-Sleep -Seconds 10
Write-Host "Check Kibana dashboard at http://192.168.1.20:5601"
```

## Troubleshooting

### Winlogbeat Not Sending Logs

1. **Check service status:**
```powershell
Get-Service winlogbeat
```

2. **Check network connectivity to SIEM:**
```powershell
Test-NetConnection -ComputerName 192.168.1.20 -Port 5044
```

3. **Check Winlogbeat logs:**
```powershell
Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat" -Tail 50
```

4. **Verify configuration:**
```powershell
cd "C:\Program Files\Winlogbeat"
.\winlogbeat.exe test config -c .\winlogbeat.yml
.\winlogbeat.exe test output -c .\winlogbeat.yml
```

5. **Check Windows Firewall:**
```powershell
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*winlogbeat*"}
```

### Common Issues

- **Connection timeout**: Verify SIEM server is running and accessible
- **Authentication errors**: Check that Logstash is configured to accept Beats input
- **No events showing**: Verify audit policies are enabled and events are being generated
- **High CPU usage**: Reduce event filtering or increase event_id filtering in config

## Snapshots

Create VM snapshots for easy recovery:
```bash
# Clean state after setup
VBoxManage snapshot "WIN10-VULN" take "Clean-Install-With-Winlogbeat" --description "Fresh install with logging configured"

# After intentional infections
VBoxManage snapshot "WIN10-VULN" take "Pre-Attack" --description "Before running attack scenarios"
```

## Security Notes

⚠️ **WARNING**: This VM is intentionally vulnerable. Never expose it to the internet or untrusted networks.

- All security features are weakened for educational purposes
- Always run in an isolated lab environment
- Use snapshots to restore to clean states
- Monitor resource usage as logging can be intensive

## Next Steps

1. ✅ Verify Winlogbeat is sending logs to SIEM
2. ✅ Check Kibana dashboard shows Windows events
3. ✅ Generate test security events
4. ✅ Practice incident response scenarios
5. ✅ Document findings and create detection rules

## References

- [Winlogbeat Documentation](https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html)
- [Windows Event Log Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
