# Vulnerable Windows 10 VM Configuration

## VM Specifications
- **OS**: Windows 10 Pro (Build 19041 or later)
- **RAM**: 4GB (minimum), 8GB (recommended)
- **Storage**: 60GB
- **Network**: NAT Network (SOC-Lab-Network)
- **CPU**: 2 cores

## Installation Steps

1. **Download Windows 10 ISO**
   - Download from Microsoft's official website
   - Use Windows 10 Pro for better features

2. **VirtualBox Configuration**
   ```bash
   # Create VM
   VBoxManage createvm --name "Windows10-Vulnerable" --ostype "Windows10_64" --register
   
   # Configure VM
   VBoxManage modifyvm "Windows10-Vulnerable" --memory 4096 --cpus 2
   VBoxManage modifyvm "Windows10-Vulnerable" --vram 128
   VBoxManage modifyvm "Windows10-Vulnerable" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
   VBoxManage modifyvm "Windows10-Vulnerable" --audio none
   
   # Create and attach storage
   VBoxManage createhd --filename "Windows10-Vulnerable.vdi" --size 61440
   VBoxManage storagectl "Windows10-Vulnerable" --name "SATA Controller" --add sata --controller IntelAHCI
   VBoxManage storageattach "Windows10-Vulnerable" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "Windows10-Vulnerable.vdi"
   VBoxManage storageattach "Windows10-Vulnerable" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "Windows10.iso"
   ```

## Post-Installation Configuration

### 1. Disable Windows Defender
```powershell
# Run as Administrator
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisablePrivacyMode $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
```

### 2. Enable Vulnerable Services
```powershell
# Enable SMBv1
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Enable Telnet Client
Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient

# Enable IIS with vulnerable configurations
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer
Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45
```

### 3. Create Vulnerable User Accounts
```powershell
# Create weak password users
net user vulnerable Password123 /add
net user admin admin /add
net user guest guest /add /active:yes
net user test test /add

# Add users to groups
net localgroup "Remote Desktop Users" vulnerable /add
net localgroup "Administrators" admin /add
```

### 4. Install Vulnerable Software
- **Java 8** (older version with known vulnerabilities)
- **Adobe Flash Player** (outdated version)
- **Internet Explorer** (with ActiveX enabled)
- **FileZilla Server** (with weak configuration)
- **Apache Tomcat** (with default credentials)

### 5. Configure Logging
```powershell
# Enable PowerShell logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1

# Enable process creation logging
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable

# Enable logon/logoff logging
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
```

## Vulnerable Configurations

### 1. Weak File Permissions
```powershell
# Create files with weak permissions
icacls "C:\VulnerableApp" /grant Everyone:F /T
icacls "C:\Windows\Temp" /grant Everyone:F /T
```

### 2. Registry Vulnerabilities
```powershell
# Disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0

# Enable AutoLogon with stored credentials
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d vulnerable
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d Password123
```

### 3. Network Vulnerabilities
```powershell
# Enable WinRM with basic authentication
winrm quickconfig -force
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'

# Configure RDP with weak settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0
```

## Installed Monitoring Agents

### 1. Sysmon
```powershell
# Download and install Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"
C:\Tools\Sysmon\sysmon64.exe -accepteula -i sysmon-config.xml
```

### 2. Winlogbeat
```powershell
# Install Winlogbeat for log forwarding to ELK
# Configuration will forward logs to SIEM VM
```

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Windows Login | vulnerable | Password123 |
| Windows Login | admin | admin |
| RDP | vulnerable | Password123 |
| WinRM | vulnerable | Password123 |

## Attack Scenarios Supported

1. **Credential Attacks**
   - Password spraying
   - Brute force attacks
   - Pass-the-hash

2. **Privilege Escalation**
   - UAC bypass
   - Service exploitation
   - DLL hijacking

3. **Persistence**
   - Registry modifications
   - Scheduled tasks
   - Service creation

4. **Lateral Movement**
   - SMB exploitation
   - WMI abuse
   - PowerShell remoting

## Security Notes

⚠️ **WARNING**: This VM is intentionally vulnerable and should only be used in isolated lab environments. Never connect this VM to production networks or the internet without proper isolation.