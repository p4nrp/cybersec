# SOC Lab Exercises

This document provides a comprehensive set of hands-on exercises designed to develop SOC analyst skills using the VirtualBox lab environment.

## Exercise Categories

### 🔰 Beginner Level
- Basic log analysis and pattern recognition
- Simple attack detection and response
- Fundamental SIEM usage
- Network traffic analysis basics

### 🔶 Intermediate Level
- Complex attack chain analysis
- Malware analysis and reverse engineering
- Advanced SIEM queries and dashboards
- Incident response procedures

### 🔴 Advanced Level
- Threat hunting and proactive detection
- Memory forensics and deep analysis
- Custom detection rule development
- Advanced persistent threat simulation

## Exercise Structure

Each exercise includes:
- **Learning Objectives** - What skills you'll develop
- **Prerequisites** - Required knowledge and setup
- **Scenario Description** - Background and context
- **Step-by-Step Instructions** - Detailed procedures
- **Expected Results** - What you should observe
- **Analysis Questions** - Critical thinking prompts
- **Additional Challenges** - Extended learning opportunities

---

## Beginner Exercises

### Exercise 1: Basic Log Analysis
**Duration**: 45 minutes  
**Difficulty**: 🔰 Beginner

#### Learning Objectives
- Navigate and search log files
- Identify common log formats
- Recognize normal vs. suspicious activity
- Use basic command-line tools for log analysis

#### Prerequisites
- Access to Ubuntu Vulnerable VM (10.0.2.101)
- Basic Linux command-line knowledge

#### Scenario
You're a new SOC analyst tasked with reviewing authentication logs to identify any suspicious login activity on a Linux server.

#### Instructions

1. **Connect to the target system**
   ```bash
   ssh soc@10.0.2.101
   # Password: soclab123
   ```

2. **Examine authentication logs**
   ```bash
   # View the authentication log
   sudo tail -50 /var/log/auth.log
   
   # Search for failed login attempts
   grep "Failed password" /var/log/auth.log
   
   # Count total failed attempts
   grep "Failed password" /var/log/auth.log | wc -l
   ```

3. **Analyze patterns**
   ```bash
   # Find top attacking IP addresses
   grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
   
   # Find targeted usernames
   grep "Failed password" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -nr
   
   # Check for successful logins
   grep "Accepted password" /var/log/auth.log
   ```

4. **Timeline analysis**
   ```bash
   # View recent activity
   grep -E "(Failed password|Accepted password)" /var/log/auth.log | tail -20
   
   # Check for patterns in timing
   grep "Failed password" /var/log/auth.log | awk '{print $1, $2, $3}' | uniq -c
   ```

#### Analysis Questions
1. How many failed login attempts were recorded?
2. Which IP addresses attempted the most failed logins?
3. What usernames were most commonly targeted?
4. Were there any successful logins from suspicious IPs?
5. What time periods showed the highest attack activity?

#### Expected Results
- Identification of brute force attack patterns
- Understanding of log file structure
- Recognition of suspicious vs. normal activity

---

### Exercise 2: Network Traffic Analysis with Wireshark
**Duration**: 60 minutes  
**Difficulty**: 🔰 Beginner

#### Learning Objectives
- Capture and analyze network traffic
- Use Wireshark filters effectively
- Identify different protocols and their purposes
- Detect suspicious network communications

#### Prerequisites
- Wireshark installed on host system or Kali VM
- Basic understanding of TCP/IP networking

#### Scenario
Network monitoring has detected unusual traffic patterns. You need to capture and analyze network traffic to identify potential security issues.

#### Instructions

1. **Start packet capture**
   ```bash
   # On Kali Linux VM
   sudo wireshark &
   
   # Select the network interface (usually eth0)
   # Start capturing packets
   ```

2. **Generate network traffic**
   ```bash
   # From Kali VM, generate various types of traffic
   
   # Normal web browsing
   curl http://10.0.2.101
   
   # SSH connection
   ssh soc@10.0.2.101
   
   # Port scan (generates suspicious traffic)
   nmap -sS 10.0.2.101
   ```

3. **Apply Wireshark filters**
   ```
   # Filter for HTTP traffic
   http
   
   # Filter for SSH traffic
   tcp.port == 22
   
   # Filter for traffic to/from specific IP
   ip.addr == 10.0.2.101
   
   # Filter for TCP SYN packets (port scanning)
   tcp.flags.syn == 1 and tcp.flags.ack == 0
   ```

4. **Analyze captured traffic**
   - Right-click on packets to follow TCP streams
   - Examine packet details in the middle pane
   - Look for unusual patterns or protocols

#### Analysis Questions
1. What different protocols did you observe?
2. How can you distinguish between normal and scanning traffic?
3. What information can be extracted from HTTP traffic?
4. How does SSH traffic appear compared to unencrypted protocols?

#### Additional Challenges
- Capture traffic during a brute force attack
- Identify data exfiltration attempts
- Analyze DNS queries for suspicious domains

---

### Exercise 3: SIEM Dashboard Creation
**Duration**: 90 minutes  
**Difficulty**: 🔰 Beginner

#### Learning Objectives
- Navigate Kibana interface
- Create basic visualizations
- Build security monitoring dashboards
- Set up simple alerts

#### Prerequisites
- ELK SIEM VM running (10.0.2.100)
- Log data being collected from other VMs

#### Scenario
You need to create a security dashboard to monitor authentication events and provide visibility into potential security incidents.

#### Instructions

1. **Access Kibana**
   ```
   Open browser: http://10.0.2.100:5601
   ```

2. **Explore data**
   - Navigate to "Discover" tab
   - Select the `soc-lab-*` index pattern
   - Explore available fields and data

3. **Create visualizations**
   
   **Failed Login Attempts Over Time**
   - Go to "Visualize" → "Create visualization" → "Line chart"
   - X-axis: Date histogram on @timestamp
   - Y-axis: Count of documents
   - Filter: `event_category:"ssh_failed_login"`
   
   **Top Attacking IP Addresses**
   - Create "Data table" visualization
   - Rows: Terms aggregation on `src_ip` field
   - Metrics: Count
   - Filter: `event_category:"ssh_failed_login"`
   
   **Authentication Success vs. Failure**
   - Create "Pie chart" visualization
   - Slice: Terms aggregation on `event_category`
   - Include: ssh_failed_login, ssh_successful_login

4. **Build dashboard**
   - Go to "Dashboard" → "Create dashboard"
   - Add your created visualizations
   - Arrange and resize panels
   - Save the dashboard as "Authentication Monitoring"

#### Analysis Questions
1. What patterns do you observe in the failed login attempts?
2. Which time periods show the highest attack activity?
3. How effective are the current security measures?
4. What additional visualizations would be helpful?

---

## Intermediate Exercises

### Exercise 4: Malware Analysis Fundamentals
**Duration**: 120 minutes  
**Difficulty**: 🔶 Intermediate

#### Learning Objectives
- Perform static malware analysis
- Use analysis tools safely
- Identify malware characteristics and behavior
- Create indicators of compromise (IOCs)

#### Prerequisites
- Windows 10 Vulnerable VM with analysis tools
- Basic understanding of Windows processes
- Malware samples from tools directory

#### Scenario
A suspicious file has been detected on a workstation. You need to analyze it to determine if it's malicious and understand its capabilities.

#### Instructions

1. **Set up analysis environment**
   ```powershell
   # On Windows VM, create isolated analysis folder
   mkdir C:\Analysis
   cd C:\Analysis
   
   # Copy malware sample (use safe educational samples)
   copy \\10.0.2.100\tools\malware-samples\suspicious.exe .
   ```

2. **Static analysis**
   ```powershell
   # Calculate file hash
   Get-FileHash suspicious.exe -Algorithm SHA256
   
   # Check file properties
   Get-ItemProperty suspicious.exe
   
   # Examine strings
   strings suspicious.exe | findstr -i "http"
   strings suspicious.exe | findstr -i "registry"
   ```

3. **Behavioral analysis preparation**
   ```powershell
   # Enable process monitoring
   # Start Process Monitor (ProcMon)
   # Configure filters for the suspicious executable
   ```

4. **Safe execution and monitoring**
   ```powershell
   # Execute in controlled environment
   # Monitor file system changes
   # Monitor registry modifications
   # Monitor network connections
   ```

5. **Analysis and documentation**
   - Document observed behaviors
   - Identify persistence mechanisms
   - Note network communications
   - Create IOC list

#### Analysis Questions
1. What type of malware is this (trojan, backdoor, etc.)?
2. What persistence mechanisms does it use?
3. What network communications were observed?
4. What files or registry keys were modified?
5. How would you detect this malware in the future?

---

### Exercise 5: Advanced Log Correlation
**Duration**: 90 minutes  
**Difficulty**: 🔶 Intermediate

#### Learning Objectives
- Correlate events across multiple log sources
- Build complex search queries
- Identify attack patterns and timelines
- Create actionable intelligence

#### Prerequisites
- Multiple VMs generating log data
- ELK SIEM with data from all systems
- Understanding of attack methodologies

#### Scenario
Multiple security alerts have been triggered. You need to correlate events across different systems to understand the full scope of a potential security incident.

#### Instructions

1. **Initial alert triage**
   ```
   # In Kibana, search for recent alerts
   @timestamp:[now-1h TO now] AND (event_category:"ssh_failed_login" OR winlog.event_id:4625)
   ```

2. **Identify related events**
   ```
   # Find events from the same source IP
   src_ip:"10.0.2.15" AND @timestamp:[now-2h TO now]
   
   # Look for successful logins after failed attempts
   src_ip:"10.0.2.15" AND event_category:"ssh_successful_login"
   ```

3. **Build attack timeline**
   ```
   # Create timeline of events
   src_ip:"10.0.2.15" | sort @timestamp
   
   # Look for lateral movement
   (src_ip:"10.0.2.102" OR src_ip:"10.0.2.101") AND destination.ip:*
   ```

4. **Cross-system correlation**
   ```
   # Correlate Windows and Linux events
   (winlog.event_id:4624 AND winlog.event_data.IpAddress:"10.0.2.15") OR 
   (event_category:"ssh_successful_login" AND src_ip:"10.0.2.15")
   ```

5. **Impact assessment**
   ```
   # Check for data access
   (winlog.event_id:4663 OR program:"audit") AND user:"compromised_account"
   
   # Look for privilege escalation
   winlog.event_id:4672 AND winlog.event_data.PrivilegeList:*SeDebugPrivilege*
   ```

#### Analysis Questions
1. What was the initial attack vector?
2. How did the attacker move laterally?
3. What systems were compromised?
4. What data might have been accessed?
5. What is the recommended response?

---

## Advanced Exercises

### Exercise 6: Threat Hunting Campaign
**Duration**: 180 minutes  
**Difficulty**: 🔴 Advanced

#### Learning Objectives
- Develop threat hunting hypotheses
- Create custom detection logic
- Perform proactive threat detection
- Build threat intelligence

#### Prerequisites
- Advanced SIEM knowledge
- Understanding of MITRE ATT&CK framework
- Experience with multiple attack techniques

#### Scenario
Intelligence suggests that advanced persistent threat (APT) actors are targeting organizations similar to yours. You need to proactively hunt for signs of compromise.

#### Instructions

1. **Develop hunting hypotheses**
   - Research current APT techniques
   - Identify likely attack vectors for your environment
   - Create testable hypotheses

2. **Hunt for living-off-the-land techniques**
   ```
   # PowerShell execution with suspicious parameters
   winlog.event_id:4688 AND process.command_line:*powershell* AND 
   (process.command_line:*-enc* OR process.command_line:*-nop* OR process.command_line:*-w hidden*)
   
   # WMI usage for lateral movement
   winlog.event_id:4688 AND process.name:wmic.exe AND 
   process.command_line:*/node:*
   ```

3. **Hunt for persistence mechanisms**
   ```
   # Scheduled task creation
   winlog.event_id:4698 AND winlog.event_data.TaskName:*
   
   # Service installation
   winlog.event_id:4697 AND winlog.event_data.ServiceName:*
   
   # Registry run key modifications
   winlog.event_id:4657 AND winlog.event_data.ObjectName:*\\Run\\*
   ```

4. **Hunt for data exfiltration**
   ```
   # Large outbound data transfers
   bytes:>10000000 AND source.ip:10.0.2.0/24 AND NOT destination.ip:10.0.2.0/24
   
   # Unusual DNS queries
   dns.question.name:*.exe OR dns.question.name:*powershell*
   ```

5. **Validate findings**
   - Investigate suspicious results
   - Eliminate false positives
   - Document true positives

#### Analysis Questions
1. What hunting hypotheses proved most valuable?
2. Which techniques were most difficult to detect?
3. What new detection rules should be implemented?
4. How can the hunting process be improved?

---

### Exercise 7: Memory Forensics Investigation
**Duration**: 150 minutes  
**Difficulty**: 🔴 Advanced

#### Learning Objectives
- Acquire and analyze memory dumps
- Use Volatility for memory analysis
- Identify malware in memory
- Extract forensic artifacts

#### Prerequisites
- Memory dump from compromised system
- Volatility framework installed
- Advanced malware analysis knowledge

#### Scenario
A system has been compromised and you have acquired a memory dump. You need to analyze the memory to understand what happened and gather evidence.

#### Instructions

1. **Memory dump analysis setup**
   ```bash
   # Install Volatility (if not already installed)
   pip install volatility3
   
   # Identify the memory profile
   vol.py -f memory.dump imageinfo
   ```

2. **Process analysis**
   ```bash
   # List running processes
   vol.py -f memory.dump --profile=Win10x64 pslist
   
   # Look for suspicious processes
   vol.py -f memory.dump --profile=Win10x64 psscan
   
   # Examine process tree
   vol.py -f memory.dump --profile=Win10x64 pstree
   ```

3. **Network analysis**
   ```bash
   # Show network connections
   vol.py -f memory.dump --profile=Win10x64 netscan
   
   # Extract network artifacts
   vol.py -f memory.dump --profile=Win10x64 connscan
   ```

4. **Malware analysis**
   ```bash
   # Detect code injection
   vol.py -f memory.dump --profile=Win10x64 malfind
   
   # Extract suspicious processes
   vol.py -f memory.dump --profile=Win10x64 procdump -p <PID> -D ./
   
   # Analyze DLLs
   vol.py -f memory.dump --profile=Win10x64 dlllist -p <PID>
   ```

5. **Artifact extraction**
   ```bash
   # Extract command history
   vol.py -f memory.dump --profile=Win10x64 cmdline
   
   # Extract registry information
   vol.py -f memory.dump --profile=Win10x64 hivelist
   
   # Extract files
   vol.py -f memory.dump --profile=Win10x64 filescan
   ```

#### Analysis Questions
1. What malicious processes were identified?
2. What network connections were established?
3. What persistence mechanisms were used?
4. What data was potentially compromised?
5. What recommendations would you make?

---

## Capstone Exercise: Full Incident Response

### Exercise 8: Complete IR Scenario
**Duration**: 4-6 hours  
**Difficulty**: 🔴 Advanced

#### Learning Objectives
- Execute complete incident response lifecycle
- Coordinate multiple analysis techniques
- Make critical security decisions
- Document comprehensive findings

#### Prerequisites
- Completion of previous exercises
- All lab VMs operational
- Understanding of IR processes

#### Scenario
Your organization has detected suspicious activity across multiple systems. You are the lead analyst responsible for the complete incident response from detection through recovery.

#### Phase 1: Detection and Analysis (90 minutes)
1. **Initial alert triage**
   - Review SIEM alerts and dashboards
   - Prioritize incidents based on severity
   - Gather initial evidence

2. **Scope determination**
   - Identify affected systems
   - Determine attack timeline
   - Assess potential impact

3. **Evidence collection**
   - Preserve log data
   - Create memory dumps
   - Document network traffic

#### Phase 2: Containment and Eradication (60 minutes)
1. **Immediate containment**
   - Isolate affected systems
   - Block malicious IP addresses
   - Prevent lateral movement

2. **Threat eradication**
   - Remove malware
   - Close attack vectors
   - Patch vulnerabilities

#### Phase 3: Recovery and Lessons Learned (90 minutes)
1. **System recovery**
   - Restore from clean backups
   - Implement additional monitoring
   - Validate system integrity

2. **Documentation and reporting**
   - Create incident timeline
   - Document IOCs
   - Write executive summary
   - Provide recommendations

#### Deliverables
1. **Incident Response Report**
   - Executive summary
   - Technical analysis
   - Timeline of events
   - Impact assessment
   - Recommendations

2. **Technical Artifacts**
   - IOC list
   - YARA rules
   - Detection signatures
   - Network diagrams

3. **Process Improvements**
   - Updated playbooks
   - New detection rules
   - Training recommendations
   - Tool enhancements

---

## Assessment and Certification

### Skills Assessment Matrix

| Skill Area | Beginner | Intermediate | Advanced |
|------------|----------|--------------|----------|
| Log Analysis | Basic grep/search | Complex queries | Advanced correlation |
| Network Analysis | Protocol identification | Traffic analysis | Deep packet inspection |
| Malware Analysis | Static analysis | Dynamic analysis | Memory forensics |
| SIEM Usage | Basic dashboards | Custom queries | Rule development |
| Incident Response | Documentation | Investigation | Leadership |

### Certification Requirements

To complete SOC Analyst certification:

1. **Complete all beginner exercises** (minimum 80% score)
2. **Complete 3 intermediate exercises** (minimum 85% score)
3. **Complete 1 advanced exercise** (minimum 90% score)
4. **Complete capstone exercise** (comprehensive assessment)
5. **Submit portfolio** of work products

### Continuing Education

- Advanced threat hunting techniques
- Cloud security monitoring
- Machine learning in security
- Threat intelligence analysis
- Advanced forensics techniques

---

## Additional Resources

### Reference Materials
- MITRE ATT&CK Framework
- NIST Cybersecurity Framework
- SANS FOR508 Course Materials
- Incident Response Playbooks

### Tools and Techniques
- Sigma rule development
- YARA rule creation
- Custom Splunk/ELK queries
- Threat intelligence platforms

### Community Resources
- Security blogs and research
- Threat intelligence feeds
- Open source security tools
- Professional certifications