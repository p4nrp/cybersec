# VirtualBox SOC Analyst Practice Labs

<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/N9KAUN8.png">
</p>

Created By : 0xp4nrp


This repository contains a comprehensive VirtualBox lab environment designed for practicing cybersecurity SOC (Security Operations Center) analyst skills. The lab includes vulnerable systems, monitoring tools, attack scenarios, and hands-on exercises.

## 🎯 Lab Overview

This lab environment simulates a realistic corporate network with:
- **Vulnerable Windows Systems** - For practicing incident response
- **Vulnerable Linux Systems** - For Unix-based security analysis
- **SIEM/Monitoring Stack** - ELK Stack, Splunk, and other monitoring tools
- **Attacker Machine** - Kali Linux with penetration testing tools
- **Domain Controller** - Windows AD environment
- **Network Monitoring** - Traffic analysis and network security

## 🏗️ Architecture

### Network Topology
```
┌────────────────────────────────────────────────────────────────────┐
│                   VirtualBox NAT Network (192.168.1.0/24)          │
└────────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
┌───────▼───────┐      ┌────────▼────────┐    ┌────────▼────────┐
│   SOC-DC1     │      │   SIEM-ELK      │    │ KALI-ATTACKER   │
│  192.168.1.10 │      │  192.168.1.20   │    │  192.168.1.50   │
│  Win Srv 2019 │      │  Ubuntu 22.04   │    │  Kali Linux     │
│  AD/DNS/DHCP  │      │  ELK + Wazuh    │    │  Attack Tools   │
└───────────────┘      └─────────────────┘    └─────────────────┘
                               ▲
                               │ ALL LOGS FLOW HERE
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
┌───────▼───────┐      ┌───────▼───────┐           
│  WIN10-VULN   │      │ UBUNTU-VULN   │           
│ 192.168.1.30  │      │ 192.168.1.40  │           
│ Windows 10    │      │ Ubuntu 20.04  │           
│ Winlogbeat ───┼──────┼─→ Filebeat ───┘           
└───────────────┘      └───────────────┘           
```

### Log Collection Flow
```
Windows Systems                    Linux Systems
     │                                  │
     │ Winlogbeat (Port 5044)           │ Filebeat (Port 5044)
     │                                  │ Rsyslog (Port 514)
     ├──────────────────────────────────┤
     │                                  │
     ▼                                  ▼
         Logstash (Parse & Transform)
                     │
                     ▼
           Elasticsearch (Store & Index)
                     │
                     ▼
             Kibana (Visualize & Alert)
                     │
                     ▼
            SOC Analyst Dashboard
           http://192.168.1.20:5601
```

## 🚀 Quick Start

### Prerequisites
- **VirtualBox**: 7.0+ installed
- **RAM**: 16GB minimum, 32GB+ recommended
- **Storage**: 250GB+ free disk space
- **CPU**: 4+ cores recommended
- **Host OS**: Windows 10/11, macOS, or Linux

### VM Resource Allocation

| VM | RAM | CPU | Storage | Purpose |
|----|-----|-----|---------|---------|
| SIEM-ELK | 8-16GB | 4 cores | 100GB | Log collection & analysis |
| SOC-DC1 | 4GB | 2 cores | 60GB | Domain Controller |
| WIN10-VULN | 4GB | 2 cores | 50GB | Vulnerable Windows endpoint |
| UBUNTU-VULN | 2-4GB | 2 cores | 30GB | Vulnerable Linux server |
| KALI-ATTACKER | 4-8GB | 2 cores | 50GB | Attack simulation |
| **TOTAL** | **22-36GB** | **12 cores** | **290GB** | **Full Lab** |

### Setup Steps

#### Step 1: Create NAT Network

```bash
# Create isolated network for lab
VBoxManage natnetwork add \
  --netname "SOC-Lab-Network" \
  --network "192.168.1.0/24" \
  --enable \
  --dhcp off

# Verify
VBoxManage list natnetworks
```

Or via VirtualBox GUI:
1. **File** → **Preferences** → **Network** → **NAT Networks**
2. Click **+** to add network
3. Name: `SOC-Lab-Network`
4. IPv4 Prefix: `192.168.1.0/24`
5. Disable DHCP

#### Step 2: Download Required ISOs

- [Windows Server 2019 Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019)
- [Windows 10 Pro Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise)
- [Ubuntu Server 22.04 LTS](https://ubuntu.com/download/server)
- [Ubuntu Server 20.04 LTS](https://ubuntu.com/download/server)
- [Kali Linux 2023.4](https://www.kali.org/get-kali/)

#### Step 3: Build VMs in Order

**Recommended build order for log collection:**

1. **SIEM-ELK** (192.168.1.20) - Build FIRST
   - Follow: [`vm-conf/siem-elk.md`](vm-conf/siem-elk.md)
   - Install ELK Stack, Wazuh, Suricata
   - Verify Logstash is listening on port 5044
   - Access Kibana: http://192.168.1.20:5601

2. **SOC-DC1** (192.168.1.10) - Build SECOND
   - Follow: [`vm-conf/win-server.md`](vm-conf/win-server.md)
   - Configure AD, DNS, DHCP
   - Install Winlogbeat → Forward to SIEM

3. **WIN10-VULN** (192.168.1.30)
   - Follow: [`vm-conf/win10-vuln.md`](vm-conf/win10-vuln.md)
   - Configure vulnerable services
   - Install Winlogbeat → Forward to SIEM
   - Verify logs in Kibana

4. **UBUNTU-VULN** (192.168.1.40)
   - Follow: [`vm-conf/ubuntuserver-vuln.md`](vm-conf/ubuntuserver-vuln.md)
   - Install DVWA, vulnerable apps
   - Configure Filebeat & Rsyslog → Forward to SIEM
   - Verify logs in Kibana

5. **KALI-ATTACKER** (192.168.1.50) - Build LAST
   - Follow: [`vm-conf/kali.md`](vm-conf/kali.md)
   - Configure attack tools
   - Run test attacks to generate logs

#### Step 4: Verify Log Collection

On SIEM server (192.168.1.20):

```bash
# Check Elasticsearch indices
curl http://localhost:9200/_cat/indices?v

# Should show: soc-lab-YYYY.MM.DD

# Check logs from Windows 10
curl -X GET "localhost:9200/soc-lab-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {"match": {"host.name": "WIN10-VULN"}},
  "size": 5
}'

# Check logs from Ubuntu
curl -X GET "localhost:9200/soc-lab-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {"match": {"log_source": "ubuntu-vuln"}},
  "size": 5
}'
```

Access Kibana dashboard: **http://192.168.1.20:5601**

#### Step 5: Run Test Attacks

From Kali Linux (192.168.1.50):

```bash
# SSH brute force (generates logs)
hydra -l admin -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://192.168.1.40

# Web attack (generates logs)
curl "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1"

# Network scan (generates Suricata alerts)
nmap -sS 192.168.1.0/24
```

Check SIEM for generated alerts!

## 📚 Lab Exercises

### Beginner Level
- [ ] **Log Analysis Basics** - Analyze Windows Event Logs
- [ ] **Network Traffic Analysis** - Use Wireshark to investigate suspicious traffic
- [ ] **Malware Detection** - Identify and analyze malicious files
- [ ] **Incident Timeline** - Create timeline of security events

### Intermediate Level
- [ ] **Advanced Persistent Threat (APT)** - Investigate multi-stage attack
- [ ] **Lateral Movement Detection** - Track attacker movement across network
- [ ] **Data Exfiltration** - Detect and analyze data theft attempts
- [ ] **Privilege Escalation** - Identify elevation of privileges attacks

### Advanced Level
- [ ] **Memory Forensics** - Analyze memory dumps for artifacts
- [ ] **Network Forensics** - Deep packet inspection and analysis
- [ ] **Threat Hunting** - Proactive threat detection techniques
- [ ] **Incident Response** - Full IR lifecycle simulation

## 🛠️ Tools & Technologies

### SIEM Stack (192.168.1.20)
- **Elasticsearch 7.x** - Log storage and indexing
- **Logstash 7.x** - Log parsing and transformation
- **Kibana 7.x** - Visualization and dashboards
- **Wazuh** - Host-based IDS and file integrity monitoring
- **Suricata** - Network IDS/IPS
- **Filebeat** - Lightweight log shipper
- **Rsyslog** - Traditional syslog server

### Log Collection Agents
- **Winlogbeat** - Windows event log forwarding
  - Installed on: SOC-DC1, WIN10-VULN
  - Forwards to: Logstash (192.168.1.20:5044)
  - Collects: Security, System, Application, PowerShell, Sysmon logs

- **Filebeat** - General-purpose log shipper
  - Installed on: UBUNTU-VULN, SIEM-ELK
  - Forwards to: Logstash (192.168.1.20:5044)
  - Collects: Auth logs, Apache logs, MySQL logs, FTP logs

### Attack Tools (Kali Linux)
- **Nmap** - Network reconnaissance
- **Metasploit Framework** - Exploitation
- **Hydra** - Password brute forcing
- **SQLMap** - SQL injection testing
- **Burp Suite** - Web application testing
- **Nikto** - Web server scanning
- **John the Ripper** - Password cracking
- **Wireshark** - Traffic analysis

### Vulnerable Applications (Ubuntu)
- **DVWA** - Damn Vulnerable Web Application
- **Weak SSH/FTP servers** - Brute force testing
- **Anonymous FTP** - Unauthorized access
- **Unpatched services** - Exploitation practice

## 📖 Documentation

### Network Configuration
- [Network Setup Guide](net-conf/README.md) - Complete network configuration
- [Network Topology](topology/topology.md) - Visual network diagram

### VM Configuration Guides (WITH LOG FORWARDING)
- [SIEM-ELK Server](vm-conf/siem-elk.md) - **BUILD THIS FIRST** - Central log collection
- [Windows Server DC](vm-conf/win-server.md) - Domain Controller with Winlogbeat
- [Windows 10 Vulnerable](vm-conf/win10-vuln.md) - Endpoint with Winlogbeat
- [Ubuntu Vulnerable Server](vm-conf/ubuntuserver-vuln.md) - Server with Filebeat & Rsyslog
- [Kali Attacker](vm-conf/kali.md) - Attack machine with pre-built scenarios

### Key Features
✅ **All logs automatically forwarded to SIEM**
✅ **Real-time log collection and analysis**
✅ **Pre-configured Kibana dashboards**
✅ **Attack detection rules included**
✅ **Network IDS/IPS with Suricata**
✅ **Host-based IDS with Wazuh**

### Additional Guides
- **[🚀 Quick Start Guide](QUICKSTART.md)** - Get started in 5-6 hours
- **[⚔️ Attack Scenarios](attack-scenarios.md)** - Practice attacks with log analysis

## 🔧 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 16GB | 32GB+ |
| CPU | 4 cores | 8+ cores |
| Storage | 200GB | 500GB+ |
| Network | 1 Gbps | 1 Gbps+ |

## 🎓 Learning Objectives

After completing these labs, you will be able to:
- Analyze security logs and identify threats
- Perform incident response procedures
- Use SIEM tools effectively
- Conduct network traffic analysis
- Perform malware analysis
- Create incident timelines and reports
- Implement threat hunting techniques
- Understand attack patterns and TTPs

## ⚠️ Legal Disclaimer

This lab environment is for educational purposes only. All vulnerable systems and attack tools should only be used in isolated lab environments. Do not use these tools or techniques against systems you do not own or have explicit permission to test.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests for improvements.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
