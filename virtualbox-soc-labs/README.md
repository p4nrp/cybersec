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

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Attacker VM   │    │  Domain Controller│    │   SIEM/Monitor  │
│   (Kali Linux)  │    │   (Windows 2019)  │    │   (Ubuntu+ELK)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
    ┌─────────────────┬──────────┼──────────┬─────────────────┐
    │                 │          │          │                 │
┌─────────────┐ ┌─────────────┐ │ ┌─────────────┐ ┌─────────────┐
│Vulnerable   │ │Vulnerable   │ │ │Web Server   │ │Database     │
│Windows 10   │ │Ubuntu 20.04 │ │ │(DVWA)       │ │Server       │
└─────────────┘ └─────────────┘   └─────────────┘ └─────────────┘
```

## 🚀 Quick Start

1. **Prerequisites**
   - VirtualBox 6.1+ installed
   - At least 16GB RAM (32GB recommended)
   - 200GB+ free disk space
   - Host OS: Windows, macOS, or Linux

2. **Setup**
   ```bash
   # Clone this repository
   git clone <repository-url>
   cd virtualbox-soc-labs
   
   # Run the automated setup script
   chmod +x scripts/setup-lab.sh
   ./scripts/setup-lab.sh
   ```

3. **Start the Lab**
   ```bash
   # Start all VMs in the correct order
   ./scripts/start-lab.sh
   ```

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

## 🛠️ Tools Included

### SIEM & Monitoring
- **Elasticsearch, Logstash, Kibana (ELK Stack)**
- **Splunk Free**
- **OSSEC HIDS**
- **Suricata IDS**
- **Wazuh**

### Network Analysis
- **Wireshark**
- **tcpdump**
- **NetworkMiner**
- **Security Onion**

### Forensics
- **Volatility**
- **Autopsy**
- **YARA**
- **ClamAV**

### Vulnerability Assessment
- **Nessus**
- **OpenVAS**
- **Nikto**
- **OWASP ZAP**

## 📖 Documentation

- [VM Setup Guide](documentation/vm-setup.md)
- [Network Configuration](documentation/network-config.md)
- [Attack Scenarios](documentation/attack-scenarios.md)
- [Lab Exercises](documentation/lab-exercises.md)
- [Troubleshooting](documentation/troubleshooting.md)

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
