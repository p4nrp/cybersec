# 🚀 Quick Start Guide - SOC Analyst VirtualBox Labs

## Overview

This quick start guide will get your SOC lab up and running with full log collection to SIEM/ELK in approximately **4-6 hours** (depending on your system specs and experience).

## ⏱️ Time Estimate

| Phase | Duration | Description |
|-------|----------|-------------|
| Prerequisites | 30 min | Download ISOs and install VirtualBox |
| Network Setup | 10 min | Create NAT network |
| SIEM-ELK Setup | 90 min | Build log collection server |
| Domain Controller | 60 min | Windows Server + AD |
| Windows 10 Target | 45 min | Vulnerable endpoint |
| Ubuntu Target | 45 min | Vulnerable server |
| Kali Attacker | 30 min | Attack platform |
| Testing & Validation | 30 min | Verify log collection |
| **TOTAL** | **5-6 hours** | Full lab deployment |

## 🎯 What You'll Build

```
┌────────────────────────────────────────────────┐
│          SOC Analyst Practice Lab               │
│                                                  │
│  ┌──────────┐      ┌──────────┐                │
│  │  SIEM-   │◄─────┤ Windows  │                │
│  │   ELK    │◄─────┤  Linux   │                │
│  │192.168   │◄─────┤ Systems  │                │
│  │  .1.20   │      │          │                │
│  └──────────┘      └──────────┘                │
│       ▲                                         │
│       │ ALL LOGS COLLECTED HERE                │
│       │                                         │
│  ┌────▼────┐  ┌──────────┐  ┌──────────┐      │
│  │Attacker │  │Win10     │  │Ubuntu    │      │
│  │  Kali   │─→│Vulnerable│─→│Vulnerable│      │
│  │192.168  │  │192.168   │  │192.168   │      │
│  │  .1.50  │  │  .1.30   │  │  .1.40   │      │
│  └─────────┘  └──────────┘  └──────────┘      │
└────────────────────────────────────────────────┘
```

---

## Step 1: Prerequisites (30 minutes)

### Download Required ISOs

Open these links in your browser and download:

1. **Windows Server 2019** (SOC-DC1)
   - URL: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019
   - Size: ~5.3 GB
   - File: `Windows_Server_2019_Datacenter_EVAL.iso`

2. **Windows 10 Enterprise** (WIN10-VULN)
   - URL: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
   - Size: ~5.1 GB
   - File: `Windows_10_Enterprise_EVAL.iso`

3. **Ubuntu Server 22.04 LTS** (SIEM-ELK)
   - URL: https://ubuntu.com/download/server
   - Size: ~1.4 GB
   - File: `ubuntu-22.04-live-server-amd64.iso`

4. **Ubuntu Server 20.04 LTS** (UBUNTU-VULN)
   - URL: https://releases.ubuntu.com/20.04/
   - Size: ~1.1 GB
   - File: `ubuntu-20.04-server-amd64.iso`

5. **Kali Linux 2023.4** (KALI-ATTACKER)
   - URL: https://www.kali.org/get-kali/#kali-installer-images
   - Size: ~3.7 GB
   - File: `kali-linux-2023.4-installer-amd64.iso`

### Install VirtualBox

- **Windows/Mac**: https://www.virtualbox.org/wiki/Downloads
- **Linux**: 
  ```bash
  sudo apt update
  sudo apt install virtualbox virtualbox-ext-pack
  ```

### System Requirements Check

```bash
# Check available RAM
free -h  # Linux/Mac
# Windows: Task Manager → Performance → Memory

# Check disk space
df -h  # Linux/Mac
# Windows: File Explorer → This PC

# Minimum: 16GB RAM, 250GB free space
# Recommended: 32GB RAM, 500GB free space
```

---

## Step 2: Network Setup (10 minutes)

### Create NAT Network

**Option A: Command Line (Recommended)**
```bash
# Create isolated lab network
VBoxManage natnetwork add \
  --netname "SOC-Lab-Network" \
  --network "192.168.1.0/24" \
  --enable \
  --dhcp off

# Verify
VBoxManage list natnetworks
```

**Option B: GUI**
1. Open VirtualBox Manager
2. **File** → **Preferences** → **Network**
3. Click **NAT Networks** tab
4. Click **+** icon
5. Configure:
   - Name: `SOC-Lab-Network`
   - IPv4 Prefix: `192.168.1.0/24`
   - ☐ Enable DHCP (UNCHECKED)
6. Click **OK**

### (Optional) Port Forwarding for Host Access

```bash
# Forward Kibana to access SIEM dashboard from host
VBoxManage natnetwork modify \
  --netname "SOC-Lab-Network" \
  --port-forward-4 "kibana:tcp:[]:5601:[192.168.1.20]:5601"

# Now access from host: http://localhost:5601
```

---

## Step 3: Build SIEM-ELK Server (90 minutes) 🔴 BUILD FIRST!

### Why Build SIEM First?
The SIEM server collects logs from all other systems, so it must be ready before configuring log forwarding on other VMs.

### Create VM

```bash
VBoxManage createvm --name "SIEM-ELK" --ostype "Ubuntu_64" --register
VBoxManage modifyvm "SIEM-ELK" --memory 8192 --cpus 4 --vram 16
VBoxManage modifyvm "SIEM-ELK" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage createhd --filename "SIEM-ELK.vdi" --size 102400
VBoxManage storagectl "SIEM-ELK" --name "SATA Controller" --add sata --controller IntelAHCI
VBoxManage storageattach "SIEM-ELK" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "SIEM-ELK.vdi"
VBoxManage storageattach "SIEM-ELK" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "ubuntu-22.04-live-server-amd64.iso"
```

### Install Ubuntu Server

1. Start VM
2. Follow installation prompts:
   - **Name**: `socuser`
   - **Server name**: `siem-elk`
   - **Password**: `Password123!`
   - Install OpenSSH server: **YES**
3. Reboot after installation

### Configure Static IP

```bash
sudo tee /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 192.168.1.20/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
EOF

sudo netplan apply
```

### Install ELK Stack

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Java
sudo apt install -y openjdk-11-jdk

# Add Elastic repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Install Elasticsearch, Logstash, Kibana
sudo apt update
sudo apt install -y elasticsearch logstash kibana
```

### Configure Elasticsearch

```bash
sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<EOF
cluster.name: soc-lab-cluster
node.name: elk-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
EOF

# Set JVM heap (4GB for 8GB system)
sudo sed -i 's/-Xms1g/-Xms4g/' /etc/elasticsearch/jvm.options
sudo sed -i 's/-Xmx1g/-Xmx4g/' /etc/elasticsearch/jvm.options

# Start Elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Test (wait 30 seconds for startup)
sleep 30
curl http://localhost:9200
```

### Configure Logstash

```bash
sudo tee /etc/logstash/conf.d/soc-lab.conf > /dev/null <<'EOF'
input {
  beats {
    port => 5044
  }
  syslog {
    port => 514
  }
}

filter {
  # Add log type
  mutate {
    add_field => { "[@metadata][target_index]" => "soc-lab-%{+YYYY.MM.dd}" }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "%{[@metadata][target_index]}"
  }
}
EOF

# Start Logstash
sudo systemctl enable logstash
sudo systemctl start logstash

# Verify listening on port 5044
sudo netstat -tlnp | grep 5044
```

### Configure Kibana

```bash
sudo tee /etc/kibana/kibana.yml > /dev/null <<EOF
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
EOF

# Start Kibana
sudo systemctl enable kibana
sudo systemctl start kibana

# Wait for Kibana to start (2-3 minutes)
sleep 120
```

### Install Suricata IDS

```bash
sudo apt install -y suricata
sudo suricata-update
sudo systemctl enable suricata
sudo systemctl start suricata
```

### ✅ Verification

```bash
# Check all services
sudo systemctl status elasticsearch logstash kibana suricata

# Test Elasticsearch
curl http://localhost:9200

# Test Kibana
curl http://localhost:5601

# Test Logstash
sudo netstat -tlnp | grep 5044
```

**Access Kibana**: http://192.168.1.20:5601 (or http://localhost:5601 if using port forwarding)

---

## Step 4: Build Domain Controller (60 minutes)

**Full Guide**: [`vm-conf/win-server.md`](vm-conf/win-server.md)

### Quick Setup

```bash
VBoxManage createvm --name "SOC-DC1" --ostype "Windows2019_64" --register
VBoxManage modifyvm "SOC-DC1" --memory 4096 --cpus 2 --vram 128
VBoxManage modifyvm "SOC-DC1" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage createhd --filename "SOC-DC1.vdi" --size 61440
VBoxManage storagectl "SOC-DC1" --name "SATA Controller" --add sata --controller IntelAHCI
VBoxManage storageattach "SOC-DC1" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "SOC-DC1.vdi"
VBoxManage storageattach "SOC-DC1" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "Windows_Server_2019_Datacenter_EVAL.iso"
```

### Key Configuration Steps

1. Install Windows Server 2019
2. Set static IP: `192.168.1.10`
3. Set hostname: `SOC-DC1`
4. Install Active Directory Domain Services
5. Promote to Domain Controller (domain: `soclab.local`)
6. **Install Winlogbeat** (forward logs to 192.168.1.20:5044)

---

## Step 5: Build Windows 10 Target (45 minutes)

**Full Guide**: [`vm-conf/win10-vuln.md`](vm-conf/win10-vuln.md)

### Quick Setup

```bash
VBoxManage createvm --name "WIN10-VULN" --ostype "Windows10_64" --register
VBoxManage modifyvm "WIN10-VULN" --memory 4096 --cpus 2 --vram 128
VBoxManage modifyvm "WIN10-VULN" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage createhd --filename "WIN10-VULN.vdi" --size 51200
VBoxManage storagectl "WIN10-VULN" --name "SATA Controller" --add sata --controller IntelAHCI
VBoxManage storageattach "WIN10-VULN" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "WIN10-VULN.vdi"
VBoxManage storageattach "WIN10-VULN" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "Windows_10_Enterprise_EVAL.iso"
```

### Key Configuration Steps

1. Install Windows 10 Pro
2. Set static IP: `192.168.1.30`
3. Enable RDP, SMB, WinRM
4. Disable Windows Defender
5. Create weak user accounts
6. **Install Sysmon**
7. **Install Winlogbeat** ← CRITICAL for log collection

---

## Step 6: Build Ubuntu Target (45 minutes)

**Full Guide**: [`vm-conf/ubuntuserver-vuln.md`](vm-conf/ubuntuserver-vuln.md)

### Quick Setup

```bash
VBoxManage createvm --name "UBUNTU-VULN" --ostype "Ubuntu_64" --register
VBoxManage modifyvm "UBUNTU-VULN" --memory 2048 --cpus 2 --vram 16
VBoxManage modifyvm "UBUNTU-VULN" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage createhd --filename "UBUNTU-VULN.vdi" --size 30720
VBoxManage storagectl "UBUNTU-VULN" --name "SATA Controller" --add sata --controller IntelAHCI
VBoxManage storageattach "UBUNTU-VULN" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "UBUNTU-VULN.vdi"
VBoxManage storageattach "UBUNTU-VULN" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "ubuntu-20.04-server-amd64.iso"
```

### Key Configuration Steps

1. Install Ubuntu Server 20.04
2. Set static IP: `192.168.1.40`
3. Install LAMP stack (Apache, MySQL, PHP)
4. Install DVWA (Damn Vulnerable Web Application)
5. Configure weak SSH/FTP servers
6. **Install Filebeat** ← CRITICAL for log collection
7. **Configure Rsyslog** to forward to SIEM

---

## Step 7: Build Kali Attacker (30 minutes)

**Full Guide**: [`vm-conf/kali.md`](vm-conf/kali.md)

### Quick Setup

```bash
VBoxManage createvm --name "KALI-ATTACKER" --ostype "Debian_64" --register
VBoxManage modifyvm "KALI-ATTACKER" --memory 4096 --cpus 2 --vram 128
VBoxManage modifyvm "KALI-ATTACKER" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage createhd --filename "KALI-ATTACKER.vdi" --size 51200
VBoxManage storagectl "KALI-ATTACKER" --name "SATA Controller" --add sata --controller IntelAHCI
VBoxManage storageattach "KALI-ATTACKER" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "KALI-ATTACKER.vdi"
VBoxManage storageattach "KALI-ATTACKER" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "kali-linux-2023.4-installer-amd64.iso"
```

### Key Configuration Steps

1. Install Kali Linux (XFCE desktop)
2. Set static IP: `192.168.1.50`
3. Update system and tools
4. Install attack scripts from guide

---

## Step 8: Testing & Validation (30 minutes)

### 🔍 Verify Network Connectivity

On any VM:
```bash
ping -c 3 192.168.1.10   # DC
ping -c 3 192.168.1.20   # SIEM
ping -c 3 192.168.1.30   # Win10
ping -c 3 192.168.1.40   # Ubuntu
ping -c 3 192.168.1.50   # Kali
```

### 🔍 Verify Log Collection

**On SIEM (192.168.1.20):**

```bash
# Check Elasticsearch indices
curl http://localhost:9200/_cat/indices?v
# Should show: soc-lab-YYYY.MM.DD

# Check logs from Windows
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

# Check Logstash is receiving data
sudo tail -f /var/log/logstash/logstash-plain.log
```

### 🔍 Verify Kibana Dashboard

1. Open browser: **http://192.168.1.20:5601**
2. Go to **Discover**
3. Create index pattern: `soc-lab-*`
4. Set time field: `@timestamp`
5. You should see logs from all systems!

### 🎯 Generate Test Logs

**From Kali (192.168.1.50):**

```bash
# Test 1: SSH brute force (generates auth logs)
echo "admin" > /tmp/test-pass.txt
echo "password" >> /tmp/test-pass.txt
hydra -l admin -P /tmp/test-pass.txt ssh://192.168.1.40 -t 4

# Test 2: Web attack (generates apache logs)
curl "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1"

# Test 3: Network scan (generates Suricata alerts)
nmap -sS 192.168.1.30 -p 80,443,445,3389
```

**Check in Kibana:**
1. Go to **Discover**
2. Search: `ssh` or `apache` or `suricata`
3. You should see your test attacks!

---

## 🎓 What to Do Next

### 1. Follow Attack Scenarios

Complete guide: [`attack-scenarios.md`](attack-scenarios.md)

**Try these first:**
- Scenario 1: SSH Brute Force
- Scenario 2: SQL Injection
- Scenario 3: RDP Brute Force

### 2. Build Kibana Dashboards

Create visualizations:
- Failed login attempts over time
- Top attack sources
- Web attack patterns
- Network scanning activity

### 3. Practice Incident Response

For each attack:
1. Detect in Kibana
2. Investigate logs
3. Create timeline
4. Block attacker
5. Write incident report

### 4. Create Detection Rules

- Set up alerts for brute force attacks
- Configure thresholds for failed logins
- Create rules for web attacks
- Monitor for privilege escalation

---

## 📋 Quick Reference Card

### System Information

| System | IP | Username | Password | Purpose |
|--------|-----|----------|----------|---------|
| SOC-DC1 | 192.168.1.10 | Administrator | P@ssw0rd123! | Domain Controller |
| SIEM-ELK | 192.168.1.20 | socuser | Password123! | Log collection |
| WIN10-VULN | 192.168.1.30 | socuser / admin | Password123! / admin | Windows target |
| UBUNTU-VULN | 192.168.1.40 | admin | admin | Linux target |
| KALI-ATTACKER | 192.168.1.50 | kali | kali | Attack machine |

### Critical URLs

- **Kibana SIEM Dashboard**: http://192.168.1.20:5601
- **DVWA (Vulnerable Web App)**: http://192.168.1.40/dvwa/
- **Elasticsearch API**: http://192.168.1.20:9200

### Important Commands

```bash
# Check SIEM logs
curl http://192.168.1.20:9200/_cat/indices?v

# View recent logs
curl http://192.168.1.20:9200/soc-lab-*/_search?size=10&pretty

# Check Logstash
sudo systemctl status logstash
sudo netstat -tlnp | grep 5044

# Test connectivity
ping 192.168.1.20
nc -zv 192.168.1.20 5044
```

---

## 🆘 Troubleshooting

### Problem: Logs not appearing in Kibana

**Solution:**
```bash
# On SIEM - Check Logstash
sudo systemctl status logstash
sudo netstat -tlnp | grep 5044

# On Windows - Check Winlogbeat
Get-Service winlogbeat
Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat"

# On Linux - Check Filebeat
sudo systemctl status filebeat
sudo tail -f /var/log/filebeat/filebeat
```

### Problem: Can't access Kibana

**Solution:**
```bash
# On SIEM
sudo systemctl status kibana
curl http://localhost:5601

# Check firewall
sudo ufw status
sudo ufw allow 5601/tcp

# Restart Kibana
sudo systemctl restart kibana
```

### Problem: VMs can't communicate

**Solution:**
```bash
# Check NAT network exists
VBoxManage list natnetworks

# Verify VM is on correct network
VBoxManage showvminfo "VM-NAME" | grep -i "NIC 1"

# Should show: NAT Network 'SOC-Lab-Network'
```

---

## 📚 Full Documentation

- **Main README**: [README.md](README.md)
- **Network Guide**: [net-conf/README.md](net-conf/README.md)
- **Attack Scenarios**: [attack-scenarios.md](attack-scenarios.md)
- **VM Configs**:
  - [SIEM-ELK](vm-conf/siem-elk.md)
  - [Windows Server](vm-conf/win-server.md)
  - [Windows 10](vm-conf/win10-vuln.md)
  - [Ubuntu Server](vm-conf/ubuntuserver-vuln.md)
  - [Kali Linux](vm-conf/kali.md)

---

## ✅ Completion Checklist

- [ ] All VMs created and running
- [ ] Network connectivity verified (all VMs can ping each other)
- [ ] SIEM receiving logs from Windows systems
- [ ] SIEM receiving logs from Linux systems
- [ ] Kibana accessible and showing logs
- [ ] Test attack generated logs successfully
- [ ] Attack scenarios working
- [ ] Incident response procedures understood

**Congratulations! Your SOC Lab is ready! 🎉**

Start with [attack-scenarios.md](attack-scenarios.md) to begin practicing!
