# SOC Lab Network Configuration

## 🔴 Network Architecture Overview

This SOC lab uses a fully isolated NAT network in VirtualBox to simulate a realistic corporate environment with vulnerable systems and a centralized SIEM for log collection.

## Network Topology

```
┌─────────────────────────────────────────────────────────────────────┐
│                    VirtualBox NAT Network                            │
│                  Network: 192.168.1.0/24                            │
│                  Gateway: 192.168.1.1                               │
└─────────────────────────────────────────────────────────────────────┘
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
                               │ Logs Flow to SIEM
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

## IP Address Allocation

| System | Hostname | IP Address | Role | OS | Services |
|--------|----------|------------|------|----|---------| 
| Domain Controller | SOC-DC1 | 192.168.1.10 | AD Domain Controller | Windows Server 2019 | AD DS, DNS, DHCP, SMB |
| SIEM Server | SIEM-ELK | 192.168.1.20 | Security Monitoring | Ubuntu Server 22.04 | ELK Stack, Wazuh, Suricata |
| Windows Endpoint | WIN10-VULN | 192.168.1.30 | Vulnerable Endpoint | Windows 10 Pro | RDP, SMB, WinRM, Winlogbeat |
| Linux Server | UBUNTU-VULN | 192.168.1.40 | Vulnerable Server | Ubuntu Server 20.04 | SSH, HTTP, FTP, MySQL, Filebeat |
| Attacker | KALI-ATTACKER | 192.168.1.50 | Attack Platform | Kali Linux 2023.4 | Pentesting Tools |

## VirtualBox NAT Network Setup

### Step 1: Create NAT Network

You can create the NAT network via GUI or command line:

#### Via VirtualBox GUI:
1. Open VirtualBox Manager
2. Go to **File** → **Preferences** → **Network**
3. Click the **NAT Networks** tab
4. Click the **+** icon to add a new NAT network
5. Configure:
   - **Name**: `SOC-Lab-Network`
   - **IPv4 Prefix**: `192.168.1.0/24`
   - **Enable DHCP**: ❌ (Unchecked - we use static IPs)
   - **Supports IPv6**: ❌ (Unchecked)
   - **Port Forwarding**: (Configure below if needed)

#### Via VBoxManage Command:
```bash
# Create NAT network
VBoxManage natnetwork add \
  --netname "SOC-Lab-Network" \
  --network "192.168.1.0/24" \
  --enable \
  --dhcp off

# Verify creation
VBoxManage list natnetworks
```

### Step 2: Configure Network Isolation

The NAT network provides complete isolation from your host network and the internet by default. This is critical for lab security.

```bash
# Verify network configuration
VBoxManage natnetwork list

# Expected output:
# NAT Network Name: SOC-Lab-Network
# Network: 192.168.1.0/24
# Gateway: 192.168.1.1/24
# DHCP: Disabled
# IPv6: No
# Enabled: Yes
```

### Step 3: Optional Port Forwarding (Host Access)

If you need to access lab services from your host machine:

```bash
# Forward Kibana (SIEM Web Interface)
VBoxManage natnetwork modify \
  --netname "SOC-Lab-Network" \
  --port-forward-4 "kibana:tcp:[]:5601:[192.168.1.20]:5601"

# Forward SSH to SIEM (for management)
VBoxManage natnetwork modify \
  --netname "SOC-Lab-Network" \
  --port-forward-4 "siem-ssh:tcp:[]:2222:[192.168.1.20]:22"

# Forward RDP to Windows 10 (for testing)
VBoxManage natnetwork modify \
  --netname "SOC-Lab-Network" \
  --port-forward-4 "win10-rdp:tcp:[]:3389:[192.168.1.30]:3389"

# Access from host:
# Kibana: http://localhost:5601
# SIEM SSH: ssh -p 2222 user@localhost
# Win10 RDP: rdesktop localhost:3389
```

## Network Services

### DNS Configuration (SOC-DC1)

The Domain Controller provides DNS services:

| Service | Details |
|---------|---------|
| Primary DNS | 192.168.1.10 (SOC-DC1) |
| Secondary DNS | 8.8.8.8 (Google DNS - for external resolution) |
| Domain | soclab.local |

### DHCP Configuration (Disabled)

DHCP is disabled; all systems use static IP configuration for consistency and security monitoring.

## Log Flow Architecture

### Centralized Logging to SIEM-ELK (192.168.1.20)

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Log Collection Flow                            │
└─────────────────────────────────────────────────────────────────────┘

Windows Systems (SOC-DC1, WIN10-VULN)
  │
  │ Winlogbeat (Port 5044)
  ├────────────────────────────────────┐
  │                                    │
  ▼                                    ▼
Linux Systems (UBUNTU-VULN)      Logstash (192.168.1.20:5044)
  │                                    │
  │ Filebeat (Port 5044)               │ Parse & Transform
  │ Rsyslog (Port 514)                 │
  └────────────────────────────────────┤
                                       │
                                       ▼
                              Elasticsearch (Port 9200)
                                       │
                                       │ Index & Store
                                       │
                                       ▼
                                 Kibana (Port 5601)
                                       │
                                       │ Visualize & Alert
                                       │
                                       ▼
                                SOC Analyst Dashboard
```

### Log Collection Ports

| Port | Protocol | Service | Purpose |
|------|----------|---------|---------|
| 514 | TCP/UDP | Rsyslog | Traditional syslog forwarding |
| 5044 | TCP | Logstash Beats | Filebeat & Winlogbeat input |
| 5601 | TCP | Kibana | Web UI for SIEM dashboard |
| 9200 | TCP | Elasticsearch | Log storage and search API |
| 1514 | TCP | Wazuh | HIDS agent communication |

## Firewall Configuration

### SIEM Server (192.168.1.20) Firewall Rules

```bash
# Allow log collection
sudo ufw allow 514/tcp    # Rsyslog
sudo ufw allow 514/udp    # Rsyslog UDP
sudo ufw allow 5044/tcp   # Logstash Beats
sudo ufw allow 1514/tcp   # Wazuh agents

# Allow SIEM access
sudo ufw allow 5601/tcp   # Kibana web UI
sudo ufw allow 9200/tcp   # Elasticsearch API (restrict in production)

# SSH management
sudo ufw allow 22/tcp

# Enable firewall
sudo ufw enable
```

### Windows 10 (192.168.1.30) Firewall Rules

```powershell
# Allow vulnerable services
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
New-NetFirewallRule -DisplayName "Allow SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
New-NetFirewallRule -DisplayName "Allow WinRM" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow

# Allow Winlogbeat to SIEM
New-NetFirewallRule -DisplayName "Winlogbeat to SIEM" -Direction Outbound -Protocol TCP -RemoteAddress 192.168.1.20 -RemotePort 5044 -Action Allow
```

### Ubuntu Vulnerable Server (192.168.1.40) Firewall Rules

```bash
# Allow vulnerable services
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 21/tcp    # FTP
sudo ufw allow 3306/tcp  # MySQL

# Allow log forwarding to SIEM
sudo ufw allow out to 192.168.1.20 port 514
sudo ufw allow out to 192.168.1.20 port 5044

sudo ufw enable
```

## Network Testing and Validation

### Connectivity Test Script

Create this script on any VM to test network connectivity:

```bash
#!/bin/bash

echo "=== SOC Lab Network Connectivity Test ==="
echo ""

# Test reachability
echo "Testing connectivity to all systems:"
for ip in 192.168.1.10 192.168.1.20 192.168.1.30 192.168.1.40 192.168.1.50; do
    if ping -c 1 -W 1 $ip > /dev/null 2>&1; then
        echo "✓ $ip - Reachable"
    else
        echo "✗ $ip - NOT reachable"
    fi
done

echo ""
echo "Testing SIEM ports:"

# Test SIEM services
nc -zv 192.168.1.20 514 2>&1 | grep -q succeeded && echo "✓ Rsyslog (514) - Open" || echo "✗ Rsyslog (514) - Closed"
nc -zv 192.168.1.20 5044 2>&1 | grep -q succeeded && echo "✓ Logstash (5044) - Open" || echo "✗ Logstash (5044) - Closed"
nc -zv 192.168.1.20 5601 2>&1 | grep -q succeeded && echo "✓ Kibana (5601) - Open" || echo "✗ Kibana (5601) - Closed"
nc -zv 192.168.1.20 9200 2>&1 | grep -q succeeded && echo "✓ Elasticsearch (9200) - Open" || echo "✗ Elasticsearch (9200) - Closed"

echo ""
echo "DNS Resolution Test:"
nslookup soclab.local 192.168.1.10 > /dev/null 2>&1 && echo "✓ DNS - Working" || echo "✗ DNS - Failed"
```

### Verify Log Collection

On SIEM server (192.168.1.20):

```bash
# Check Elasticsearch indices
curl -X GET "localhost:9200/_cat/indices?v"

# Should show indices like: soc-lab-YYYY.MM.DD

# Check recent logs
curl -X GET "localhost:9200/soc-lab-*/_search?size=5&pretty"

# Check Logstash is listening
sudo netstat -tlnp | grep 5044

# Check logs from specific host
curl -X GET "localhost:9200/soc-lab-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {"host.name": "WIN10-VULN"}
  },
  "size": 5
}
'
```

## Network Performance Tuning

### For SIEM Server (High Log Volume)

```bash
# Increase network buffer sizes
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 67108864"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 67108864"

# Make permanent
sudo tee -a /etc/sysctl.conf > /dev/null <<EOF
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
EOF

sudo sysctl -p
```

## Network Security Best Practices

### 1. Verify Complete Isolation

```bash
# From any lab VM, test isolation
ping -c 3 8.8.8.8  # Should fail or timeout
curl -I https://google.com --max-time 5  # Should timeout

# If these succeed, your lab has internet access (not ideal)
```

### 2. Network Segmentation (Advanced)

For advanced scenarios, you can create multiple NAT networks:

```bash
# Create DMZ network
VBoxManage natnetwork add \
  --netname "SOC-Lab-DMZ" \
  --network "192.168.2.0/24" \
  --enable \
  --dhcp off

# Create Management network  
VBoxManage natnetwork add \
  --netname "SOC-Lab-Mgmt" \
  --network "192.168.3.0/24" \
  --enable \
  --dhcp off
```

## Troubleshooting Network Issues

### Issue 1: VMs Can't Communicate

```bash
# Check NAT network exists
VBoxManage list natnetworks

# Verify VM is attached to correct network
VBoxManage showvminfo "VM-NAME" | grep -i "NIC 1"

# Should show: NIC 1: MAC: ..., Attachment: NAT Network 'SOC-Lab-Network'
```

### Issue 2: No Internet Access (Expected)

This is expected and desired for security. If you need to update systems:

**Option 1: Temporarily attach to NAT**
```bash
# Change to regular NAT (gives internet)
VBoxManage modifyvm "SIEM-ELK" --nic1 nat

# After updates, revert
VBoxManage modifyvm "SIEM-ELK" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
```

**Option 2: Create a proxy VM** (Advanced)

### Issue 3: Logs Not Reaching SIEM

```bash
# On source system, check connectivity
nc -zv 192.168.1.20 5044
telnet 192.168.1.20 5044

# Check firewall
sudo ufw status

# On SIEM, check listening ports
sudo netstat -tlnp | grep -E "(514|5044|5601|9200)"

# Check Logstash logs
sudo tail -f /var/log/logstash/logstash-plain.log
```

## Network Monitoring

### Capture Traffic for Analysis

```bash
# On SIEM server, capture all traffic
sudo tcpdump -i enp0s3 -w /tmp/soc-lab-traffic.pcap

# Capture only log traffic
sudo tcpdump -i enp0s3 'port 514 or port 5044' -w /tmp/log-traffic.pcap

# View in real-time
sudo tcpdump -i enp0s3 -n 'port 5044'
```

### Monitor Suricata IDS on SIEM

```bash
# View Suricata alerts
sudo tail -f /var/log/suricata/fast.log

# View JSON events
sudo tail -f /var/log/suricata/eve.json | jq
```

## Network Diagram Export

For documentation, you can export the network topology:

```bash
# Create topology visualization
cat > /tmp/soc-lab-topology.dot << 'EOF'
digraph SOC_Lab {
    rankdir=TB;
    
    Gateway [label="Gateway\n192.168.1.1", shape=diamond];
    DC [label="SOC-DC1\n192.168.1.10\nWindows Server 2019", shape=box];
    SIEM [label="SIEM-ELK\n192.168.1.20\nUbuntu 22.04", shape=box, color=red];
    Win10 [label="WIN10-VULN\n192.168.1.30\nWindows 10", shape=box];
    Ubuntu [label="UBUNTU-VULN\n192.168.1.40\nUbuntu 20.04", shape=box];
    Kali [label="KALI-ATTACKER\n192.168.1.50\nKali Linux", shape=box, color=orange];
    
    Gateway -> DC;
    Gateway -> SIEM;
    Gateway -> Win10;
    Gateway -> Ubuntu;
    Gateway -> Kali;
    
    Win10 -> SIEM [label="Winlogbeat:5044", color=blue];
    Ubuntu -> SIEM [label="Filebeat:5044", color=blue];
    DC -> SIEM [label="Winlogbeat:5044", color=blue];
    
    Kali -> Win10 [label="Attacks", color=red, style=dashed];
    Kali -> Ubuntu [label="Attacks", color=red, style=dashed];
}
EOF

# Convert to PNG (requires graphviz)
dot -Tpng /tmp/soc-lab-topology.dot -o ~/soc-lab-network.png
```

## Quick Reference

### Network Information
- **Network CIDR**: 192.168.1.0/24
- **Gateway**: 192.168.1.1
- **DNS Server**: 192.168.1.10 (SOC-DC1)
- **SIEM Dashboard**: http://192.168.1.20:5601

### Critical Ports
- **5044**: Logstash Beats input (ALL LOGS)
- **5601**: Kibana web interface
- **514**: Rsyslog
- **9200**: Elasticsearch

### DNS Entries (Configure on SOC-DC1)
```
192.168.1.10    soc-dc1.soclab.local    soc-dc1
192.168.1.20    siem-elk.soclab.local   siem-elk
192.168.1.30    win10-vuln.soclab.local win10-vuln
192.168.1.40    ubuntu-vuln.soclab.local ubuntu-vuln
192.168.1.50    kali-attacker.soclab.local kali-attacker
```

## Next Steps

After configuring the network:

1. ✅ Verify all VMs can communicate
2. ✅ Test DNS resolution
3. ✅ Confirm network isolation from internet
4. ✅ Verify SIEM is receiving logs from all sources
5. ✅ Access Kibana dashboard
6. ✅ Begin attack scenarios

## References

- [VirtualBox Network Settings](https://www.virtualbox.org/manual/ch06.html)
- [VirtualBox NAT Networking](https://www.virtualbox.org/manual/ch06.html#network_nat_service)
- [Elastic Stack Networking](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html)
