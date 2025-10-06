# Network Topology and Configuration

## Network Overview

The SOC Lab environment uses a NAT Network configuration in VirtualBox to create an isolated network segment that simulates a corporate environment. This setup allows for realistic attack scenarios while maintaining complete isolation from production networks.

## Network Architecture

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                VirtualBox Host                          │
                    │                                                         │
                    │  ┌─────────────────────────────────────────────────┐   │
                    │  │            NAT Network                          │   │
                    │  │         SOC-Lab-Network                         │   │
                    │  │        10.0.2.0/24                             │   │
                    │  │                                                 │   │
                    │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐     │   │
                    │  │  │   SIEM   │  │ Attacker │  │   DC     │     │   │
                    │  │  │ELK Stack │  │   Kali   │  │ Win2019  │     │   │
                    │  │  │10.0.2.100│  │10.0.2.15 │  │10.0.2.10 │     │   │
                    │  │  └──────────┘  └──────────┘  └──────────┘     │   │
                    │  │                                                 │   │
                    │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐     │   │
                    │  │  │Vulnerable│  │Vulnerable│  │   Web    │     │   │
                    │  │  │ Windows  │  │  Linux   │  │ Server   │     │   │
                    │  │  │10.0.2.102│  │10.0.2.101│  │10.0.2.103│     │   │
                    │  │  └──────────┘  └──────────┘  └──────────┘     │   │
                    │  │                                                 │   │
                    │  │              Gateway: 10.0.2.1                 │   │
                    │  │              DNS: 10.0.2.1                     │   │
                    │  └─────────────────────────────────────────────────┘   │
                    │                                                         │
                    └─────────────────────────────────────────────────────────┘
```

## IP Address Allocation

| System | IP Address | Role | OS | Services |
|--------|------------|------|----|---------| 
| Gateway | 10.0.2.1 | Network Gateway | VirtualBox NAT | DHCP, DNS |
| Domain Controller | 10.0.2.10 | AD Domain Controller | Windows Server 2019 | AD DS, DNS, DHCP |
| Attacker | 10.0.2.15 | Attack Platform | Kali Linux | Penetration Testing Tools |
| SIEM | 10.0.2.100 | Security Monitoring | Ubuntu 20.04 | ELK Stack, Suricata |
| Vulnerable Linux | 10.0.2.101 | Target System | Ubuntu 20.04 | SSH, HTTP, FTP, MySQL |
| Vulnerable Windows | 10.0.2.102 | Target System | Windows 10 Pro | RDP, SMB, WinRM |
| Web Server | 10.0.2.103 | Web Applications | Ubuntu 20.04 | Apache, DVWA, WebGoat |

## VirtualBox Network Configuration

### Create NAT Network
```bash
# Create the NAT network
VBoxManage natnetwork add --netname "SOC-Lab-Network" --network "10.0.2.0/24" --enable

# Configure DHCP (optional - we'll use static IPs)
VBoxManage natnetwork modify --netname "SOC-Lab-Network" --dhcp off

# Enable port forwarding for external access (optional)
VBoxManage natnetwork modify --netname "SOC-Lab-Network" --port-forward-4 "ssh-siem:tcp:[]:2222:[10.0.2.100]:22"
VBoxManage natnetwork modify --netname "SOC-Lab-Network" --port-forward-4 "kibana:tcp:[]:5601:[10.0.2.100]:5601"
VBoxManage natnetwork modify --netname "SOC-Lab-Network" --port-forward-4 "dvwa:tcp:[]:8080:[10.0.2.101]:80"
```

### VM Network Configuration
```bash
# Configure each VM to use the NAT network
VBoxManage modifyvm "ELK-SIEM" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage modifyvm "Kali-Attacker" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage modifyvm "Windows10-Vulnerable" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage modifyvm "Ubuntu-Vulnerable" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage modifyvm "Windows-DC" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage modifyvm "Web-Server" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
```

## Static IP Configuration

### Ubuntu Systems (SIEM, Vulnerable Linux, Web Server)
```yaml
# /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 10.0.2.100/24  # Change IP for each system
      gateway4: 10.0.2.1
      nameservers:
        addresses:
          - 10.0.2.1
          - 8.8.8.8
```

### Windows Systems (Domain Controller, Vulnerable Windows)
```powershell
# PowerShell commands for static IP configuration
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "10.0.2.10" -PrefixLength 24 -DefaultGateway "10.0.2.1"
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "10.0.2.1","8.8.8.8"
```

### Kali Linux (Attacker)
```bash
# /etc/network/interfaces or use NetworkManager
auto eth0
iface eth0 inet static
address 10.0.2.15
netmask 255.255.255.0
gateway 10.0.2.1
dns-nameservers 10.0.2.1 8.8.8.8
```

## Network Services Configuration

### Domain Controller (10.0.2.10)
```powershell
# Install Active Directory Domain Services
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest -DomainName "soclab.local" -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Force

# Configure DNS forwarders
Add-DnsServerForwarder -IPAddress 8.8.8.8
Add-DnsServerForwarder -IPAddress 8.8.4.4

# Create domain users
New-ADUser -Name "John Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@soclab.local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Jane Smith" -SamAccountName "jsmith" -UserPrincipalName "jsmith@soclab.local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true

# Create service accounts
New-ADUser -Name "SQL Service" -SamAccountName "sqlsvc" -UserPrincipalName "sqlsvc@soclab.local" -AccountPassword (ConvertTo-SecureString "SQLService123!" -AsPlainText -Force) -Enabled $true
```

### SIEM System (10.0.2.100)
```bash
# Configure log collection from all systems
# Rsyslog configuration for centralized logging
cat >> /etc/rsyslog.conf << 'EOF'

# Enable UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")

# Enable TCP syslog reception
module(load="imtcp")
input(type="imtcp" port="514")

# Log separation by host
$template DynamicFile,"/var/log/remote-hosts/%HOSTNAME%/%programname%.log"
*.* ?DynamicFile
& stop
EOF

systemctl restart rsyslog

# Configure Suricata for network monitoring
cat > /etc/suricata/suricata.yaml << 'EOF'
vars:
  address-groups:
    HOME_NET: "[10.0.2.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    
af-packet:
  - interface: enp0s3
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - smtp
        - ssh
        - flow
EOF
```

## Network Monitoring Configuration

### Traffic Mirroring Setup
```bash
# Configure network tap for monitoring (if using multiple interfaces)
# This would be done on a physical switch or hypervisor level
# For VirtualBox, we rely on promiscuous mode

# Enable promiscuous mode on SIEM VM
VBoxManage modifyvm "ELK-SIEM" --nicpromisc1 allow-all
```

### Suricata Rules for Lab Environment
```bash
# Custom rules for lab detection
cat > /etc/suricata/rules/soc-lab.rules << 'EOF'
# Internal network scanning
alert icmp $HOME_NET any -> $HOME_NET any (msg:"Internal Network Scan"; itype:8; threshold:type both,track by_src,count 10,seconds 60; sid:1000100; rev:1;)

# Brute force attacks
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force"; flow:to_server,established; content:"SSH"; threshold:type both,track by_src,count 5,seconds 60; sid:1000101; rev:1;)
alert tcp any any -> $HOME_NET 3389 (msg:"RDP Brute Force"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 60; sid:1000102; rev:1;)

# Web application attacks
alert http any any -> $HOME_NET any (msg:"SQL Injection Attempt"; flow:to_server,established; content:"union select"; nocase; sid:1000103; rev:1;)
alert http any any -> $HOME_NET any (msg:"XSS Attempt"; flow:to_server,established; content:"<script"; nocase; sid:1000104; rev:1;)

# Malware communication
alert tcp $HOME_NET any -> any 4444 (msg:"Meterpreter Communication"; flow:to_server,established; content:"|00 00 00|"; depth:3; sid:1000105; rev:1;)

# Data exfiltration
alert http $HOME_NET any -> any any (msg:"Large HTTP POST"; flow:to_server,established; http_method; content:"POST"; dsize:>100000; sid:1000106; rev:1;)
EOF
```

## Firewall Configuration

### Ubuntu Systems (iptables)
```bash
# Basic firewall rules for vulnerable systems
# Allow necessary services but log connections

# SIEM system - allow log collection
iptables -A INPUT -p tcp --dport 514 -j ACCEPT
iptables -A INPUT -p udp --dport 514 -j ACCEPT
iptables -A INPUT -p tcp --dport 5601 -j ACCEPT  # Kibana
iptables -A INPUT -p tcp --dport 9200 -j ACCEPT  # Elasticsearch

# Vulnerable Linux system - allow attack vectors
iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # SSH
iptables -A INPUT -p tcp --dport 80 -j ACCEPT   # HTTP
iptables -A INPUT -p tcp --dport 21 -j ACCEPT   # FTP
iptables -A INPUT -p tcp --dport 23 -j ACCEPT   # Telnet
iptables -A INPUT -p tcp --dport 3306 -j ACCEPT # MySQL

# Log all connections for analysis
iptables -A INPUT -j LOG --log-prefix "IPTABLES-INPUT: "
iptables -A OUTPUT -j LOG --log-prefix "IPTABLES-OUTPUT: "

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Windows Systems (Windows Firewall)
```powershell
# Configure Windows Firewall with logging
# Enable firewall logging
netsh advfirewall set allprofiles logging filename C:\Windows\System32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set allprofiles logging maxfilesize 4096
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable

# Allow specific services for attack scenarios
netsh advfirewall firewall add rule name="Allow RDP" dir=in action=allow protocol=TCP localport=3389
netsh advfirewall firewall add rule name="Allow SMB" dir=in action=allow protocol=TCP localport=445
netsh advfirewall firewall add rule name="Allow WinRM" dir=in action=allow protocol=TCP localport=5985
```

## DNS Configuration

### Domain Controller DNS Setup
```powershell
# Configure DNS zones
Add-DnsServerPrimaryZone -Name "soclab.local" -ZoneFile "soclab.local.dns"
Add-DnsServerPrimaryZone -Name "2.0.10.in-addr.arpa" -ZoneFile "2.0.10.in-addr.arpa.dns"

# Add DNS records for lab systems
Add-DnsServerResourceRecordA -ZoneName "soclab.local" -Name "dc" -IPv4Address "10.0.2.10"
Add-DnsServerResourceRecordA -ZoneName "soclab.local" -Name "siem" -IPv4Address "10.0.2.100"
Add-DnsServerResourceRecordA -ZoneName "soclab.local" -Name "web" -IPv4Address "10.0.2.101"
Add-DnsServerResourceRecordA -ZoneName "soclab.local" -Name "win10" -IPv4Address "10.0.2.102"
Add-DnsServerResourceRecordA -ZoneName "soclab.local" -Name "webserver" -IPv4Address "10.0.2.103"

# Add reverse DNS records
Add-DnsServerResourceRecordPtr -ZoneName "2.0.10.in-addr.arpa" -Name "10" -PtrDomainName "dc.soclab.local"
Add-DnsServerResourceRecordPtr -ZoneName "2.0.10.in-addr.arpa" -Name "100" -PtrDomainName "siem.soclab.local"
Add-DnsServerResourceRecordPtr -ZoneName "2.0.10.in-addr.arpa" -Name "101" -PtrDomainName "web.soclab.local"
Add-DnsServerResourceRecordPtr -ZoneName "2.0.10.in-addr.arpa" -Name "102" -PtrDomainName "win10.soclab.local"
Add-DnsServerResourceRecordPtr -ZoneName "2.0.10.in-addr.arpa" -Name "103" -PtrDomainName "webserver.soclab.local"
```

## Network Testing and Validation

### Connectivity Tests
```bash
# Test script to validate network connectivity
#!/bin/bash

echo "=== SOC Lab Network Connectivity Test ==="

# Test basic connectivity
echo "Testing basic connectivity..."
ping -c 3 10.0.2.1   # Gateway
ping -c 3 10.0.2.10  # Domain Controller
ping -c 3 10.0.2.15  # Attacker
ping -c 3 10.0.2.100 # SIEM
ping -c 3 10.0.2.101 # Vulnerable Linux
ping -c 3 10.0.2.102 # Vulnerable Windows
ping -c 3 10.0.2.103 # Web Server

# Test DNS resolution
echo "Testing DNS resolution..."
nslookup dc.soclab.local 10.0.2.10
nslookup siem.soclab.local 10.0.2.10
nslookup web.soclab.local 10.0.2.10

# Test service connectivity
echo "Testing service connectivity..."
nc -zv 10.0.2.100 5601  # Kibana
nc -zv 10.0.2.101 22    # SSH
nc -zv 10.0.2.101 80    # HTTP
nc -zv 10.0.2.102 3389  # RDP
nc -zv 10.0.2.102 445   # SMB

echo "Network test completed."
```

### Network Performance Baseline
```bash
# Bandwidth testing between systems
iperf3 -s &  # On target system
iperf3 -c 10.0.2.101 -t 30  # From source system

# Latency testing
ping -c 100 10.0.2.101 | tail -1
```

## Security Considerations

### Network Isolation
- **Complete Isolation**: The NAT network is completely isolated from the host network and internet
- **No Production Access**: Lab traffic cannot reach production systems
- **Controlled Internet Access**: Only through VirtualBox NAT gateway if needed

### Monitoring Points
- **Gateway Traffic**: All traffic flows through VirtualBox NAT gateway
- **SIEM Collection**: Centralized log collection from all systems
- **Network Tap**: Suricata monitors all network traffic
- **Host-based Monitoring**: Agents on each system provide detailed telemetry

### Access Control
- **Management Access**: SSH/RDP access to systems for administration
- **Service Access**: Only necessary services exposed on each system
- **Firewall Rules**: Restrictive rules with logging enabled

## Troubleshooting

### Common Network Issues
1. **IP Conflicts**: Ensure each VM has unique static IP
2. **DNS Resolution**: Verify DNS server configuration
3. **Service Connectivity**: Check firewall rules and service status
4. **Performance**: Monitor resource usage and network bandwidth

### Diagnostic Commands
```bash
# Network interface status
ip addr show
ip route show

# DNS resolution
nslookup hostname
dig hostname

# Port connectivity
telnet hostname port
nc -zv hostname port

# Network traffic
tcpdump -i eth0 host 10.0.2.15
netstat -tulpn
```

## Network Documentation

### Network Diagram
- Physical topology diagram
- Logical network flow diagram
- Security zone mapping
- Monitoring point locations

### IP Address Management
- DHCP reservations (if used)
- Static IP assignments
- DNS record mappings
- Service port allocations

### Change Management
- Network configuration changes
- Firewall rule modifications
- DNS record updates
- Monitoring configuration changes