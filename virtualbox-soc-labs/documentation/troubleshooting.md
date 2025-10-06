# Troubleshooting Guide

This guide provides solutions to common issues encountered when setting up and running the SOC Lab environment.

## Table of Contents
- [Installation Issues](#installation-issues)
- [VM Creation Problems](#vm-creation-problems)
- [Network Connectivity Issues](#network-connectivity-issues)
- [Performance Problems](#performance-problems)
- [Service Issues](#service-issues)
- [Log Collection Problems](#log-collection-problems)
- [Application-Specific Issues](#application-specific-issues)
- [General Troubleshooting Steps](#general-troubleshooting-steps)

---

## Installation Issues

### VirtualBox Installation Problems

#### Issue: VirtualBox won't install or start
**Symptoms:**
- Installation fails with permission errors
- VirtualBox service won't start
- "VT-x is not available" error

**Solutions:**
1. **Enable virtualization in BIOS/UEFI**
   ```bash
   # Check if virtualization is enabled (Linux)
   grep -E "(vmx|svm)" /proc/cpuinfo
   
   # Check on Windows
   systeminfo | findstr /i "Hyper-V"
   ```

2. **Disable Hyper-V on Windows**
   ```powershell
   # Run as Administrator
   Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
   bcdedit /set hypervisorlaunchtype off
   # Reboot required
   ```

3. **Install VirtualBox with proper permissions**
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install virtualbox virtualbox-ext-pack
   
   # Add user to vboxusers group
   sudo usermod -aG vboxusers $USER
   ```

#### Issue: Extension pack installation fails
**Symptoms:**
- USB 3.0 support not available
- RDP access not working
- PXE boot not available

**Solutions:**
1. **Download and install extension pack**
   ```bash
   # Download extension pack
   wget https://download.virtualbox.org/virtualbox/7.0.12/Oracle_VM_VirtualBox_Extension_Pack-7.0.12.vbox-extpack
   
   # Install extension pack
   sudo VBoxManage extpack install Oracle_VM_VirtualBox_Extension_Pack-7.0.12.vbox-extpack
   ```

2. **Accept license agreement**
   ```bash
   # If installation fails due to license
   VBoxManage extpack install --accept-license=<license-hash> <extpack-file>
   ```

---

## VM Creation Problems

### Insufficient Resources

#### Issue: VM creation fails due to insufficient RAM/disk space
**Symptoms:**
- "Not enough memory" error
- VM won't start
- Disk creation fails

**Solutions:**
1. **Check available resources**
   ```bash
   # Check available RAM
   free -h
   
   # Check disk space
   df -h
   
   # Check CPU cores
   nproc
   ```

2. **Adjust VM resource allocation**
   ```bash
   # Reduce RAM allocation
   VBoxManage modifyvm "VM-Name" --memory 2048
   
   # Reduce CPU allocation
   VBoxManage modifyvm "VM-Name" --cpus 2
   ```

3. **Free up system resources**
   ```bash
   # Stop unnecessary services
   sudo systemctl stop unnecessary-service
   
   # Clear temporary files
   sudo apt clean
   rm -rf /tmp/*
   ```

### ISO File Issues

#### Issue: ISO files not found or corrupted
**Symptoms:**
- "Medium not found" error
- VM boots to black screen
- Installation fails

**Solutions:**
1. **Verify ISO file integrity**
   ```bash
   # Check file exists and size
   ls -lh /path/to/iso/file.iso
   
   # Verify checksum (if available)
   sha256sum file.iso
   ```

2. **Re-download corrupted ISOs**
   ```bash
   # Remove corrupted file
   rm corrupted-file.iso
   
   # Download fresh copy
   wget https://official-source/file.iso
   ```

3. **Check file permissions**
   ```bash
   # Ensure VirtualBox can read the ISO
   chmod 644 /path/to/iso/file.iso
   ```

---

## Network Connectivity Issues

### NAT Network Problems

#### Issue: VMs can't communicate with each other
**Symptoms:**
- Ping between VMs fails
- Services not accessible
- Network isolation not working

**Solutions:**
1. **Verify NAT network configuration**
   ```bash
   # List NAT networks
   VBoxManage list natnetworks
   
   # Check network details
   VBoxManage natnetwork modify --netname "SOC-Lab-Network" --dhcp off
   ```

2. **Check VM network settings**
   ```bash
   # Verify VM is using correct network
   VBoxManage showvminfo "VM-Name" | grep NIC
   
   # Modify if necessary
   VBoxManage modifyvm "VM-Name" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
   ```

3. **Restart network services**
   ```bash
   # On Ubuntu VMs
   sudo systemctl restart networking
   sudo netplan apply
   
   # On Windows VMs
   ipconfig /release
   ipconfig /renew
   ```

#### Issue: Port forwarding not working
**Symptoms:**
- Can't access services from host
- SSH/HTTP connections fail
- Kibana not accessible

**Solutions:**
1. **Check port forwarding rules**
   ```bash
   # List current rules
   VBoxManage natnetwork modify --netname "SOC-Lab-Network" --port-forward-4 list
   
   # Add missing rules
   VBoxManage natnetwork modify --netname "SOC-Lab-Network" --port-forward-4 "kibana:tcp:[]:5601:[10.0.2.100]:5601"
   ```

2. **Verify service is listening**
   ```bash
   # On target VM
   netstat -tlnp | grep 5601
   ss -tlnp | grep 5601
   ```

3. **Check firewall settings**
   ```bash
   # Ubuntu
   sudo ufw status
   sudo ufw allow 5601
   
   # Windows
   netsh advfirewall firewall show rule name="Kibana"
   ```

### Static IP Configuration Issues

#### Issue: Static IP not working
**Symptoms:**
- VM gets wrong IP address
- Network services unreachable
- DHCP conflicts

**Solutions:**
1. **Check netplan configuration (Ubuntu)**
   ```bash
   # Verify configuration
   sudo netplan --debug try
   
   # Apply configuration
   sudo netplan apply
   
   # Check interface status
   ip addr show
   ```

2. **Verify network interface name**
   ```bash
   # List network interfaces
   ip link show
   
   # Update netplan with correct interface name
   sudo nano /etc/netplan/01-netcfg.yaml
   ```

3. **Windows static IP issues**
   ```powershell
   # Check current configuration
   Get-NetIPAddress
   
   # Remove old configuration
   Remove-NetIPAddress -IPAddress "10.0.2.102" -Confirm:$false
   
   # Set new configuration
   New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "10.0.2.102" -PrefixLength 24 -DefaultGateway "10.0.2.1"
   ```

---

## Performance Problems

### Slow VM Performance

#### Issue: VMs running slowly
**Symptoms:**
- High CPU usage on host
- VMs unresponsive
- Long boot times

**Solutions:**
1. **Optimize VM settings**
   ```bash
   # Enable hardware acceleration
   VBoxManage modifyvm "VM-Name" --hwvirtex on
   VBoxManage modifyvm "VM-Name" --nestedpaging on
   VBoxManage modifyvm "VM-Name" --largepages on
   
   # Adjust video memory
   VBoxManage modifyvm "VM-Name" --vram 128
   
   # Enable 3D acceleration (if supported)
   VBoxManage modifyvm "VM-Name" --accelerate3d on
   ```

2. **Adjust resource allocation**
   ```bash
   # Don't allocate more than 75% of host RAM
   # For 16GB host, max 12GB total for all VMs
   VBoxManage modifyvm "ELK-SIEM" --memory 6144
   VBoxManage modifyvm "Windows10-Vulnerable" --memory 3072
   ```

3. **Host system optimization**
   ```bash
   # Close unnecessary applications
   # Disable Windows Defender real-time scanning for VM directory
   # Use SSD storage for VMs if possible
   ```

### Disk Performance Issues

#### Issue: Slow disk I/O
**Symptoms:**
- Long file operations
- Database queries slow
- Log processing delayed

**Solutions:**
1. **Use SSD storage**
   ```bash
   # Move VMs to SSD
   VBoxManage clonemedium disk "old-location.vdi" "new-ssd-location.vdi"
   ```

2. **Enable SSD optimization**
   ```bash
   # Mark disk as SSD
   VBoxManage storageattach "VM-Name" --storagectl "SATA Controller" --port 0 --device 0 --nonrotational on
   ```

3. **Adjust disk cache settings**
   ```bash
   # Enable host I/O cache
   VBoxManage storageattach "VM-Name" --storagectl "SATA Controller" --port 0 --device 0 --cache writeback
   ```

---

## Service Issues

### ELK Stack Problems

#### Issue: Elasticsearch won't start
**Symptoms:**
- Elasticsearch service fails
- "Out of memory" errors
- Port 9200 not responding

**Solutions:**
1. **Check Java heap size**
   ```bash
   # Edit JVM options
   sudo nano /etc/elasticsearch/jvm.options
   
   # Adjust heap size (max 50% of available RAM)
   -Xms2g
   -Xmx2g
   ```

2. **Check disk space**
   ```bash
   # Elasticsearch requires disk space
   df -h /var/lib/elasticsearch
   
   # Clean old indices if needed
   curl -X DELETE "localhost:9200/old-index-*"
   ```

3. **Check file permissions**
   ```bash
   # Fix ownership
   sudo chown -R elasticsearch:elasticsearch /var/lib/elasticsearch
   sudo chown -R elasticsearch:elasticsearch /var/log/elasticsearch
   ```

#### Issue: Kibana not accessible
**Symptoms:**
- Kibana web interface not loading
- Connection refused errors
- Blank page

**Solutions:**
1. **Check Kibana service**
   ```bash
   # Check service status
   sudo systemctl status kibana
   
   # Check logs
   sudo journalctl -u kibana -f
   ```

2. **Verify Elasticsearch connectivity**
   ```bash
   # Test from Kibana server
   curl http://localhost:9200
   
   # Check Kibana configuration
   sudo nano /etc/kibana/kibana.yml
   ```

3. **Check network binding**
   ```bash
   # Ensure Kibana binds to all interfaces
   server.host: "0.0.0.0"
   ```

### Web Application Issues

#### Issue: DVWA not working
**Symptoms:**
- Database connection errors
- Setup page not accessible
- PHP errors

**Solutions:**
1. **Check Apache service**
   ```bash
   # Restart Apache
   sudo systemctl restart apache2
   
   # Check error logs
   sudo tail -f /var/log/apache2/error.log
   ```

2. **Fix database connection**
   ```bash
   # Check MySQL service
   sudo systemctl status mysql
   
   # Reset MySQL password
   sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';"
   ```

3. **Fix file permissions**
   ```bash
   # Set correct permissions
   sudo chown -R www-data:www-data /var/www/html/dvwa
   sudo chmod -R 755 /var/www/html/dvwa
   sudo chmod -R 777 /var/www/html/dvwa/hackable/uploads/
   ```

---

## Log Collection Problems

### Rsyslog Issues

#### Issue: Logs not being forwarded
**Symptoms:**
- No logs in SIEM
- Empty log files
- Network connectivity but no data

**Solutions:**
1. **Check rsyslog configuration**
   ```bash
   # Test configuration
   sudo rsyslogd -N1
   
   # Check forwarding rules
   sudo nano /etc/rsyslog.conf
   
   # Ensure forwarding is enabled
   *.* @@10.0.2.100:514
   ```

2. **Restart rsyslog service**
   ```bash
   sudo systemctl restart rsyslog
   sudo systemctl status rsyslog
   ```

3. **Check network connectivity**
   ```bash
   # Test UDP connection
   nc -u 10.0.2.100 514
   
   # Check firewall
   sudo ufw allow out 514
   ```

### Winlogbeat Issues

#### Issue: Windows logs not appearing in ELK
**Symptoms:**
- No Windows event logs in Kibana
- Winlogbeat service not running
- Connection errors

**Solutions:**
1. **Check Winlogbeat service**
   ```powershell
   # Check service status
   Get-Service winlogbeat
   
   # Start service
   Start-Service winlogbeat
   
   # Check logs
   Get-EventLog -LogName Application -Source winlogbeat
   ```

2. **Verify configuration**
   ```yaml
   # Check winlogbeat.yml
   output.logstash:
     hosts: ["10.0.2.100:5044"]
   
   winlogbeat.event_logs:
     - name: Security
     - name: System
     - name: Application
   ```

3. **Test connectivity**
   ```powershell
   # Test connection to Logstash
   Test-NetConnection -ComputerName 10.0.2.100 -Port 5044
   ```

---

## Application-Specific Issues

### Kali Linux Problems

#### Issue: Tools not working properly
**Symptoms:**
- Command not found errors
- Database not initialized
- Outdated tool versions

**Solutions:**
1. **Update package database**
   ```bash
   sudo apt update && sudo apt upgrade
   
   # Update locate database
   sudo updatedb
   ```

2. **Initialize tool databases**
   ```bash
   # Initialize Metasploit database
   sudo msfdb init
   
   # Update Nmap scripts
   sudo nmap --script-updatedb
   
   # Update searchsploit
   sudo searchsploit -u
   ```

3. **Install missing tools**
   ```bash
   # Install common tools
   sudo apt install gobuster nikto sqlmap
   
   # Install from source if needed
   git clone https://github.com/tool/repo.git
   cd repo && sudo python setup.py install
   ```

### Windows Domain Issues

#### Issue: Domain controller not working
**Symptoms:**
- Domain join fails
- DNS resolution problems
- Authentication errors

**Solutions:**
1. **Check DNS configuration**
   ```powershell
   # Verify DNS settings
   Get-DnsClientServerAddress
   
   # Test DNS resolution
   nslookup soclab.local
   
   # Flush DNS cache
   ipconfig /flushdns
   ```

2. **Verify Active Directory services**
   ```powershell
   # Check AD services
   Get-Service ADWS,DNS,Netlogon,NTDS
   
   # Restart if needed
   Restart-Service ADWS,DNS,Netlogon
   ```

3. **Check time synchronization**
   ```powershell
   # Time sync is critical for AD
   w32tm /query /status
   w32tm /resync
   ```

---

## General Troubleshooting Steps

### Systematic Approach

1. **Identify the Problem**
   - What exactly is not working?
   - When did it stop working?
   - What changed recently?

2. **Gather Information**
   ```bash
   # Check system resources
   top
   df -h
   free -h
   
   # Check network connectivity
   ping 8.8.8.8
   netstat -tlnp
   
   # Check logs
   sudo journalctl -xe
   dmesg | tail
   ```

3. **Test Connectivity**
   ```bash
   # Test network connectivity between VMs
   ping 10.0.2.100
   telnet 10.0.2.100 5601
   nc -zv 10.0.2.100 9200
   ```

4. **Check Service Status**
   ```bash
   # Linux services
   sudo systemctl status service-name
   sudo journalctl -u service-name -f
   
   # Windows services
   Get-Service service-name
   Get-EventLog -LogName System -Newest 50
   ```

### Useful Diagnostic Commands

#### Linux Diagnostics
```bash
# System information
uname -a
lsb_release -a
cat /proc/meminfo
cat /proc/cpuinfo

# Network diagnostics
ip addr show
ip route show
ss -tlnp
netstat -rn

# Process diagnostics
ps aux
pstree
lsof -i
```

#### Windows Diagnostics
```powershell
# System information
Get-ComputerInfo
Get-WmiObject -Class Win32_OperatingSystem
Get-WmiObject -Class Win32_ComputerSystem

# Network diagnostics
Get-NetAdapter
Get-NetIPAddress
Get-NetRoute
netstat -an

# Process diagnostics
Get-Process
Get-Service
netstat -b
```

### Log File Locations

#### Linux Log Files
```bash
# System logs
/var/log/syslog
/var/log/auth.log
/var/log/kern.log

# Service-specific logs
/var/log/apache2/
/var/log/mysql/
/var/log/elasticsearch/
/var/log/kibana/
```

#### Windows Log Files
```powershell
# Event logs (use Event Viewer or PowerShell)
Get-WinEvent -LogName System
Get-WinEvent -LogName Security
Get-WinEvent -LogName Application

# Service-specific logs
C:\Windows\Logs\
C:\ProgramData\
```

### Getting Help

#### Online Resources
- VirtualBox documentation: https://www.virtualbox.org/wiki/Documentation
- Elastic Stack documentation: https://www.elastic.co/guide/
- Kali Linux documentation: https://www.kali.org/docs/
- Ubuntu documentation: https://help.ubuntu.com/

#### Community Support
- VirtualBox forums
- Elastic Stack community forums
- Reddit communities (r/sysadmin, r/cybersecurity)
- Stack Overflow

#### Log Analysis
When seeking help, always include:
- Exact error messages
- Relevant log entries
- System specifications
- Steps to reproduce the issue
- What troubleshooting steps you've already tried

Remember: Most issues can be resolved by carefully reading error messages, checking logs, and following systematic troubleshooting procedures.