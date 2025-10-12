# Ubuntu Vulnerable Server - UBUNTU-VULN

## VM Specifications
- **OS**: Ubuntu Server 20.04 LTS
- **RAM**: 2GB (minimum), 4GB (recommended)
- **Storage**: 30GB
- **Network**: NAT Network (SOC-Lab-Network)
- **CPU**: 2 cores
- **IP Address**: 192.168.1.40 (static)
- **Hostname**: ubuntu-vuln

## Purpose
This VM serves as a vulnerable Linux server for practicing:
- Linux log analysis
- SSH brute force detection
- Web application attacks (DVWA, vulnerable apps)
- SQL injection detection
- Directory traversal attacks
- File upload vulnerabilities
- Command injection
- Linux privilege escalation

## VirtualBox Configuration

### Create VM via VBoxManage
```bash
# Create VM
VBoxManage createvm --name "UBUNTU-VULN" --ostype "Ubuntu_64" --register

# Configure VM
VBoxManage modifyvm "UBUNTU-VULN" --memory 2048 --cpus 2
VBoxManage modifyvm "UBUNTU-VULN" --vram 16
VBoxManage modifyvm "UBUNTU-VULN" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
VBoxManage modifyvm "UBUNTU-VULN" --audio none

# Create and attach storage
VBoxManage createhd --filename "UBUNTU-VULN.vdi" --size 30720
VBoxManage storagectl "UBUNTU-VULN" --name "SATA Controller" --add sata --controller IntelAHCI
VBoxManage storageattach "UBUNTU-VULN" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "UBUNTU-VULN.vdi"
VBoxManage storageattach "UBUNTU-VULN" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "ubuntu-20.04-server.iso"
```

## Ubuntu Installation

1. Start the VM and install Ubuntu Server 20.04
2. Configuration during installation:
   - **Hostname**: ubuntu-vuln
   - **Username**: socuser
   - **Password**: Password123!
   - **Install OpenSSH server**: Yes

## Post-Installation Configuration

### 1. Initial System Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y curl wget git vim net-tools htop openssh-server

# Set hostname
sudo hostnamectl set-hostname ubuntu-vuln
```

### 2. Configure Static IP

```bash
# Create netplan configuration
sudo tee /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 192.168.1.40/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses:
          - 192.168.1.10
          - 8.8.8.8
EOF

# Apply network configuration
sudo netplan apply

# Verify
ip addr show enp0s3
```

### 3. Install and Configure SSH Server

```bash
# Install SSH server
sudo apt install -y openssh-server

# Backup original SSH config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Configure SSH with weak settings for testing
sudo tee /etc/ssh/sshd_config > /dev/null <<'EOF'
# Weak SSH configuration for testing
Port 22
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Weak settings for lab environment
MaxAuthTries 100
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 120
EOF

# Restart SSH
sudo systemctl restart sshd
sudo systemctl enable sshd
```

### 4. Create Weak User Accounts

```bash
# Create users with weak passwords
sudo useradd -m -s /bin/bash admin
echo "admin:admin" | sudo chpasswd

sudo useradd -m -s /bin/bash test
echo "test:test" | sudo chpasswd

sudo useradd -m -s /bin/bash user
echo "user:password" | sudo chpasswd

sudo useradd -m -s /bin/bash backup
echo "backup:backup123" | sudo chpasswd

# Enable root with weak password
echo "root:toor" | sudo chpasswd
sudo passwd -u root

# Add admin to sudo group
sudo usermod -aG sudo admin
```

### 5. Install Vulnerable Web Applications

#### Install Apache, PHP, MySQL
```bash
# Install LAMP stack
sudo apt install -y apache2 mysql-server php libapache2-mod-php php-mysql php-gd php-xml php-mbstring unzip

# Start services
sudo systemctl start apache2
sudo systemctl enable apache2
sudo systemctl start mysql
sudo systemctl enable mysql

# Configure MySQL with no root password (vulnerable)
sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '';"
sudo mysql -e "CREATE DATABASE IF NOT EXISTS vulnerable_db;"
sudo mysql -e "FLUSH PRIVILEGES;"
```

#### Install DVWA (Damn Vulnerable Web Application)
```bash
# Download DVWA
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git dvwa

# Set permissions
sudo chown -R www-data:www-data /var/www/html/dvwa
sudo chmod -R 755 /var/www/html/dvwa

# Configure DVWA
sudo cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php

# Update database credentials (no password)
sudo sed -i "s/\$_DVWA\[ 'db_password' \] = 'p@ssw0rd';/\$_DVWA[ 'db_password' ] = '';/" /var/www/html/dvwa/config/config.inc.php
sudo sed -i "s/\$_DVWA\[ 'recaptcha_public_key' \] = '';/\$_DVWA[ 'recaptcha_public_key' ] = '6LdK7xITAAzzAAJQTfL7fu6I-0aPl8KHHieAT_yJg';/" /var/www/html/dvwa/config/config.inc.php
sudo sed -i "s/\$_DVWA\[ 'recaptcha_private_key' \] = '';/\$_DVWA[ 'recaptcha_private_key' ] = '6LdK7xITAzzAAL_uw9YXVUOPoIHPZLfw2K1n5NVQ';/" /var/www/html/dvwa/config/config.inc.php

# Create setup
sudo mysql -e "CREATE DATABASE dvwa;"
sudo mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost' IDENTIFIED BY '';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Configure PHP for DVWA
sudo sed -i 's/allow_url_include = Off/allow_url_include = On/' /etc/php/7.4/apache2/php.ini
sudo sed -i 's/display_errors = Off/display_errors = On/' /etc/php/7.4/apache2/php.ini

# Restart Apache
sudo systemctl restart apache2

# Create index redirect
sudo tee /var/www/html/index.html > /dev/null <<'EOF'
<!DOCTYPE html>
<html>
<head><title>Vulnerable Server</title></head>
<body>
<h1>SOC Lab - Vulnerable Ubuntu Server</h1>
<ul>
  <li><a href="/dvwa/">DVWA - Damn Vulnerable Web Application</a></li>
  <li><a href="/uploads/">Upload Directory</a></li>
</ul>
</body>
</html>
EOF
```

#### Create Vulnerable Upload Directory
```bash
# Create upload directory
sudo mkdir -p /var/www/html/uploads
sudo chmod 777 /var/www/html/uploads
sudo chown www-data:www-data /var/www/html/uploads

# Create simple upload form
sudo tee /var/www/html/uploads/index.php > /dev/null <<'EOF'
<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $target_dir = "/var/www/html/uploads/";
    $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
    
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "File uploaded: <a href='" . basename($_FILES["fileToUpload"]["name"]) . "'>" . basename($_FILES["fileToUpload"]["name"]) . "</a>";
    } else {
        echo "Error uploading file.";
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>File Upload</title></head>
<body>
<h2>Vulnerable File Upload</h2>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="fileToUpload">
    <input type="submit" value="Upload" name="submit">
</form>
</body>
</html>
EOF
```

### 6. Install FTP Server (Vulnerable)

```bash
# Install vsftpd
sudo apt install -y vsftpd

# Backup original config
sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.backup

# Configure vsftpd (weak settings)
sudo tee /etc/vsftpd.conf > /dev/null <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_file=/var/log/vsftpd.log
ftpd_banner=Welcome to vulnerable FTP server
chroot_local_user=NO
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
EOF

# Create FTP directory
sudo mkdir -p /srv/ftp/upload
sudo chmod 777 /srv/ftp/upload
sudo chown ftp:ftp /srv/ftp/upload

# Restart vsftpd
sudo systemctl restart vsftpd
sudo systemctl enable vsftpd
```

### 7. Install Telnet Server (Very Vulnerable)

```bash
# Install telnet server
sudo apt install -y telnetd xinetd

# Enable telnet
sudo systemctl enable inetd
sudo systemctl start inetd
```

## 🔴 CRITICAL: Configure Log Forwarding to SIEM

### 1. Configure Rsyslog for Remote Logging

```bash
# Configure rsyslog to send logs to SIEM
sudo tee /etc/rsyslog.d/50-siem.conf > /dev/null <<'EOF'
# Send all logs to SIEM server
*.* @@192.168.1.20:514

# Local logging rules
auth,authpriv.* /var/log/auth.log
*.*;auth,authpriv.none -/var/log/syslog
kern.* -/var/log/kern.log
mail.* -/var/log/mail.log
EOF

# Restart rsyslog
sudo systemctl restart rsyslog

# Verify rsyslog is running
sudo systemctl status rsyslog
```

### 2. Install and Configure Filebeat

```bash
# Download and install Filebeat
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

sudo apt update
sudo apt install -y filebeat

# Create Filebeat configuration
sudo tee /etc/filebeat/filebeat.yml > /dev/null <<'EOF'
# Filebeat configuration for Ubuntu Vulnerable Server

filebeat.inputs:
# System authentication logs
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
  fields:
    log_type: auth
    log_source: ubuntu-vuln
    environment: soc-lab
  fields_under_root: true
  
# System logs
- type: log
  enabled: true
  paths:
    - /var/log/syslog
  fields:
    log_type: syslog
    log_source: ubuntu-vuln
    environment: soc-lab
  fields_under_root: true

# Apache access logs
- type: log
  enabled: true
  paths:
    - /var/log/apache2/access.log
  fields:
    log_type: apache_access
    log_source: ubuntu-vuln
    environment: soc-lab
  fields_under_root: true

# Apache error logs
- type: log
  enabled: true
  paths:
    - /var/log/apache2/error.log
  fields:
    log_type: apache_error
    log_source: ubuntu-vuln
    environment: soc-lab
  fields_under_root: true

# MySQL logs
- type: log
  enabled: true
  paths:
    - /var/log/mysql/error.log
  fields:
    log_type: mysql_error
    log_source: ubuntu-vuln
    environment: soc-lab
  fields_under_root: true

# FTP logs
- type: log
  enabled: true
  paths:
    - /var/log/vsftpd.log
  fields:
    log_type: ftp
    log_source: ubuntu-vuln
    environment: soc-lab
  fields_under_root: true

# Output to Logstash
output.logstash:
  hosts: ["192.168.1.20:5044"]
  
# Processor to add host metadata
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_fields:
      target: ''
      fields:
        asset_type: vulnerable_linux_server

# Logging
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
EOF

# Enable and start Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Verify Filebeat is running
sudo systemctl status filebeat
```

### 3. Configure Auditd for Security Event Logging

```bash
# Install auditd
sudo apt install -y auditd audispd-plugins

# Configure audit rules
sudo tee /etc/audit/rules.d/soc-lab.rules > /dev/null <<'EOF'
# SOC Lab Audit Rules

# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (0=silent 1=printk 2=panic)
-f 1

# Authentication and Authorization
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

# SSH Configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# System calls by root
-a exit,always -F arch=b64 -F euid=0 -S execve -k root_commands
-a exit,always -F arch=b32 -F euid=0 -S execve -k root_commands

# Unauthorized file access attempts
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -k access

# File deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# Suspicious activity
-w /usr/bin/wget -p x -k network_tools
-w /usr/bin/curl -p x -k network_tools
-w /usr/bin/nc -p x -k network_tools
-w /usr/bin/ncat -p x -k network_tools
-w /usr/bin/ssh -p x -k network_tools
-w /usr/bin/scp -p x -k network_tools

# Web server file changes
-w /var/www/html/ -p wa -k webserver_files

# Privilege escalation
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p rw -k priv_esc

# Make configuration immutable
-e 2
EOF

# Restart auditd
sudo service auditd restart

# Verify audit rules
sudo auditctl -l
```

### 4. Enhanced SSH Logging

```bash
# Increase SSH logging verbosity
sudo sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart sshd
```

### 5. Configure MySQL Query Logging

```bash
# Enable MySQL general query log
sudo tee -a /etc/mysql/mysql.conf.d/mysqld.cnf > /dev/null <<'EOF'

# General query log for security monitoring
general_log_file = /var/log/mysql/mysql.log
general_log = 1
log_error = /var/log/mysql/error.log
EOF

# Create log directory
sudo mkdir -p /var/log/mysql
sudo chown mysql:mysql /var/log/mysql

# Restart MySQL
sudo systemctl restart mysql
```

## Vulnerable Services Summary

| Service | Port | Status | Credentials |
|---------|------|--------|-------------|
| SSH | 22 | Running | Multiple weak accounts |
| HTTP | 80 | Running | DVWA, file upload |
| FTP | 21 | Running | Anonymous enabled |
| Telnet | 23 | Running | Same as SSH users |
| MySQL | 3306 | Running | root with no password |

## Attack Scenarios for Testing

### 1. SSH Brute Force
```bash
# From Kali Linux:
# hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.40

# This generates auth.log entries that are sent to SIEM
```

### 2. Web Application Attacks
```bash
# SQL Injection test
curl "http://192.168.1.40/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit#"

# XSS test
curl "http://192.168.1.40/dvwa/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>"

# File upload
# Upload PHP web shell
```

### 3. FTP Anonymous Access
```bash
# From Kali:
# ftp 192.168.1.40
# Username: anonymous
# Password: <blank>
```

### 4. Directory Traversal
```bash
curl "http://192.168.1.40/dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd"
```

## Log Monitoring Commands

### Check Local Logs
```bash
# SSH authentication attempts
sudo tail -f /var/log/auth.log

# Web server access
sudo tail -f /var/log/apache2/access.log

# Audit logs
sudo ausearch -k identity -i

# All syslog
sudo tail -f /var/log/syslog
```

### Verify Log Forwarding

```bash
# Check rsyslog status
sudo systemctl status rsyslog

# Check Filebeat status
sudo systemctl status filebeat

# View Filebeat logs
sudo tail -f /var/log/filebeat/filebeat

# Test connection to SIEM
nc -zv 192.168.1.20 514
nc -zv 192.168.1.20 5044

# Generate test log entry
logger -t "SOC-TEST" "Test message from ubuntu-vuln server"
```

## Verify Logs on SIEM Server

From the SIEM server (192.168.1.20):

```bash
# Check if logs are being received
sudo tail -f /var/log/remote-hosts/ubuntu-vuln/auth.log

# Query Elasticsearch
curl -X GET "localhost:9200/soc-lab-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        {"match": {"log_source": "ubuntu-vuln"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "size": 10,
  "sort": [{"@timestamp": "desc"}]
}
'
```

## Important Log Patterns to Monitor

### SSH Attacks
```
Failed password for invalid user
Failed password for admin from
Accepted password for
```

### Web Attacks
```
union select
<script>
../../
SELECT * FROM
DROP TABLE
```

### Suspicious Commands
```
sudo su
wget http://
curl http://
nc -e
/bin/bash
```

## Firewall Configuration (Minimal for Testing)

```bash
# Install UFW
sudo apt install -y ufw

# Allow all required services
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 21/tcp    # FTP
sudo ufw allow 23/tcp    # Telnet
sudo ufw allow 3306/tcp  # MySQL

# Enable with logging
sudo ufw logging on
sudo ufw enable

# Check status
sudo ufw status verbose
```

## Maintenance and Monitoring

### Create Health Check Script
```bash
sudo tee /usr/local/bin/check-logging.sh > /dev/null <<'EOF'
#!/bin/bash

echo "=== Logging Status Check ==="
echo ""

# Check services
echo "Rsyslog: $(systemctl is-active rsyslog)"
echo "Filebeat: $(systemctl is-active filebeat)"
echo "Auditd: $(systemctl is-active auditd)"
echo "Apache: $(systemctl is-active apache2)"
echo "MySQL: $(systemctl is-active mysql)"
echo "vsftpd: $(systemctl is-active vsftpd)"
echo ""

# Check SIEM connectivity
echo "SIEM Rsyslog (514): $(nc -zv 192.168.1.20 514 2>&1 | grep -q succeeded && echo 'Connected' || echo 'Failed')"
echo "SIEM Logstash (5044): $(nc -zv 192.168.1.20 5044 2>&1 | grep -q succeeded && echo 'Connected' || echo 'Failed')"
echo ""

# Recent auth events
echo "Recent SSH attempts:"
sudo grep -i "authentication failure" /var/log/auth.log | tail -5
EOF

sudo chmod +x /usr/local/bin/check-logging.sh

# Run it
/usr/local/bin/check-logging.sh
```

## Troubleshooting

### Logs Not Reaching SIEM

1. **Check network connectivity:**
```bash
ping -c 3 192.168.1.20
nc -zv 192.168.1.20 514
nc -zv 192.168.1.20 5044
```

2. **Check Filebeat:**
```bash
sudo systemctl status filebeat
sudo filebeat test config
sudo filebeat test output
sudo tail -f /var/log/filebeat/filebeat
```

3. **Check rsyslog:**
```bash
sudo systemctl status rsyslog
sudo rsyslogd -N1  # Test config
```

4. **Verify log generation:**
```bash
logger -t "TEST" "Test message"
tail /var/log/syslog
```

## Snapshots

```bash
# Clean state
VBoxManage snapshot "UBUNTU-VULN" take "Clean-With-Logging" --description "Fresh install with logging configured"

# After DVWA setup
VBoxManage snapshot "UBUNTU-VULN" take "DVWA-Configured" --description "DVWA and vulnerable apps installed"
```

## Security Warnings

⚠️ **EXTREME WARNING**: This server is HIGHLY vulnerable by design.

- Never connect to the internet
- Run only in isolated lab environment
- Contains multiple intentional security flaws
- No password complexity requirements
- Anonymous FTP enabled
- Root login enabled
- All services exposed
- Logging is the ONLY security control

## Quick Reference

### Default Credentials
- **socuser**: Password123!
- **admin**: admin
- **test**: test
- **root**: toor
- **MySQL root**: (no password)
- **FTP anonymous**: (no password)

### Access URLs
- **DVWA**: http://192.168.1.40/dvwa/
- **File Upload**: http://192.168.1.40/uploads/
- **Main Page**: http://192.168.1.40/

### Log Locations
- **Auth logs**: /var/log/auth.log
- **Apache**: /var/log/apache2/
- **MySQL**: /var/log/mysql/
- **FTP**: /var/log/vsftpd.log
- **Audit**: /var/log/audit/audit.log

## Next Steps

1. ✅ Verify all services are running
2. ✅ Confirm logs are reaching SIEM (check Kibana)
3. ✅ Access DVWA and complete setup
4. ✅ Generate test attacks and verify detection
5. ✅ Create detection rules in SIEM
6. ✅ Practice incident response scenarios

## References

- [DVWA Documentation](https://github.com/digininja/DVWA)
- [Filebeat Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Linux Audit Documentation](https://linux-audit.com/)
- [Apache Security](https://httpd.apache.org/docs/2.4/misc/security_tips.html)
