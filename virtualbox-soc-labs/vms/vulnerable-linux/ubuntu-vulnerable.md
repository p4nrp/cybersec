# Vulnerable Ubuntu Linux VM Configuration

## VM Specifications
- **OS**: Ubuntu 20.04 LTS Server
- **RAM**: 2GB (minimum), 4GB (recommended)
- **Storage**: 40GB
- **Network**: NAT Network (SOC-Lab-Network)
- **CPU**: 2 cores

## Installation Steps

1. **Download Ubuntu Server ISO**
   - Download Ubuntu 20.04 LTS Server from official website

2. **VirtualBox Configuration**
   ```bash
   # Create VM
   VBoxManage createvm --name "Ubuntu-Vulnerable" --ostype "Ubuntu_64" --register
   
   # Configure VM
   VBoxManage modifyvm "Ubuntu-Vulnerable" --memory 2048 --cpus 2
   VBoxManage modifyvm "Ubuntu-Vulnerable" --vram 16
   VBoxManage modifyvm "Ubuntu-Vulnerable" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
   VBoxManage modifyvm "Ubuntu-Vulnerable" --audio none
   
   # Create and attach storage
   VBoxManage createhd --filename "Ubuntu-Vulnerable.vdi" --size 40960
   VBoxManage storagectl "Ubuntu-Vulnerable" --name "SATA Controller" --add sata --controller IntelAHCI
   VBoxManage storageattach "Ubuntu-Vulnerable" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "Ubuntu-Vulnerable.vdi"
   VBoxManage storageattach "Ubuntu-Vulnerable" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "ubuntu-20.04-server.iso"
   ```

## Post-Installation Configuration

### 1. Initial Setup
```bash
# Update system (but keep vulnerable packages)
sudo apt update

# Install essential tools
sudo apt install -y openssh-server apache2 mysql-server php php-mysql
sudo apt install -y vsftpd telnetd xinetd
sudo apt install -y net-tools nmap curl wget
```

### 2. Create Vulnerable User Accounts
```bash
# Create users with weak passwords
sudo useradd -m -s /bin/bash vulnerable
echo 'vulnerable:password' | sudo chpasswd

sudo useradd -m -s /bin/bash admin
echo 'admin:admin' | sudo chpasswd

sudo useradd -m -s /bin/bash test
echo 'test:test' | sudo chpasswd

sudo useradd -m -s /bin/bash guest
echo 'guest:guest' | sudo chpasswd

# Add users to sudo group
sudo usermod -aG sudo admin
sudo usermod -aG sudo vulnerable

# Create user with no password
sudo useradd -m -s /bin/bash nopass
sudo passwd -d nopass
```

### 3. Configure Vulnerable SSH
```bash
# Backup original config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Create vulnerable SSH config
sudo tee /etc/ssh/sshd_config > /dev/null <<EOF
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
StrictModes no
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts no
RhostsRSAAuthentication yes
HostbasedAuthentication yes
PermitEmptyPasswords yes
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
EOF

sudo systemctl restart ssh
```

### 4. Install Vulnerable Web Applications

#### DVWA (Damn Vulnerable Web Application)
```bash
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git dvwa
sudo chown -R www-data:www-data dvwa
sudo chmod -R 755 dvwa
sudo chmod -R 777 dvwa/hackable/uploads/
sudo chmod 666 dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt

# Configure DVWA
sudo cp dvwa/config/config.inc.php.dist dvwa/config/config.inc.php
```

#### WebGoat
```bash
# Install Java
sudo apt install -y openjdk-8-jdk

# Download and setup WebGoat
cd /opt
sudo wget https://github.com/WebGoat/WebGoat/releases/download/v8.2.2/webgoat-server-8.2.2.jar
sudo chmod +x webgoat-server-8.2.2.jar

# Create service
sudo tee /etc/systemd/system/webgoat.service > /dev/null <<EOF
[Unit]
Description=WebGoat
After=network.target

[Service]
Type=simple
User=www-data
ExecStart=/usr/bin/java -jar /opt/webgoat-server-8.2.2.jar --server.port=8080 --server.address=0.0.0.0
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable webgoat
sudo systemctl start webgoat
```

### 5. Configure Vulnerable Services

#### FTP Server (vsftpd)
```bash
sudo tee /etc/vsftpd.conf > /dev/null <<EOF
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=YES
local_umask=022
anon_upload_enable=YES
anon_mkdir_write_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=NO
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
allow_anon_ssl=NO
force_local_data_ssl=NO
force_local_logins_ssl=NO
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH
EOF

sudo systemctl restart vsftpd
```

#### Telnet Service
```bash
sudo tee /etc/xinetd.d/telnet > /dev/null <<EOF
service telnet
{
    disable = no
    flags = REUSE
    socket_type = stream
    wait = no
    user = root
    server = /usr/sbin/in.telnetd
    log_on_failure += USERID
}
EOF

sudo systemctl restart xinetd
```

### 6. Install Vulnerable Software Versions

#### Old PHP Version with Vulnerabilities
```bash
# Install PHP 7.4 with known vulnerabilities
sudo apt install -y php7.4 php7.4-mysql php7.4-gd php7.4-xml

# Configure PHP with vulnerable settings
sudo sed -i 's/allow_url_fopen = Off/allow_url_fopen = On/' /etc/php/7.4/apache2/php.ini
sudo sed -i 's/allow_url_include = Off/allow_url_include = On/' /etc/php/7.4/apache2/php.ini
sudo sed -i 's/display_errors = Off/display_errors = On/' /etc/php/7.4/apache2/php.ini
```

#### MySQL with Weak Configuration
```bash
# Configure MySQL with weak settings
sudo mysql -e "CREATE USER 'root'@'%' IDENTIFIED BY '';"
sudo mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%';"
sudo mysql -e "CREATE USER 'admin'@'%' IDENTIFIED BY 'admin';"
sudo mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Allow remote connections
sudo sed -i 's/bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf
sudo systemctl restart mysql
```

### 7. File System Vulnerabilities
```bash
# Create world-writable directories
sudo mkdir -p /tmp/uploads
sudo chmod 777 /tmp/uploads

# Create SUID binaries
sudo cp /bin/bash /tmp/vulnerable_bash
sudo chmod 4755 /tmp/vulnerable_bash

# Create files with weak permissions
sudo touch /etc/shadow.backup
sudo chmod 644 /etc/shadow.backup

# Create cron job with weak permissions
echo "* * * * * root /tmp/backup.sh" | sudo tee /etc/cron.d/vulnerable_cron
sudo chmod 666 /etc/cron.d/vulnerable_cron
```

### 8. Install Monitoring Tools

#### Auditd for System Auditing
```bash
sudo apt install -y auditd audispd-plugins

# Configure audit rules
sudo tee /etc/audit/rules.d/audit.rules > /dev/null <<EOF
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor file access
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Monitor system calls
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# Monitor network connections
-a always,exit -F arch=b64 -S socket -k network
-a always,exit -F arch=b32 -S socket -k network
EOF

sudo systemctl restart auditd
```

#### Rsyslog Configuration
```bash
# Configure rsyslog to forward logs
sudo tee -a /etc/rsyslog.conf > /dev/null <<EOF

# Forward logs to SIEM Machine
*.* @@10.0.2.100:514
EOF

sudo systemctl restart rsyslog
```

## Default Credentials

| Service | Username | Password | Port |
|---------|----------|----------|------|
| SSH | vulnerable | password | 22 |
| SSH | admin | admin | 22 |
| SSH | root | toor | 22 |
| FTP | anonymous | (any) | 21 |
| FTP | vulnerable | password | 21 |
| MySQL | root | (empty) | 3306 |
| MySQL | admin | admin | 3306 |
| Telnet | vulnerable | password | 23 |

## Vulnerable Services Running

| Service | Port | Vulnerability |
|---------|------|---------------|
| SSH | 22 | Weak passwords, root login enabled |
| Telnet | 23 | Unencrypted, weak passwords |
| FTP | 21 | Anonymous access, weak passwords |
| HTTP | 80 | DVWA, vulnerable PHP apps |
| MySQL | 3306 | No root password, remote access |
| WebGoat | 8080 | Intentionally vulnerable web app |

## Attack Scenarios Supported

1. **Brute Force Attacks**
   - SSH password attacks
   - FTP credential attacks
   - MySQL authentication bypass

2. **Web Application Attacks**
   - SQL injection (DVWA)
   - XSS attacks
   - File upload vulnerabilities
   - Directory traversal

3. **Privilege Escalation**
   - SUID binary exploitation
   - Cron job abuse
   - Weak file permissions

4. **Network Service Exploitation**
   - Telnet interception
   - FTP bounce attacks
   - MySQL enumeration

## Security Notes

⚠️ **WARNING**: This VM is intentionally vulnerable and should only be used in isolated lab environments. Never connect this VM to production networks or the internet without proper isolation.

## Log Locations

- **System logs**: `/var/log/syslog`
- **Auth logs**: `/var/log/auth.log`
- **Apache logs**: `/var/log/apache2/`
- **MySQL logs**: `/var/log/mysql/`
- **Audit logs**: `/var/log/audit/audit.log`
