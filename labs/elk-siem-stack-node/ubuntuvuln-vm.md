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
