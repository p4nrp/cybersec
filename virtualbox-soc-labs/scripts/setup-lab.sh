#!/bin/bash

# SOC Lab Environment Setup Script
# This script automates the creation of VirtualBox VMs for SOC analyst training

set -e  # Exit on any error

# Configuration variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
ISO_DIR="$LAB_DIR/iso"
VM_DIR="$HOME/VirtualBox VMs"
NAT_NETWORK_NAME="SOC-Lab-Network"
NAT_NETWORK_CIDR="10.0.2.0/24"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Check if VirtualBox is installed
check_virtualbox() {
    log "Checking VirtualBox installation..."
    if ! command -v VBoxManage &> /dev/null; then
        error "VirtualBox is not installed or not in PATH"
    fi
    
    local vbox_version=$(VBoxManage --version)
    log "VirtualBox version: $vbox_version"
    
    # Check if version is 6.1 or higher
    local version_major=$(echo $vbox_version | cut -d'.' -f1)
    local version_minor=$(echo $vbox_version | cut -d'.' -f2)
    
    if [[ $version_major -lt 6 ]] || [[ $version_major -eq 6 && $version_minor -lt 1 ]]; then
        warn "VirtualBox version 6.1 or higher is recommended"
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check available RAM
    local total_ram=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $total_ram -lt 16 ]]; then
        warn "System has ${total_ram}GB RAM. 16GB or more is recommended for optimal performance"
    else
        log "System RAM: ${total_ram}GB (sufficient)"
    fi
    
    # Check available disk space
    local available_space=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ $available_space -lt 200 ]]; then
        warn "Available disk space: ${available_space}GB. 200GB or more is recommended"
    else
        log "Available disk space: ${available_space}GB (sufficient)"
    fi
    
    # Check CPU cores
    local cpu_cores=$(nproc)
    if [[ $cpu_cores -lt 4 ]]; then
        warn "System has ${cpu_cores} CPU cores. 4 or more cores are recommended"
    else
        log "CPU cores: ${cpu_cores} (sufficient)"
    fi
}

# Create ISO directory and check for required ISOs
setup_iso_directory() {
    log "Setting up ISO directory..."
    mkdir -p "$ISO_DIR"
    
    local required_isos=(
        "ubuntu-20.04.6-live-server-amd64.iso"
        "kali-linux-2023.4-installer-amd64.iso"
        "Win10_22H2_English_x64.iso"
        "Windows_Server_2019_Datacenter_EVAL_x64_FRE_en-us.iso"
    )
    
    local missing_isos=()
    
    for iso in "${required_isos[@]}"; do
        if [[ ! -f "$ISO_DIR/$iso" ]]; then
            missing_isos+=("$iso")
        fi
    done
    
    if [[ ${#missing_isos[@]} -gt 0 ]]; then
        warn "Missing ISO files in $ISO_DIR:"
        for iso in "${missing_isos[@]}"; do
            echo "  - $iso"
        done
        echo ""
        echo "Please download the required ISO files and place them in $ISO_DIR"
        echo "Download links:"
        echo "  Ubuntu 20.04: https://ubuntu.com/download/server"
        echo "  Kali Linux: https://www.kali.org/get-kali/"
        echo "  Windows 10: https://www.microsoft.com/software-download/windows10"
        echo "  Windows Server 2019: https://www.microsoft.com/evalcenter/evaluate-windows-server-2019"
        echo ""
        read -p "Continue without creating VMs that require missing ISOs? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log "All required ISO files found"
    fi
}

# Create NAT network
create_nat_network() {
    log "Creating NAT network: $NAT_NETWORK_NAME"
    
    # Check if network already exists
    if VBoxManage list natnetworks | grep -q "$NAT_NETWORK_NAME"; then
        warn "NAT network '$NAT_NETWORK_NAME' already exists, removing it first"
        VBoxManage natnetwork remove --netname "$NAT_NETWORK_NAME"
    fi
    
    # Create new NAT network
    VBoxManage natnetwork add --netname "$NAT_NETWORK_NAME" --network "$NAT_NETWORK_CIDR" --enable
    
    # Disable DHCP (we'll use static IPs)
    VBoxManage natnetwork modify --netname "$NAT_NETWORK_NAME" --dhcp off
    
    # Add port forwarding rules for external access
    log "Adding port forwarding rules..."
    VBoxManage natnetwork modify --netname "$NAT_NETWORK_NAME" --port-forward-4 "ssh-siem:tcp:[]:2222:[10.0.2.100]:22"
    VBoxManage natnetwork modify --netname "$NAT_NETWORK_NAME" --port-forward-4 "kibana:tcp:[]:5601:[10.0.2.100]:5601"
    VBoxManage natnetwork modify --netname "$NAT_NETWORK_NAME" --port-forward-4 "dvwa:tcp:[]:8080:[10.0.2.101]:80"
    VBoxManage natnetwork modify --netname "$NAT_NETWORK_NAME" --port-forward-4 "ssh-kali:tcp:[]:2223:[10.0.2.15]:22"
    
    log "NAT network created successfully"
}

# Create VM function
create_vm() {
    local vm_name="$1"
    local os_type="$2"
    local memory="$3"
    local cpus="$4"
    local disk_size="$5"
    local iso_file="$6"
    local ip_address="$7"
    
    log "Creating VM: $vm_name"
    
    # Check if VM already exists
    if VBoxManage list vms | grep -q "\"$vm_name\""; then
        warn "VM '$vm_name' already exists, skipping creation"
        return 0
    fi
    
    # Check if ISO file exists (if provided)
    if [[ -n "$iso_file" && ! -f "$ISO_DIR/$iso_file" ]]; then
        warn "ISO file '$iso_file' not found, skipping VM '$vm_name'"
        return 0
    fi
    
    # Create VM
    VBoxManage createvm --name "$vm_name" --ostype "$os_type" --register
    
    # Configure VM
    VBoxManage modifyvm "$vm_name" --memory "$memory" --cpus "$cpus"
    VBoxManage modifyvm "$vm_name" --vram 128
    VBoxManage modifyvm "$vm_name" --nic1 natnetwork --nat-network1 "$NAT_NETWORK_NAME"
    VBoxManage modifyvm "$vm_name" --audio none
    VBoxManage modifyvm "$vm_name" --clipboard bidirectional
    VBoxManage modifyvm "$vm_name" --draganddrop bidirectional
    
    # Create and attach storage
    local disk_path="$VM_DIR/$vm_name/$vm_name.vdi"
    VBoxManage createhd --filename "$disk_path" --size "$disk_size"
    VBoxManage storagectl "$vm_name" --name "SATA Controller" --add sata --controller IntelAHCI
    VBoxManage storageattach "$vm_name" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$disk_path"
    
    # Attach ISO if provided
    if [[ -n "$iso_file" ]]; then
        VBoxManage storageattach "$vm_name" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "$ISO_DIR/$iso_file"
    fi
    
    # Enable nested virtualization for some VMs
    if [[ "$vm_name" == "Kali-Attacker" || "$vm_name" == "ELK-SIEM" ]]; then
        VBoxManage modifyvm "$vm_name" --nested-hw-virt on
    fi
    
    # Set boot order
    VBoxManage modifyvm "$vm_name" --boot1 dvd --boot2 disk --boot3 none --boot4 none
    
    log "VM '$vm_name' created successfully (IP: $ip_address)"
}

# Create all VMs
create_all_vms() {
    log "Creating all VMs..."
    
    # ELK SIEM VM
    create_vm "ELK-SIEM" "Ubuntu_64" 8192 4 102400 "ubuntu-20.04.6-live-server-amd64.iso" "10.0.2.100"
    
    # Kali Attacker VM
    create_vm "Kali-Attacker" "Debian_64" 4096 2 81920 "kali-linux-2023.4-installer-amd64.iso" "10.0.2.15"
    
    # Vulnerable Ubuntu VM
    create_vm "Ubuntu-Vulnerable" "Ubuntu_64" 2048 2 40960 "ubuntu-20.04.6-live-server-amd64.iso" "10.0.2.101"
    
    # Vulnerable Windows 10 VM
    create_vm "Windows10-Vulnerable" "Windows10_64" 4096 2 61440 "Win10_22H2_English_x64.iso" "10.0.2.102"
    
    # Windows Server 2019 Domain Controller
    create_vm "Windows-DC" "Windows2019_64" 4096 2 61440 "Windows_Server_2019_Datacenter_EVAL_x64_FRE_en-us.iso" "10.0.2.10"
    
    # Web Server VM (Ubuntu)
    create_vm "Web-Server" "Ubuntu_64" 2048 2 40960 "ubuntu-20.04.6-live-server-amd64.iso" "10.0.2.103"
    
    log "All VMs created successfully"
}

# Create VM groups for organization
create_vm_groups() {
    log "Creating VM groups for organization..."
    
    # Create groups
    VBoxManage modifyvm "ELK-SIEM" --groups "/SOC-Lab/Monitoring"
    VBoxManage modifyvm "Kali-Attacker" --groups "/SOC-Lab/Attackers"
    VBoxManage modifyvm "Ubuntu-Vulnerable" --groups "/SOC-Lab/Targets"
    VBoxManage modifyvm "Windows10-Vulnerable" --groups "/SOC-Lab/Targets"
    VBoxManage modifyvm "Windows-DC" --groups "/SOC-Lab/Infrastructure"
    VBoxManage modifyvm "Web-Server" --groups "/SOC-Lab/Targets"
    
    log "VM groups created successfully"
}

# Generate configuration files
generate_configs() {
    log "Generating configuration files..."
    
    local config_dir="$LAB_DIR/generated-configs"
    mkdir -p "$config_dir"
    
    # Generate network configuration for Ubuntu systems
    cat > "$config_dir/netplan-siem.yaml" << 'EOF'
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 10.0.2.100/24
      gateway4: 10.0.2.1
      nameservers:
        addresses:
          - 10.0.2.1
          - 8.8.8.8
EOF

    cat > "$config_dir/netplan-ubuntu-vulnerable.yaml" << 'EOF'
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 10.0.2.101/24
      gateway4: 10.0.2.1
      nameservers:
        addresses:
          - 10.0.2.1
          - 8.8.8.8
EOF

    cat > "$config_dir/netplan-web-server.yaml" << 'EOF'
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 10.0.2.103/24
      gateway4: 10.0.2.1
      nameservers:
        addresses:
          - 10.0.2.1
          - 8.8.8.8
EOF

    # Generate Windows PowerShell configuration script
    cat > "$config_dir/windows-network-config.ps1" << 'EOF'
# Windows Network Configuration Script
# Run as Administrator

# Configure static IP for Domain Controller (10.0.2.10)
if ($env:COMPUTERNAME -eq "DC") {
    New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "10.0.2.10" -PrefixLength 24 -DefaultGateway "10.0.2.1"
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "127.0.0.1","8.8.8.8"
}

# Configure static IP for Windows 10 Vulnerable (10.0.2.102)
if ($env:COMPUTERNAME -eq "WIN10-VULN") {
    New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "10.0.2.102" -PrefixLength 24 -DefaultGateway "10.0.2.1"
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "10.0.2.10","8.8.8.8"
}

Write-Host "Network configuration completed"
EOF

    # Generate VM startup script
    cat > "$config_dir/start-vms.sh" << 'EOF'
#!/bin/bash

# Start VMs in the correct order
echo "Starting SOC Lab VMs..."

# Start infrastructure first
echo "Starting Domain Controller..."
VBoxManage startvm "Windows-DC" --type headless

# Wait for DC to boot
sleep 60

# Start monitoring systems
echo "Starting SIEM system..."
VBoxManage startvm "ELK-SIEM" --type headless

# Start target systems
echo "Starting vulnerable systems..."
VBoxManage startvm "Ubuntu-Vulnerable" --type headless
VBoxManage startvm "Windows10-Vulnerable" --type headless
VBoxManage startvm "Web-Server" --type headless

# Start attacker system last
echo "Starting attacker system..."
VBoxManage startvm "Kali-Attacker" --type gui

echo "All VMs started. Please wait for systems to fully boot."
echo "Access points:"
echo "  Kibana: http://localhost:5601"
echo "  DVWA: http://localhost:8080/dvwa"
echo "  SSH to SIEM: ssh -p 2222 user@localhost"
echo "  SSH to Kali: ssh -p 2223 kali@localhost"
EOF

    chmod +x "$config_dir/start-vms.sh"
    
    # Generate VM shutdown script
    cat > "$config_dir/stop-vms.sh" << 'EOF'
#!/bin/bash

# Stop all SOC Lab VMs
echo "Stopping SOC Lab VMs..."

VBoxManage controlvm "Kali-Attacker" acpipowerbutton 2>/dev/null || true
VBoxManage controlvm "Windows10-Vulnerable" acpipowerbutton 2>/dev/null || true
VBoxManage controlvm "Ubuntu-Vulnerable" acpipowerbutton 2>/dev/null || true
VBoxManage controlvm "Web-Server" acpipowerbutton 2>/dev/null || true
VBoxManage controlvm "ELK-SIEM" acpipowerbutton 2>/dev/null || true

# Wait a bit before stopping DC
sleep 30
VBoxManage controlvm "Windows-DC" acpipowerbutton 2>/dev/null || true

echo "Shutdown commands sent to all VMs"
EOF

    chmod +x "$config_dir/stop-vms.sh"
    
    log "Configuration files generated in $config_dir"
}

# Create documentation
create_documentation() {
    log "Creating setup documentation..."
    
    local doc_file="$LAB_DIR/SETUP-GUIDE.md"
    
    cat > "$doc_file" << 'EOF'
# SOC Lab Setup Guide

## Post-Installation Steps

After running the setup script, you need to install and configure the operating systems on each VM.

### 1. Install Operating Systems

Start each VM and follow the installation process:

#### Ubuntu Systems (SIEM, Vulnerable Linux, Web Server)
1. Boot from Ubuntu ISO
2. Follow standard server installation
3. Create user account (recommended: username `soc`, password `soclab123`)
4. Install OpenSSH server when prompted
5. After installation, configure static IP using the generated netplan files

#### Kali Linux (Attacker)
1. Boot from Kali ISO
2. Follow graphical installation
3. Create user account (default: username `kali`, password `kali`)
4. Configure network (DHCP is fine, will get 10.0.2.15)

#### Windows Systems
1. Boot from Windows ISO
2. Follow installation wizard
3. Create local administrator account
4. Configure static IP using the PowerShell script
5. Join domain (for Windows 10) after DC is configured

### 2. Network Configuration

Copy the generated network configuration files to each system:

#### Ubuntu Systems
```bash
sudo cp netplan-*.yaml /etc/netplan/01-netcfg.yaml
sudo netplan apply
```

#### Windows Systems
```powershell
# Run as Administrator
.\windows-network-config.ps1
```

### 3. Install Lab Software

Follow the detailed installation guides in each VM's documentation:
- `vms/siem-monitoring/elk-siem.md`
- `vms/vulnerable-linux/ubuntu-vulnerable.md`
- `vms/vulnerable-windows/windows10-vulnerable.md`
- `vms/attacker-kali/kali-linux.md`

### 4. Start the Lab

Use the generated startup script:
```bash
./generated-configs/start-vms.sh
```

### 5. Access Points

After all systems are running:
- **Kibana**: http://localhost:5601
- **DVWA**: http://localhost:8080/dvwa
- **SSH to SIEM**: `ssh -p 2222 soc@localhost`
- **SSH to Kali**: `ssh -p 2223 kali@localhost`

### 6. Run Attack Scenarios

Navigate to the `attack-scenarios` directory and follow the scenario guides:
- `scenario-01-brute-force.md`
- `scenario-02-malware-analysis.md`
- `scenario-03-web-application-attacks.md`

## Troubleshooting

### Common Issues
1. **VMs won't start**: Check available RAM and CPU resources
2. **Network connectivity issues**: Verify NAT network configuration
3. **Performance issues**: Allocate more resources to VMs
4. **ISO files missing**: Download required ISOs to the `iso` directory

### Support
- Check the troubleshooting section in each VM's documentation
- Review VirtualBox logs: `VBoxManage showvminfo <vmname> --log 0`
- Verify network configuration: `VBoxManage list natnetworks`
EOF

    log "Setup documentation created: $doc_file"
}

# Main setup function
main() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "  SOC Lab Environment Setup Script"
    echo "========================================"
    echo -e "${NC}"
    
    log "Starting SOC lab setup..."
    
    # Pre-flight checks
    check_virtualbox
    check_requirements
    
    # Setup directories and files
    setup_iso_directory
    
    # Create network infrastructure
    create_nat_network
    
    # Create VMs
    create_all_vms
    create_vm_groups
    
    # Generate configuration files
    generate_configs
    create_documentation
    
    echo -e "${GREEN}"
    echo "========================================"
    echo "  Setup Complete!"
    echo "========================================"
    echo -e "${NC}"
    
    echo "Next steps:"
    echo "1. Install operating systems on each VM"
    echo "2. Configure network settings using generated config files"
    echo "3. Install lab software following the VM-specific guides"
    echo "4. Start the lab using: ./generated-configs/start-vms.sh"
    echo ""
    echo "See SETUP-GUIDE.md for detailed instructions"
    echo ""
    echo "Lab access points (after setup):"
    echo "  Kibana: http://localhost:5601"
    echo "  DVWA: http://localhost:8080/dvwa"
    echo "  SSH to SIEM: ssh -p 2222 user@localhost"
    echo "  SSH to Kali: ssh -p 2223 kali@localhost"
}

# Run main function
main "$@"