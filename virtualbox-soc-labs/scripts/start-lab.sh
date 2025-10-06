#!/bin/bash

# SOC Lab Startup Script
# This script starts all VMs in the correct order for optimal performance

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAT_NETWORK_NAME="SOC-Lab-Network"
STARTUP_DELAY=30  # Seconds to wait between VM starts

# VM definitions (name, type, boot_delay)
declare -A VMS=(
    ["Windows-DC"]="infrastructure,60"
    ["ELK-SIEM"]="monitoring,45"
    ["Ubuntu-Vulnerable"]="target,30"
    ["Web-Server"]="target,30"
    ["Windows10-Vulnerable"]="target,45"
    ["Kali-Attacker"]="attacker,0"
)

# Logging functions
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

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Check if VirtualBox is available
check_virtualbox() {
    if ! command -v VBoxManage &> /dev/null; then
        error "VirtualBox is not installed or not in PATH"
    fi
}

# Check if NAT network exists
check_nat_network() {
    if ! VBoxManage list natnetworks | grep -q "$NAT_NETWORK_NAME"; then
        error "NAT network '$NAT_NETWORK_NAME' not found. Run setup-lab.sh first."
    fi
}

# Check VM status
get_vm_status() {
    local vm_name="$1"
    local status=$(VBoxManage showvminfo "$vm_name" --machinereadable | grep "VMState=" | cut -d'"' -f2)
    echo "$status"
}

# Check if VM exists
vm_exists() {
    local vm_name="$1"
    VBoxManage list vms | grep -q "\"$vm_name\""
}

# Start a VM
start_vm() {
    local vm_name="$1"
    local vm_type="$2"
    local boot_delay="$3"
    
    if ! vm_exists "$vm_name"; then
        warn "VM '$vm_name' not found, skipping"
        return 1
    fi
    
    local status=$(get_vm_status "$vm_name")
    
    if [[ "$status" == "running" ]]; then
        info "VM '$vm_name' is already running"
        return 0
    fi
    
    log "Starting VM: $vm_name ($vm_type)"
    
    # Start VM based on type
    if [[ "$vm_name" == "Kali-Attacker" ]]; then
        # Start Kali with GUI for interactive use
        VBoxManage startvm "$vm_name" --type gui
    else
        # Start other VMs headless
        VBoxManage startvm "$vm_name" --type headless
    fi
    
    # Wait for boot delay if specified
    if [[ $boot_delay -gt 0 ]]; then
        info "Waiting ${boot_delay} seconds for '$vm_name' to boot..."
        sleep $boot_delay
    fi
    
    log "VM '$vm_name' started successfully"
    return 0
}

# Stop a VM gracefully
stop_vm() {
    local vm_name="$1"
    
    if ! vm_exists "$vm_name"; then
        warn "VM '$vm_name' not found, skipping"
        return 1
    fi
    
    local status=$(get_vm_status "$vm_name")
    
    if [[ "$status" != "running" ]]; then
        info "VM '$vm_name' is not running"
        return 0
    fi
    
    log "Stopping VM: $vm_name"
    VBoxManage controlvm "$vm_name" acpipowerbutton
    
    return 0
}

# Wait for VM to be accessible
wait_for_vm() {
    local vm_name="$1"
    local ip_address="$2"
    local port="$3"
    local timeout="$4"
    
    info "Waiting for '$vm_name' to be accessible on $ip_address:$port..."
    
    local count=0
    while [[ $count -lt $timeout ]]; do
        if nc -z -w1 "$ip_address" "$port" 2>/dev/null; then
            log "VM '$vm_name' is accessible"
            return 0
        fi
        
        sleep 5
        ((count += 5))
        
        if [[ $((count % 30)) -eq 0 ]]; then
            info "Still waiting for '$vm_name'... ($count/${timeout}s)"
        fi
    done
    
    warn "Timeout waiting for '$vm_name' to become accessible"
    return 1
}

# Check VM accessibility
check_vm_accessibility() {
    log "Checking VM accessibility..."
    
    # Check SIEM (SSH and Kibana)
    if vm_exists "ELK-SIEM"; then
        wait_for_vm "ELK-SIEM" "10.0.2.100" "22" 120 &
        wait_for_vm "ELK-SIEM" "10.0.2.100" "5601" 180 &
    fi
    
    # Check vulnerable systems
    if vm_exists "Ubuntu-Vulnerable"; then
        wait_for_vm "Ubuntu-Vulnerable" "10.0.2.101" "22" 120 &
        wait_for_vm "Ubuntu-Vulnerable" "10.0.2.101" "80" 120 &
    fi
    
    if vm_exists "Windows10-Vulnerable"; then
        wait_for_vm "Windows10-Vulnerable" "10.0.2.102" "3389" 180 &
    fi
    
    if vm_exists "Web-Server"; then
        wait_for_vm "Web-Server" "10.0.2.103" "22" 120 &
        wait_for_vm "Web-Server" "10.0.2.103" "80" 120 &
    fi
    
    # Wait for all background checks to complete
    wait
}

# Display lab status
show_lab_status() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "         SOC Lab Status"
    echo "========================================"
    echo -e "${NC}"
    
    for vm_name in "${!VMS[@]}"; do
        if vm_exists "$vm_name"; then
            local status=$(get_vm_status "$vm_name")
            local status_color=""
            
            case "$status" in
                "running")
                    status_color="${GREEN}"
                    ;;
                "poweroff"|"aborted")
                    status_color="${RED}"
                    ;;
                *)
                    status_color="${YELLOW}"
                    ;;
            esac
            
            printf "%-25s %s%s%s\n" "$vm_name" "$status_color" "$status" "$NC"
        else
            printf "%-25s %s%s%s\n" "$vm_name" "$RED" "not found" "$NC"
        fi
    done
    
    echo ""
}

# Display access information
show_access_info() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "        Lab Access Information"
    echo "========================================"
    echo -e "${NC}"
    
    echo "External Access (from host system):"
    echo "  Kibana (SIEM):     http://localhost:5601"
    echo "  DVWA Web App:      http://localhost:8080/dvwa"
    echo "  SSH to SIEM:       ssh -p 2222 user@localhost"
    echo "  SSH to Kali:       ssh -p 2223 kali@localhost"
    echo ""
    
    echo "Internal Network Access (from within VMs):"
    echo "  Domain Controller: 10.0.2.10 (Windows Server 2019)"
    echo "  Kali Attacker:     10.0.2.15 (Kali Linux)"
    echo "  SIEM System:       10.0.2.100 (Ubuntu + ELK)"
    echo "  Vulnerable Linux:  10.0.2.101 (Ubuntu)"
    echo "  Vulnerable Windows: 10.0.2.102 (Windows 10)"
    echo "  Web Server:        10.0.2.103 (Ubuntu + Apache)"
    echo ""
    
    echo "Default Credentials:"
    echo "  Ubuntu systems:    user: soc, pass: soclab123"
    echo "  Kali Linux:        user: kali, pass: kali"
    echo "  Windows systems:   user: Administrator, pass: P@ssw0rd123!"
    echo ""
}

# Start all VMs
start_all_vms() {
    log "Starting SOC Lab environment..."
    
    # Start VMs in order: Infrastructure -> Monitoring -> Targets -> Attackers
    local start_order=("Windows-DC" "ELK-SIEM" "Ubuntu-Vulnerable" "Web-Server" "Windows10-Vulnerable" "Kali-Attacker")
    
    for vm_name in "${start_order[@]}"; do
        if [[ -n "${VMS[$vm_name]}" ]]; then
            local vm_info="${VMS[$vm_name]}"
            local vm_type=$(echo "$vm_info" | cut -d',' -f1)
            local boot_delay=$(echo "$vm_info" | cut -d',' -f2)
            
            start_vm "$vm_name" "$vm_type" "$boot_delay"
        fi
    done
    
    log "All VMs started successfully"
}

# Stop all VMs
stop_all_vms() {
    log "Stopping SOC Lab environment..."
    
    # Stop VMs in reverse order: Attackers -> Targets -> Monitoring -> Infrastructure
    local stop_order=("Kali-Attacker" "Windows10-Vulnerable" "Web-Server" "Ubuntu-Vulnerable" "ELK-SIEM" "Windows-DC")
    
    for vm_name in "${stop_order[@]}"; do
        stop_vm "$vm_name"
    done
    
    # Wait for graceful shutdown
    info "Waiting for VMs to shut down gracefully..."
    sleep 30
    
    # Force stop any remaining running VMs
    for vm_name in "${stop_order[@]}"; do
        if vm_exists "$vm_name"; then
            local status=$(get_vm_status "$vm_name")
            if [[ "$status" == "running" ]]; then
                warn "Force stopping '$vm_name'"
                VBoxManage controlvm "$vm_name" poweroff
            fi
        fi
    done
    
    log "All VMs stopped"
}

# Restart all VMs
restart_all_vms() {
    log "Restarting SOC Lab environment..."
    stop_all_vms
    sleep 10
    start_all_vms
}

# Show help
show_help() {
    echo "SOC Lab Management Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start     Start all VMs in the correct order"
    echo "  stop      Stop all VMs gracefully"
    echo "  restart   Restart all VMs"
    echo "  status    Show current status of all VMs"
    echo "  info      Show lab access information"
    echo "  check     Check VM accessibility"
    echo "  help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start    # Start the entire lab"
    echo "  $0 status   # Check which VMs are running"
    echo "  $0 stop     # Stop all lab VMs"
    echo ""
}

# Main function
main() {
    local command="${1:-start}"
    
    # Pre-flight checks
    check_virtualbox
    
    case "$command" in
        "start")
            check_nat_network
            start_all_vms
            echo ""
            show_lab_status
            echo ""
            show_access_info
            echo ""
            info "Lab startup complete! VMs may take a few more minutes to fully initialize."
            ;;
        "stop")
            stop_all_vms
            echo ""
            show_lab_status
            ;;
        "restart")
            check_nat_network
            restart_all_vms
            echo ""
            show_lab_status
            ;;
        "status")
            show_lab_status
            ;;
        "info")
            show_access_info
            ;;
        "check")
            check_vm_accessibility
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            error "Unknown command: $command. Use '$0 help' for usage information."
            ;;
    esac
}

# Run main function with all arguments
main "$@"