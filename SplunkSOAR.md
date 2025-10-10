# Splunk SOAR Installation and Configuration on Ubuntu Server

## Lab Setup & Requirements

- VirtualBox/VMware Workstation  
- Ubuntu Server VM with at least 8 vCPUs, 16 GB RAM, 100 GB disk  

---

## Step 1: Update the System
```
sudo apt-get update -y
sudo apt-get upgrade -y
```
## Step 2: Download the Phantom Package
Download the Splunk SOAR package for Linux (CentOS/RHEL packages may work on Ubuntu for unprivileged install, but verify compatibility):
```
wget -O splunk_soar-unpriv-6.2.1.305-7c40b403-el7-x86_64.tgz "https://download.splunk.com/products/splunk_soar-unpriv/releases/6.2.1/linux/splunk_soar-unpriv-6.2.1.305-7c40b403-el7-x86_64.tgz"
```
## Step 3: Extract the Package
Create the installation directory and extract:
```
sudo mkdir -p /opt/phantom
sudo tar -xzvf ./splunk_soar-unpriv-6.2.1.305-7c40b403-el7-x86_64.tgz -C /opt/phantom
```
## Step 4: Prepare the System for Installation
Run the provided system preparation script as root or with sudo:
```
cd /opt/phantom
sudo ./soar-prepare-system
```
