# Splunk SOAR Installation and Configuration on Ubuntu Server

## Lab Setup & Requirements

- VirtualBox/VMware Workstation  
- Ubuntu Server VM with at least 8 vCPUs, 16 GB RAM, 100 GB disk  

---

## Step 1: Update the System
```
sudo apt update -y
sudo apt upgrade -y
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
During this process:

- Install prerequisite DEB packages equivalent to the RPMs for Ubuntu. The script might need editing or manual installation for any missing dependencies.

Common packages you might need to manually install on Ubuntu (before running `./soar-prepare-system`) include:
```
sudo apt install -y python3 python3-pip python3-venv ntp ntpdate libffi-dev libssl-dev build-essential git
```
- For **GlusterFS**, install if clustering and using external file shares:
```
sudo apt install -y glusterfs-server
```
- For **ntpd**, enable and start the service:
```
sudo systemctl enable ntp
sudo systemctl start ntp
```
- Create a **non-privileged user** for running Splunk SOAR:
```
sudo adduser --system --group phantom
```
- Set password if prompted and configure file descriptor limits for that user by editing `/etc/security/limits.conf` or similar mechanism.
---

## Step 5: Install Splunk SOAR

Run the installation script (as the non-privileged user or using sudo depending on the mode):
```
sudo ./soar-install
```
## Step 6: Access the Web Interface

Open a browser and navigate to:
```
https://<ip-address-or-hostname>:<custom-https-port>
```

- Default username: `soar_local_admin`  
- Default password: `password`  

---

## Conclusion
By following the above steps adjusted for Ubuntu, you create a Splunk SOAR platform for security automation and incident response. This forms the base for integrating with SIEMs, firewalls, and other security tools in an Ubuntu environment.
---

## Additional Notes
- The package is built for EL7 (CentOS7) but the unprivileged install may work on Ubuntu with manual dependency resolution.
- Verify dependencies manually if `./soar-prepare-system` fails on Ubuntu.
- Adjust any scripts or steps referring to `yum` or `systemctl` in ways specific to Ubuntu (`apt`, `systemctl` commands).
- Review official Splunk SOAR documentation for Ubuntu-specific support or newer packages.
- If needed, help can be provided to create or adapt installation scripts to automate this process for Ubuntu.
