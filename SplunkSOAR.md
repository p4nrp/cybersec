# Splunk SOAR Installation and Configuration on CentOS 10 Stream

## Lab Setup & Requirements

- VirtualBox/VMware Workstation  
- CentOS Stream 10 VM with at least 8 vCPUs, 16 GB RAM, 100 GB disk  

---

## Step 1: Update the System
```
sudo dnf update -y
sudo dnf upgrade -y
```
## Step 2: Download the Phantom Package
Download the Splunk SOAR package for Linux (the EL7 package generally works on CentOS 10 Stream for unprivileged installation, but verify compatibility):
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
if error `Unable to read CentOS/RHEL version from /etc/redhat-release.` fix it like 
```
sudo sh -c 'echo "CentOS Stream release 10" > /etc/redhat-release'
```

NOTE
- `Install pre-requisite RPM packages required by Splunk SOAR (Y/n): If prompted, you must answer Y to proceed.`:  If prompted, you must answer Y to proceed.
- `GlusterFS is only needed if you are using an external file share. This is common if you're constructing a Splunk SOAR cluster. Do you want to run this step? (Y/n)` : You only need to answer Y if you are setting up certain cluster - -
- `configurations of Splunk SOAR (On-premises)`, : but you can answer Y even on individual instances.
- `Enable the ntpd service to guarantee clock synchronization. Do you want to run this step? (Y/n)`: Answer Y.
- `Create a non-privileged user for running Splunk SOAR (On-premises). (Y/n)`:  If prompted, you must answer Y to proceed.
- `Do you want to set a password for <non-privileged_user> now? (Y/n)`:  Answer Y if you created a non-privileged user for running Splunk SOAR (On-premises) in the previous step.
- `Set system resource limits for Splunk SOAR user, particularly file descriptor limits, which are low by default. (Y/n)`: Answer Y.

During this process:

- Install prerequisite **RPM** packages for CentOS.  
  If the script fails due to missing dependencies, install them manually using:
```
sudo dnf install -y python3 python3-pip python3-virtualenv ntp ntpdate
libffi-devel openssl-devel gcc gcc-c++ make git
```

- For **GlusterFS**, install if clustering and using external file shares:
```
sudo dnf install -y glusterfs-server
sudo systemctl enable glusterd
sudo systemctl start glusterd
```
- For **ntpd**, enable and start the service:
```
sudo systemctl enable ntpd
sudo systemctl start ntpd
```
- Create a **non-privileged user** for running Splunk SOAR:
```
sudo adduser --system --group phantom
```
- Optionally set a password and configure file descriptor limits for that user:
```
sudo passwd phantom
sudo bash -c 'echo "phantom hard nofile 65535" >> /etc/security/limits.conf'
sudo bash -c 'echo "phantom soft nofile 65535" >> /etc/security/limits.conf'
```
---

## Step 5: Install Splunk SOAR
Run the installation script (as the non-privileged user or using sudo depending on the mode):
```
sudo ./soar-install
```

## Step 6: Enable and Start the Service
After installation, enable and start the SOAR service:
```
sudo systemctl enable phantom
sudo systemctl start phantom
```
Check the service status:
```
sudo systemctl status phantom
```

## Step 7: Access the Web Interface
Open a browser and navigate to:
```
https://<ip-address-or-hostname>:<custom-https-port>
```

- Default username: `soar_local_admin`  
- Default password: `password`  

---

## Step 8: Configure Firewall (Optional)
If `firewalld` is active, allow HTTPS access:
```
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

---

## Conclusion
By following the above steps for CentOS 10 Stream, you create a Splunk SOAR platform for security automation and incident response.  
This forms the foundation for integrating with SIEMs, firewalls, and other cybersecurity tools in a CentOS environment.

---

## Additional Notes
- The package is originally built for **EL7 (CentOS 7)** but works on CentOS Stream 10 with minor manual dependency resolution.  
- Verify dependencies manually if `./soar-prepare-system` fails.  
- Adjust any scripts or steps referring to `yum` or Ubuntu commands (`apt`) to their CentOS equivalents (`dnf`).  
- Review official [Splunk SOAR Documentation](https://docs.splunk.com/Documentation/SOAR) for updates or new versions.  
- If desired, you can automate these steps via a Bash installation script for streamlined deployment.
