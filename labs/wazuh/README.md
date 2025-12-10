
### 1. Wazuh Manager installation

installation
```
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Check password dashboard
```
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Disable Wazuh Updates.
```
sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
apt update
```

check wazuh status
```
systemctl status wazuh-manager
```

Login wazuh dashboard using your machine ip address

<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/JFNqXrV.png"> \
</p>


### 2. Set windows agent

Set windows agent using powershell script 
```
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.1.142' WAZUH_AGENT_NAME='windowsvuln'   
```
start agent
```
NET START Wazuh
```

ossec.conf for edit ip 
    ```
    C:\Program Files (x86)\ossec-agent\ossec.conf
    ```

### 3. Set Linux agent

Set linux agent using this script 
``` 
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.1-1_amd64.deb && sudo WAZUH_MANAGER='192.168.1.142' WAZUH_AGENT_NAME='ubuntuvuln' dpkg -i ./wazuh-agent_4.14.1-1_amd64.deb
```
start agent
```
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Confirmation Agent Enrollment Successfull 

<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/rvNsrMs.png"> 
</p>

### 4. Set File integrity Monitoring on Wazuh Manager

```
nano /var/ossec/etc/ossec.conf
```

```
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
  </global>

  <!-- Rootcheck policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
  </rootcheck>

  <!-- Vulnerability Detection -->
  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <!-- FIM -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
  </syscheck>

  <!-- System Inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
  </wodle>
</ossec_config>

```

restart
```
systemctl restart wazuh-manager
```
### 5. Set File integrity Monitoring on Wazuh Agent

```
nano /var/ossec/etc/ossec.conf
```

```
<!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

<directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>
    <directories check_all="yes" realtime="yes">/home/pan/</directories>

    <directories check_all="yes" realtime="yes" report_changes="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">
    /bin,
    /boot,
    /dev,
    /lib,
    /lib64,
    /sbin,
    /usr/lib,
    /usr/local/bin,
    /usr/local/lib,
    /usr/local/sbin,
    /root/.ssh
    </directories>

    <directories check_all="yes" realtime="yes" restrict="^(\/dev|\/proc|\/sys)">/root</directories>

    <directories check_all="yes" realtime="yes">
    /var/log
    </directories>

```
restart wazuh agent 

```
systemctl restart wazuh-agent
```

confirmation log success

<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/IJTSBgu.png"> 
</p>

### 6. IDS Suricata on linux agent
Install suricata IDS
```
sudo add-apt-repository ppa:oisf/suricata-stable	
sudo apt-get update	
sudo apt-get install suricata -y
```
Download and extract Threat suricata ruleset
```
cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz sudo tar -xvzf emerging-rules.tar.gz && sudo mv rules/* rules /etc/suricata/rules/	
sudo chmod 640 /etc/suricata/rules/* rules
```

Edit suricata .yaml
```
nano /etc/suricata/suricata.yaml
```

```
HOME_NET: "<UBUNTU_IP>"	
EXTERNAL_NET: "any"	
default-rule-path: /etc/suricata/rules	
rule-files:	
- "*_rules"	

# Global stats configuration	
stats:	
enabled: Yes	

# Linux high speed capture support	
af-packet:	
- interface: ethe
```

Restart suricata 
```
systemctl restart suricata
```

Integration Suricata logs to Wazuh agent
```
nano /etc/var/ossec/etc/ossec.conf
```
add this 
```
<localfile>	
<log_format>json</log_format>	
<location>/var/log/suricata/eve.json</location>	
</localfile>
```
restart agent
```
systemctl restart wazuh-agent
```
