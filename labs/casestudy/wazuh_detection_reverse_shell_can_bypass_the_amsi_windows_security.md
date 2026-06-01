
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


### 2. windows endpoint install

Set windows agent using powershell 
```
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.1.142' WAZUH_AGENT_NAME='windowsvuln'   
```
start agent
```
NET START Wazuh
```

ossec.conf for edit congiguration path 
    ```
    C:\Program Files (x86)\ossec-agent\ossec.conf
    ```
Download sysmon.exe and symonconfig.xml  
```
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Users\panvmwin\Downloads\Sysmon.zip"
```
```
Invoke-WebRequest -Uri $ConfigUrl -OutFile "C:\Users\panvmwin\Downloads\sysmonconfig.xml"
```
install sysmon
```
.\Sysmon64.exe -i C:\Users\panvmwin\Downloads\sysmonconfig.xml -accepteula
```
set ossec.conf  
```
<!-- sysmon detect the network behavior -->
<localfile>
 <location>Microsoft-Windows-Sysmon/Operational</location> <log_format>eventchannel</log_format>
</localfile>

<!-- detect payload behavior -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```


