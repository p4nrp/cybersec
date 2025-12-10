
### 1. Wazuh installation

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
 


