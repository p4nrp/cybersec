
### 1. Wazuh installation

installation
```
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Check password dashboard
```
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```




### 2. Set windows agent
1. Download windows agent [Windows_Installer](https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi)
   

2. ossec.conf for edit ip 
    ```
    C:\Program Files (x86)\ossec-agent\ossec.conf
    ```

### 3. Conclusion
### the password for user "enable" is `6sK0_enable`

