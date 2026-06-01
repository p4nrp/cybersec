
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
<localfile>
 <location>Microsoft-Windows-Sysmon/Operational</location> <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
### 3. wazuh manager set
activate the log receiver to `<jsonout_output>yes</jsonout_output>`and `<alerts_log>yes</alerts_log>`
```
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>15m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
    <update_check>yes</update_check>
  </global>
```
create custom rule detection
```
nano /var/ossec/etc/rules/local_rules.xml
```
```
<group name="win-sysmon">

  <rule id="100502" level="2">
    <if_sid>92101</if_sid>
    <field name="win.system.eventID" type="pcre2">^3$</field>
    <field name="win.eventdata.image" type="pcre2">^C:\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$</field>
    <description>Network connection initiated by PowerShell (Normal/Internal)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <rule id="100503" level="13" frequency="5" timeframe="60">
    <if_matched_sid>100502</if_matched_sid>
    <description>SUSPICIOUS: Multiple network connections initiated by PowerShell (Possible Beaconing/C2)</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1071</id>
    </mitre>
  </rule>

  <rule id="100006" level="14">
    <if_sid>61603,92101</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
    <field name="win.eventdata.destinationPort" type="pcre2">^4444$</field>
    <description>ATTACK: Sysmon - PowerShell initiated network connection to malicious port 4444</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
  </rule>

  <rule id="100510" level="12">
    <if_sid>92101</if_sid>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)powershell\.exe$|cmd\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)whoami|hostname|net\s+user|net\s+localgroup|ipconfig|netstat|nltest|systeminfo|tasklist</field>
    <description>SUSPICIOUS: Reconnaissance Command Executed via Shell Parent (Possible Active Attacker)</description>
    <mitre>
      <id>T1033</id>
      <id>T1082</id>
      <id>T1016</id>
    </mitre>
  </rule>
  <rule id="100511" level="15">
    <if_matched_sid>100502</if_matched_sid>
    <if_sid>100510</if_sid>
    <description>CRITICAL ATTACK: Live Attacker Activity Detected Inside Reverse Shell Session!</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

</group>

<group name="powershell,malware,">

  <rule id="100999" level="0">
    <decoded_as>json</decoded_as>
    <field name="win.system.eventID">^4104$</field>
    <description>Bridge Logtest: PowerShell Script Block</description>
  </rule>

  <rule id="100020" level="0">
    <if_sid>92213</if_sid>
    <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\AppData\\Local\\Temp\\__PSScriptPolicyTest_.*\.ps1$</field>
    <description>False Positive: Filter Windows PowerShell Execution Policy Test Files</description>
  </rule>

  <rule id="100021" level="0">
    <if_sid>60009,91802,100999</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">^html$|^[\s\r\n]*$|(?i)get-executionpolicy</field>
    <description>False Positive: Filter Empty or Standard Execution Policy Query</description>
  </rule>

  <rule id="100003" level="7">
    <if_sid>60009,91802,91837,100999</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(Invoke-Expression|iex)</field>
    <description>Suspicious: PowerShell Invoke-Expression (iex) command detected</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
  <rule id="100001" level="9">
    <if_sid>60009,91802,91809,100999</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">FromBase64String</field>
    <description>Suspicious: PowerShell Base64 decoding method invocation</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
    </mitre>
  </rule>

  <rule id="100005" level="10">
    <if_sid>60009,91802,91809,100999</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?s)System\.Text\.Encoding.*Unicode.*FromBase64String|(?s)FromBase64String.*System\.Text\.Encoding.*Unicode</field>
    <description>Suspicious: PowerShell Obfuscated Unicode Base64 Command</description>
    <mitre>
      <id>T1027</id>
    </mitre>
  </rule>

  <rule id="100007" level="10">
    <if_sid>60009,91802,91809,100999</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">GetString\(.*0\.\.</field>
    <description>Suspicious: PowerShell Byte Array Manipulation</description>
    <mitre>
      <id>T1140</id>
    </mitre>
  </rule>

  <rule id="100009" level="14">
    <if_sid>60009,91802,91837,100999</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(iwr|Invoke-WebRequest|DownloadString).*(iex|Invoke-Expression)</field>
    <description>ATTACK: PowerShell In-Memory Script Download and Execution (Fileless Dropper)</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1105</id>
    </mitre>
  </rule>

  <rule id="100002" level="14">
    <if_sid>60009,91802,91809,100999</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">System\.Net\.Sockets\.TCPClient</field>
    <description>ATTACK: PowerShell Interactive Network Socket Created (Potential Reverse Shell)</description>
    <mitre>
      <id>T1071.001</id>
      <id>T1095</id>
    </mitre>
  </rule>
  <rule id="100004" level="15">
    <if_sid>60009,91802,91809,100999</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?s)System\.Net\.Sockets\.TCPClient.*GetStream</field>
    <description>CRITICAL ATTACK: PowerShell High Confidence Reverse Shell Active (TCPClient + GetStream)</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1071.001</id>
      <id>T1573</id>
    </mitre>
  </rule>

  <rule id="100008" level="15">
    <if_sid>60009,91802,91809,100999</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?s)System\.Net\.Sockets\.TCPClient.*FromBase64String.*GetStream|(?s)FromBase64String.*System\.Net\.Sockets\.TCPClient.*GetStream</field>
    <description>CRITICAL ATTACK: PowerShell Full Fileless Reverse Shell Exploit Executed</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1071.001</id>
      <id>T1027</id>
    </mitre>
  </rule>

</group>
```

### 4. Testing

<p align="center">
  <img height="auto" width="auto" src="https://imgur.com/a/jKaaWEQ"> \
</p>

<p align="center">
  <img height="auto" width="auto" src="https://imgur.com/a/1ELqUgS"> \
</p>

<p align="center">
  <img height="auto" width="auto" src="https://imgur.com/a/t0E0DT6"> \
</p>

<p align="center">
  <img height="auto" width="auto" src="https://imgur.com/a/t0E0DT6"> \
</p>

<p align="center">
  <img height="auto" width="auto" src="https://imgur.com/a/t0E0DT6"> \
</p>
