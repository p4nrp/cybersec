

### 1. Splunk Install

Download splunk
```
wget https://fdn.digiboy.ir/dlir-s3/splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb
```

Installation
```
dpkg -i splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb
```

move to folder installation and Check installation successful or not 
```
cd /opt/splunk/bin/
```

start splunk and configure
```
./splunk start
```


after configure success stop splunk first to change bind ip to 0.0.0.0
```
cd /opt/splunk/bin/
./splunk stop
```

edit splunk config `nano /opt/splunk/etc/splunk-launch.conf`
```
SPLUNK_BINDIP=0.0.0.0
```

start splunk again navigate to `cd /opt/splunk/bin/`
```
./splunk start
```

Access splunk dashboard
```
http://192.168.1.77:8000/
```

<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/WD14Xi4.png"> \
</p>


### 2. install and configure universal forwarder for Linux endpoint

Download universal forwarder [THIS](https://www.splunk.com/en_us/download/universal-forwarder.html)
```
wget -O splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb "https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb"
```

Install it 
```
dpkg -i splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb
```

accept license
```
sudo /opt/splunkforwarder/bin/splunk start --accept-license
```
forward to splunk server (splunk indexer)
```
sudo /opt/splunkforwarder/bin/splunk add forward-server <IP_SPLUNK_SERVER>:9997 -auth admin:<password>

EX: /opt/splunkforwarder/bin/splunk add forward-server 172.27.54.188:9997-auth admin:password
```

Configure the universal forwarder to connect to a deployment server
```
/opt/splunkforwarder/bin/splunk set deploy-poll <host name or ip address>:<management port>

EX : /opt/splunkforwarder/bin/splunk set deploy-poll 172.27.54.188:8089 -auth admin:password
```

add log path that will be monitored
```
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -auth admin:password
```
universal forwarder start
```
/opt/splunkforwarder/bin/splunk start
```
universal forwarder restart
```
/opt/splunkforwarder/bin/splunk restart
```

Enable Receiving on the Splunk Server
```
Log in to your Splunk Web UI (172.27.54.188:8000).

Go to Settings > Forwarding and receiving.

In the Receive data section, click + Add New.

Enter 9997 in the "Listen on this port" box.

Click Save.
```

verify the ubuntu server connection is established
```
netstat -ant | grep 9997
```

try tou query 
```
index=* host="ubuntu-server" source="/var/log/auth.log"
```

Check 

```
cd /opt/splunkforwarder/etc/system/local
```
3. install and configure universal forwarder for Linux endpoint

Download universal forwarder [THIS](https://www.splunk.com/en_us/download/universal-forwarder.html)

