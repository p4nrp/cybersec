

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


### 2. install universal forwarder for Linux endpoint

Download universal forwarder from or check [THIS](https://www.splunk.com/en_us/download/universal-forwarder.html)
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
forward to splunk server 
```
sudo /opt/splunkforwarder/bin/splunk add forward-server <IP_SPLUNK_SERVER>:9997 -auth admin:<password>
```
add log path and send to be monitored by splunk server
```
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log
```
add receiving port 9997 on splunk server
start
```
/opt/splunkforwarder/bin/splunk start
```
