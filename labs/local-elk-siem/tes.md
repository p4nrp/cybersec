# SIEM Monitoring VM ELK Local

## VM Specifications
- **OS**: Ubuntu 20.04 LTS Server
- **RAM**: 8GB (minimum), 16GB (recommended)
- **Storage**: 100GB
- **Network**: Bridge (SOC-Lab-Network)
- **CPU**: 4 cores
- **IP Address**: 192.168.1.114 (static)

## Installation Steps

1. **Download Ubuntu Server ISO**
   - Download Ubuntu 20.04 LTS Server from official website

  
## Post-Installation Configuration

### 1. Initial System Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y curl wget gnupg2 software-properties-common apt-transport-https
sudo apt install -y net-tools htop vim git unzip
sudo apt install -y openjdk-11-jdk
```

### 2. Install Elasticsearch

```bash
# Add Elasticsearch repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Install Elasticsearch
sudo apt update
sudo apt install -y elasticsearch

# Configure Elasticsearch
sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<EOF
network.host: 0.0.0.0
http.port: 9200
EOF

# Enable and start Elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# And check elasticsearch is running or not
curl -X GET "localhost:9200"
or
curl -X GET "192.168.1.114:9200"

# Example  output
root@ubuntu-server:/home/pan# curl -X GET "localhost:9200"
{
  "name" : "FqiZn1S",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "sWF1wSQkTfqj4mkY8snkag",
  "version" : {
    "number" : "6.8.23",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "4f67856",
    "build_date" : "2022-01-06T21:30:50.087716Z",
    "build_snapshot" : false,
    "lucene_version" : "7.7.3",
    "minimum_wire_compatibility_version" : "5.6.0",
    "minimum_index_compatibility_version" : "5.0.0"
  },
  "tagline" : "You Know, for Search"
}

```

### 3. Install Logstash

```bash
# Install Logstash
sudo apt install -y logstash

# Create openssl
mkdir -p /etc/logstash/ssl
cd /etc/logstash/
openssl req -subj '/CN=elk-master/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout ssl/logstash-forwarder.key -out ssl/logstash-forwarder.crt
# Check folder openssl
ls ssl/


# Create Logstash configuration filebeat-input.conf
sudo tee /etc/logstash/conf.d/filebeat-input.conf > /dev/null <<EOF
input {  
beats {
   port => 5443
    type => syslog
    ssl => true
    ssl_certificate => "/etc/logstash/ssl/logstash-forwarder.crt"
    ssl_key => "/etc/logstash/ssl/logstash-forwarder.key"
  }
}
EOF

# Create Logstash configuration syslog-filter.conf
sudo tee /etc/logstash/conf.d/syslog-filter.conf > /dev/null <<EOF
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
EOF

# Create Logstash configuration output-elasticsearch.conf
sudo tee /etc/logstash/conf.d/output-elasticsearch.conf > /dev/null <<EOF
output {
  elasticsearch { hosts => ["localhost:9200"]
    hosts => "localhost:9200"
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
EOF

# Enable and start Logstash
systemctl start logstash
systemctl enable logstash
systemctl status logstash
```

### 4. Install Kibana

```bash
# Install Kibana
sudo apt install -y kibana

# Configure Kibana
sudo tee /etc/kibana/kibana.yml > /dev/null <<EOF
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
EOF

# Enable and start Kibana
systemctl enable kibana
systemctl start kibana
systemctl status kibana
```

### 5. Install Nginx for Kibana
```
# Install nginx
apt install nginx apache2-utils -y

#Create virtualhost
mkdir /etc/nginx/sites-available/kibana

#Config the host
sudo tee /etc/nginx/sites-available/kibana > /dev/null <<EOF
server {
    listen 80;
    server_name localhost;
    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/.kibana-user;
    location / {
        proxy_pass https://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF

#Create authentication for kibana dashoard username and password set
sudo htpasswd -c /etc/nginx/.kibana-user elastic

#Enable nginx
ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/
nginx -t
systemctl enable nginx
systemctl restart nginx

### 6. Configure Log Collection

#### Filebeat Configuration 
```bash
# add repo
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Update repo
apt update
# Install Filebeat
sudo apt install -y filebeat

# Configure Filebeat
sudo tee /etc/filebeat/filebeat.yml > /dev/null <<EOF
enabled: true
setup.kibana:
  host: "192.168.1.114:5601"
output.elasticsearch:
  hosts: ["192.168.1.114:9200"]
  username: "elastic"
  pasword: "admin"
EOF

# Enable and start Filebeat
sudo filebeat setup
sudo service filebeat start
sudo service filebeat status

#Copy SSL cert logstash
cp /etc/logstash/ssl/logstash-forwarder.crt /etc/filebeat/
sudo service filebeat restart

#Check Kibana is running or not
https://192.168.1.114:5601/
```

### 7. Routing Linux Logs to Elasticsearch

#### Routing From Logstash To Elasticsearch
```bash
# Routing From Logstash To Elasticsearch
sudo tee /etc/logstash/conf.d/logstash.conf > /dev/null <<EOF
input {
  udp {
    host => "127.0.0.1"
    port => 10514
    codec => "json"
    type => "rsyslog"
  }
} 
# The Filter pipeline stays empty here, no formatting is done.
filter { } 
# Every single log will be forwarded to ElasticSearch. If you are using another port, you should specify it here.
output {
  if [type] == "rsyslog" {
    elasticsearch {
      hosts => [ "127.0.0.1:9200" ]
    }
  }
}
EOF

#Restart logstash
systemctl restart logstash

#check the config is allready run on 127.0.0.1 on 10514
netstat -na | grep 10514
```
### 8. Routing from rsyslog to Logstash

#### Routing from rsyslog to Logstash
```
#Rsyslog has the capacity to transform logs using templates in order to forward logs in rsylog, head over to the directory /etc/rsylog.d and create a new file named 70-output.conf
sudo tee /etc/rsyslog.d/70-output.conf > /dev/null <<EOF
# This line sends all lines to defined IP address at port 10514
# using the json-template format.
*.*                         @127.0.0.1:10514;json-template
EOF

#log forwarding, create a 01-json-template.conf file in the same folder
sudo tee /etc/rsyslog.d/01-json-template.conf > /dev/null <<EOF
template(name="json-template"
  type="list") {
    constant(value="{")
      constant(value="\"@timestamp\":\"")     property(name="timereported" dateFormat="rfc3339")
      constant(value="\",\"@version\":\"1")
      constant(value="\",\"message\":\"")     property(name="msg" format="json")
      constant(value="\",\"sysloghost\":\"")  property(name="hostname")
      constant(value="\",\"severity\":\"")    property(name="syslogseverity-text")
      constant(value="\",\"facility\":\"")    property(name="syslogfacility-text")
      constant(value="\",\"programname\":\"") property(name="programname")
      constant(value="\",\"procid\":\"")      property(name="procid")
    constant(value="\"}\n")
}
EOF

#Restart rsyslog service and verify that logs are correctly forwarded into Elasticsearch.
systemctl restart rsyslog
curl -XGET 'http://localhost:9200/logstash-*/_search?q=*&pretty'
```

### 9. Create a Log Dashboard in Kibana

#### Create a Log Dashboard in Kibana
<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/ynoN0c8.png">
</p>

### we’ve defined logstash-* as our index pattern. Now we can specify some settings before we create it. In the field of time filter field name choose @timestamp and create an index pattern
<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/C6503eN.png">
</p>


### Monitoring example SSH entries
<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/CUdO0bU.png">
</p>




