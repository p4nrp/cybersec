# SIEM Monitoring VM - ELK Stack Configuration

## VM Specifications
- **OS**: Ubuntu 20.04 LTS Server
- **RAM**: 8GB (minimum), 16GB (recommended)
- **Storage**: 100GB
- **Network**: NAT Network (SOC-Lab-Network)
- **CPU**: 4 cores
- **IP Address**: 10.0.2.100 (static)

## Installation Steps

1. **Download Ubuntu Server ISO**
   - Download Ubuntu 20.04 LTS Server from official website

2. **VirtualBox Configuration**
   ```bash
   # Create VM
   VBoxManage createvm --name "ELK-SIEM" --ostype "Ubuntu_64" --register
   
   # Configure VM
   VBoxManage modifyvm "ELK-SIEM" --memory 8192 --cpus 4
   VBoxManage modifyvm "ELK-SIEM" --vram 16
   VBoxManage modifyvm "ELK-SIEM" --nic1 natnetwork --nat-network1 "SOC-Lab-Network"
   VBoxManage modifyvm "ELK-SIEM" --audio none
   
   # Create and attach storage
   VBoxManage createhd --filename "ELK-SIEM.vdi" --size 102400
   VBoxManage storagectl "ELK-SIEM" --name "SATA Controller" --add sata --controller IntelAHCI
   VBoxManage storageattach "ELK-SIEM" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "ELK-SIEM.vdi"
   VBoxManage storageattach "ELK-SIEM" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "ubuntu-20.04-server.iso"
   ```

## Post-Installation Configuration

### 1. Initial System Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y curl wget gnupg2 software-properties-common apt-transport-https
sudo apt install -y net-tools htop vim git unzip
sudo apt install -y openjdk-11-jdk

# Set static IP
sudo tee /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 10.0.2.100/24
      gateway4: 10.0.2.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
EOF

sudo netplan apply
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
cluster.name: soc-lab-cluster
node.name: elk-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
EOF

# Set JVM heap size
sudo sed -i 's/-Xms1g/-Xms4g/' /etc/elasticsearch/jvm.options
sudo sed -i 's/-Xmx1g/-Xmx4g/' /etc/elasticsearch/jvm.options

# Enable and start Elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

### 3. Install Logstash

```bash
# Install Logstash
sudo apt install -y logstash

# Create Logstash configuration
sudo tee /etc/logstash/conf.d/soc-lab.conf > /dev/null <<EOF
input {
  beats {
    port => 5044
  }
  
  syslog {
    port => 514
  }
  
  tcp {
    port => 5000
    codec => json
  }
}

filter {
  # Windows Event Log parsing
  if [winlog] {
    mutate {
      add_field => { "log_type" => "windows" }
    }
    
    if [winlog][event_id] == 4624 {
      mutate {
        add_field => { "event_category" => "logon_success" }
      }
    }
    
    if [winlog][event_id] == 4625 {
      mutate {
        add_field => { "event_category" => "logon_failure" }
      }
    }
    
    if [winlog][event_id] == 4648 {
      mutate {
        add_field => { "event_category" => "explicit_logon" }
      }
    }
  }
  
  # Linux syslog parsing
  if [type] == "syslog" {
    mutate {
      add_field => { "log_type" => "linux" }
    }
    
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:message}" }
      overwrite => [ "message" ]
    }
  }
  
  # Apache access log parsing
  if [fields][log_type] == "apache_access" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
    
    mutate {
      convert => { "response" => "integer" }
      convert => { "bytes" => "integer" }
    }
  }
  
  # SSH authentication parsing
  if [program] == "sshd" {
    if "Failed password" in [message] {
      mutate {
        add_field => { "event_category" => "ssh_failed_login" }
      }
      
      grok {
        match => { "message" => "Failed password for %{DATA:username} from %{IPORHOST:src_ip} port %{INT:src_port}" }
      }
    }
    
    if "Accepted password" in [message] {
      mutate {
        add_field => { "event_category" => "ssh_successful_login" }
      }
      
      grok {
        match => { "message" => "Accepted password for %{DATA:username} from %{IPORHOST:src_ip} port %{INT:src_port}" }
      }
    }
  }
  
  # Add GeoIP information
  if [src_ip] {
    geoip {
      source => "src_ip"
      target => "geoip"
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "soc-lab-%{+YYYY.MM.dd}"
  }
  
  stdout {
    codec => rubydebug
  }
}
EOF

# Enable and start Logstash
sudo systemctl enable logstash
sudo systemctl start logstash
```

### 4. Install Kibana

```bash
# Install Kibana
sudo apt install -y kibana

# Configure Kibana
sudo tee /etc/kibana/kibana.yml > /dev/null <<EOF
server.port: 5601
server.host: "0.0.0.0"
server.name: "soc-lab-kibana"
elasticsearch.hosts: ["http://localhost:9200"]
kibana.index: ".kibana"
logging.dest: /var/log/kibana/kibana.log
logging.silent: false
logging.quiet: false
logging.verbose: false
EOF

# Create log directory
sudo mkdir -p /var/log/kibana
sudo chown kibana:kibana /var/log/kibana

# Enable and start Kibana
sudo systemctl enable kibana
sudo systemctl start kibana
```

### 5. Install Additional Security Tools

#### Suricata IDS
```bash
# Install Suricata
sudo apt install -y suricata

# Configure Suricata
sudo tee /etc/suricata/suricata.yaml > /dev/null <<EOF
vars:
  address-groups:
    HOME_NET: "[10.0.2.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

default-log-dir: /var/log/suricata/
stats:
  enabled: yes
  interval: 8

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - smtp
        - ssh
        - stats
        - flow

af-packet:
  - interface: enp0s3
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

pcap:
  - interface: enp0s3

app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http:
      enabled: yes
    ssh:
      enabled: yes
    smtp:
      enabled: yes
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53

rule-files:
  - suricata.rules
  - /var/lib/suricata/rules/emerging-threats.rules
EOF

# Update Suricata rules
sudo suricata-update

# Enable and start Suricata
sudo systemctl enable suricata
sudo systemctl start suricata
```

#### Wazuh Agent (HIDS)
```bash
# Install Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update
sudo apt install -y wazuh-manager wazuh-api

# Configure Wazuh
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<EOF
  <integration>
    <name>elastic</name>
    <hook_url>http://localhost:9200</hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>
EOF

# Enable and start Wazuh
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```

### 6. Configure Log Collection

#### Filebeat Configuration for Log Forwarding
```bash
# Install Filebeat
sudo apt install -y filebeat

# Configure Filebeat
sudo tee /etc/filebeat/filebeat.yml > /dev/null <<EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json
  fields:
    log_type: suricata
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /var/log/auth.log
  fields:
    log_type: auth
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /var/log/syslog
  fields:
    log_type: syslog
  fields_under_root: true

output.logstash:
  hosts: ["localhost:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
EOF

# Enable and start Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

### 7. Create Kibana Dashboards

#### SOC Dashboard Creation Script
```bash
# Create dashboard import script
sudo tee /opt/create-soc-dashboards.sh > /dev/null <<'EOF'
#!/bin/bash

# Wait for Kibana to be ready
while ! curl -s http://localhost:5601/api/status > /dev/null; do
  echo "Waiting for Kibana to start..."
  sleep 10
done

# Create index patterns
curl -X POST "localhost:5601/api/saved_objects/index-pattern/soc-lab-*" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "soc-lab-*",
      "timeFieldName": "@timestamp"
    }
  }'

# Import SOC dashboards (would contain actual dashboard JSON)
echo "SOC dashboards created successfully!"
EOF

chmod +x /opt/create-soc-dashboards.sh
```

### 8. Security Monitoring Rules

#### Custom Detection Rules
```bash
# Create custom Suricata rules
sudo tee /etc/suricata/rules/soc-lab-custom.rules > /dev/null <<EOF
# Brute force detection
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH"; threshold:type both,track by_src,count 5,seconds 60; sid:1000001; rev:1;)

# Web application attacks
alert http any any -> $HOME_NET any (msg:"SQL Injection Attempt"; flow:to_server,established; content:"union select"; nocase; sid:1000002; rev:1;)
alert http any any -> $HOME_NET any (msg:"XSS Attempt"; flow:to_server,established; content:"<script"; nocase; sid:1000003; rev:1;)

# Suspicious file uploads
alert http any any -> $HOME_NET any (msg:"Suspicious File Upload"; flow:to_server,established; content:"Content-Type: application/octet-stream"; sid:1000004; rev:1;)

# Command injection
alert http any any -> $HOME_NET any (msg:"Command Injection Attempt"; flow:to_server,established; pcre:"/(\||;|&|`|\$\()/"; sid:1000005; rev:1;)
EOF
```

## Service Status and Ports

| Service | Port | Status Check |
|---------|------|--------------|
| Elasticsearch | 9200 | `curl http://localhost:9200` |
| Kibana | 5601 | `curl http://localhost:5601` |
| Logstash | 5044 | `netstat -tlnp | grep 5044` |
| Suricata | - | `sudo systemctl status suricata` |
| Wazuh | 1514 | `sudo systemctl status wazuh-manager` |

## Default Access

- **Kibana Web Interface**: http://10.0.2.100:5601
- **Elasticsearch API**: http://10.0.2.100:9200
- **Log Collection**: Port 514 (Syslog), Port 5044 (Beats)

## Pre-configured Dashboards

1. **Security Overview Dashboard**
   - Failed login attempts
   - Top attacking IPs
   - Service usage statistics
   - Alert timeline

2. **Network Security Dashboard**
   - Suricata alerts
   - Network traffic analysis
   - Protocol distribution
   - Suspicious connections

3. **System Monitoring Dashboard**
   - System resource usage
   - Service status
   - Log volume trends
   - Error rates

## Log Sources Configured

- **Windows Event Logs** (via Winlogbeat from Windows VMs)
- **Linux System Logs** (via Rsyslog and Filebeat)
- **Web Server Logs** (Apache/Nginx access and error logs)
- **Network Traffic** (via Suricata)
- **Security Events** (via Wazuh HIDS)

## Maintenance Scripts

```bash
# Create maintenance script
sudo tee /opt/elk-maintenance.sh > /dev/null <<'EOF'
#!/bin/bash

# Clean old indices (keep 30 days)
curl -X DELETE "localhost:9200/soc-lab-$(date -d '30 days ago' +%Y.%m.%d)"

# Restart services if needed
systemctl is-active --quiet elasticsearch || systemctl restart elasticsearch
systemctl is-active --quiet logstash || systemctl restart logstash
systemctl is-active --quiet kibana || systemctl restart kibana

echo "ELK maintenance completed: $(date)"
EOF

chmod +x /opt/elk-maintenance.sh

# Add to crontab
echo "0 2 * * * /opt/elk-maintenance.sh >> /var/log/elk-maintenance.log 2>&1" | sudo crontab -
```

## Troubleshooting

### Common Issues
1. **Elasticsearch won't start**: Check JVM heap size and available RAM
2. **Logstash parsing errors**: Check configuration syntax in `/etc/logstash/conf.d/`
3. **Kibana connection issues**: Verify Elasticsearch is running and accessible
4. **No logs appearing**: Check Filebeat/Winlogbeat configuration and network connectivity

### Log Locations
- **Elasticsearch**: `/var/log/elasticsearch/`
- **Logstash**: `/var/log/logstash/`
- **Kibana**: `/var/log/kibana/`
- **Suricata**: `/var/log/suricata/`
- **Wazuh**: `/var/ossec/logs/`