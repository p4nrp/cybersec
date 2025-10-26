# Cisco Type 7 Challenge

* [Installation Docker](https://github.com/p4nrp/testnet/blob/main/taiko.md#1-Installation-Docker)
* [Alchemy Setting](https://github.com/p4nrp/testnet/blob/main/taiko.md#2-Alchemy-Setting)
* [Setup And Run Node](https://github.com/p4nrp/testnet/blob/main/taiko.md#3-Setup-And-Run-Node)
* [Monitor Node](https://github.com/p4nrp/testnet/blob/main/taiko.md#4-Monitor-Node)
* [Usefull Command](https://github.com/p4nrp/testnet/blob/main/taiko.md#usefull-commands)

### 1. Installation Docker

Install docker 
install a few prerequisite packages which let apt use packages over HTTPS:

<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/DB4IQDJ.png">
</p>
https://i.imgur.com/DB4IQDJ.png

```
sudo apt install apt-transport-https ca-certificates curl software-properties-common
```

add the GPG key for the official Docker repository to your system:
```
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
```

add the Docker repository to APT sources:
```
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

Update your existing list of packages again for the addition to be recognized:
```
sudo apt update
```

Make sure you are about to install from the Docker repo instead of the default Ubuntu repo:
```
apt-cache policy docker-ce
```

Install Docker
```
sudo apt install docker-ce
```

### 2. Alchemy Setting
1. Create [AlchemyAccount](https://auth.alchemy.com/signup?redirectUrl=https%3A%2F%2Fdashboard.alchemy.com%2Fsignup%2F%3Freferrer_origin%3DDIRECT)
2. Select `+CREATE NEW APP`
3. Define name apps
4. Network Use Sepolia
5. `CREATE APP`
6. Navigate to apps already created `VIEW DETAILS`
7. Select `VIEW KEY`
8. Copy HTTP & WSS

### 3. Setup And Run Node
1. Download Node
   ```
   git clone https://github.com/taikoxyz/simple-taiko-node.git
   ```
3. To Directory simple-taiko-node
   ```
   cd simple-taiko-node
   ```
4. Copy .env
   ```
   cp .env.sample .env
   ```
3. Edit .env
   ```
   nano .env
   ```
   Change value `L1_ENDPOINT_HTTP` and `L1_ENDPOINT_WS` with your HTTPS And WSS From Alchemy

   Change Value `ENABLE_PROVER` to `true`
   
   Change Value `L1_PROVER_PRIVATE_KEY` with your private key from metamask (new wallet)
   
   Save file CTRL + x + Y + enter
   
4. Update Node
   ```
   docker compose pull
   ```
5. Run Node
   ```
   docker compose up -d
   ```
6. Check log
   ```
   docker compose logs -f 
   ```
   or use
   ```
   docker ps
   ```
   ```
   docker inspect CONTAINER_NAME | grep log
   ```
   ```
   tail -f
   ```
   ```
   cd LOG_FOLDER
   ```
   file -i .log
   The files type: "application/octet-stream; charset=binary" have errors, can be RENAMED/REMOVED/UPDATED for fix.
   ```
8. Cek log for block approval
   ```
   docker compose logs -f | grep "💰 Your block proof was accepted"
   ```
   
### 4. Monitor Node

A node dashboard will be running on `localhost` on the `GRAFANA_PORT` you set in your `.env` or `.env.l3` file. For a Grimsvotn L2 node that would default to: 
```
http://localhost:3001/d/L2ExecutionEngine/l2-execution-engine-overview
```
