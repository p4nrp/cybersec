# Install a ArtilleryHoneyPots


<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/N9KAUN8.png">
</p>


* [Installation](https://github.com/p4nrp/cybersec/blob/main/ArtilleryHoneyPots.md#1-installation-1)
* [Setting DockerFile](https://github.com/p4nrp/cybersec/blob/main/ArtilleryHoneyPots.md#2-setting-dockerfile)
* [Start Your Validator](https://github.com/p4nrp/cybersec/blob/main/ArtilleryHoneyPots.md#3-start-your-validator)
* [Usefull Command](https://github.com/p4nrp/cybersec/blob/main/ArtilleryHoneyPots.md#usefull-commands)


### 1. Installation

Install Python3 
```
apt install python3
```

clone the official github
```
git clone https://github.com/BinaryDefense/artillery.git
```

Setup
```
python3 setup.py
```

Config 
```
nano /var/artitlery/config
```

Make sure you are about to install from the Docker repo instead of the default Ubuntu repo:
```
apt-cache policy docker-ce
```

Install Docker
```
sudo apt install docker-ce
```
Install docker with bash
```

```

### 2. Setting DockerFile

Download dockerfile from elixir finance
```
wget https://files.elixir.finance/Dockerfile
```

Edit file DockerFile with your address and your private key
```
nano DockerFile
```

Build DockerFile image
```
docker build . -f Dockerfile -t elixir-validator
```

### 3. Start Your Validator
Run the validator by executing the following docker command: 
```
docker run -it --name ev elixir-validator
```
Optionally, you can configure the the validator to automatically run at startup:
```
docker run -d --restart unless-stopped --name ev elixir-validator
```
Your validator should start up in 20 seconds and begin submitting order proposals to the network.


# Usefull commands
check docker available running
```
docker ps
```

check docker logs realtime run
```
docker logs -f machinename
```

Upgrading Node 
```
docker kill ev
docker rm ev
docker pull elixirprotocol/validator:testnet-2
docker build . -f Dockerfile -t elixir-validator
```



