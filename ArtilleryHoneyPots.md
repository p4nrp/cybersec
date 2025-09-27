# Install a ArtilleryHoneyPots


<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/N9KAUN8.png">
</p>


* [Installation](https://github.com/p4nrp/testnet/blob/main/ArtilleryHoneyPots.md#1-installation-1)
* [Setting DockerFile](https://github.com/p4nrp/testnet/blob/main/ArtilleryHoneyPots.md#2-setting-dockerfile)
* [Start Your Validator](https://github.com/p4nrp/testnet/blob/main/ArtilleryHoneyPots.md#3-start-your-validator)
* [Usefull Command](https://github.com/p4nrp/testnet/blob/main/ArtilleryHoneyPots.md#usefull-commands)


### 1. Installation

Install docker 
install a few prerequisite packages which let apt use packages over HTTPS:

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



