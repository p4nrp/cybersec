Install Cloudflare-Gui-Warp on Kali Linux : 

Link 1: https://pkg.cloudflareclient.com/#debian
Link 2: https://github.com/ALIILAPRO/cloudflare-gui-warp

1. Open Terminal and copy and paste the following commands :

$ sudo su

$ sudo apt update

$ sudo apt upgrade

# Add cloudflare gpg key
$ curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg


# Add this repo to your apt repositories
$ echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ jammy main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list

# Install
$ sudo apt-get update && sudo apt-get install cloudflare-warp

$ warp-cli registration new

$ warp-cli connect

$ curl https://www.cloudflare.com/cdn-cgi/trace/

$ git clone https://github.com/ALIILAPRO/cloudflare-gui-warp

$ cd cloudflare-gui-warp

$ python warp-GUI.py
or
$ python3 warp-GUI.py

Credit: https://github.com/ALIILAPRO
