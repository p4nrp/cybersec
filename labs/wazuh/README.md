 Cisco Type 7 Challenge
### 1. Wazuh installation

installation
```
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Check password dashboard
```
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```




### 2. Install windows agent
1. Download windows agent [Windows_Installer](https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi)
    > enable secret 5 $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0. (md-5 crypt) 
      `Try cracking using hashcat first, is if it fail to cracked, should we gather another hint again`   
    >  
    As we know here this is a `md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5) 2` and have an salt `p8Y6`

2. Lets try to decrypt cisco type 7 password of `admin` `hub` `guest` user.
   > We can use this repo to decrypt it: [c7_decrypt](https://github.com/derek-shnosh/c7_decrypt)
   > - Example command
   >
   >
   > ```bash
   > python3 c7_decrypt.py -s 10181A325528130F010D24
   > ```
   >
   **This the output we got :**
   <p align="left">
   <img height="auto" width="auto" src="https://i.imgur.com/6p0Z51i.png">
   </p>

   - **admin  :** `6sK0_admin`
   - **hub    :** `6sK0_hub`
   - **guest  :** `6sK0_guest`
   >
   > we got a hint here, the every password of user is using `6sK0_` on the first word
   >
3. Lets try to hashing to md-5 crypt, with a hint we got before, such as `6sK0_` on the first word, and use salt of encrypted enable password before `p8Y6`

   `openssl passwd -1 -salt p8Y6 6sK0_enable`

   <p align="left">
   <img height="auto" width="auto" src="https://i.imgur.com/0cDIHYm.png">
   </p>

### 3. Conclusion
### the password for user "enable" is `6sK0_enable`

