# IP - TTL Exchange Challenge

### 1. IP - TTL Exchange Challenge
   <p align="center">
   <p align="left">
   <img height="auto" width="auto" src="https://i.imgur.com/xG1eKVt.png">
   </p>

### 2. Lets Analyze the ICMP Packet Exchange using Wireshark
1. This The Packet 
   <p align="center">
   <p align="left">
   <img height="auto" width="auto" src="https://i.imgur.com/gkigK6w.png">
   </p>

2. As we see on screenshot number one before, the packet ICMP and have TTL connection success is just on packet number `71 to 76`
   <p align="center">
   <p align="left">
   <img height="auto" width="auto" src="https://i.imgur.com/7GKX0Wm.png">
   </p>

3. Lets try to hashing to md-5, with a hint we got, such as `6sK0_` on the first word, and use salt of encrypted enable password `p8Y6`

   `openssl passwd -1 -salt p8Y6 6sK0_enable`

<p align="left">
<img height="auto" width="auto" src="https://i.imgur.com/0cDIHYm.png">
</p>

### 3. Conclusion
### the password for user enable is `6sK0_enable`

