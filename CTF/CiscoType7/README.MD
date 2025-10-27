# Cisco Type 7 Challenge

* [.](https://github.com/p4nrp/testnet/blob/main/taiko.md#1-Installation-Docker)
* [.](https://github.com/p4nrp/testnet/blob/main/taiko.md#2-Alchemy-Setting)
* [.](https://github.com/p4nrp/testnet/blob/main/taiko.md#3-Setup-And-Run-Node)
* [.](https://github.com/p4nrp/testnet/blob/main/taiko.md#4-Monitor-Node)
* [.](https://github.com/p4nrp/testnet/blob/main/taiko.md#usefull-commands)

### 1. Installation Docker

Install docker 
install a few prerequisite packages which let apt use packages over HTTPS:

<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/DB4IQDJ.png">
</p>


lets analyze the log given
```
!
! Last configuration change at 13:41:43 CET Mon Jul 8 2013 by admin
! NVRAM config last updated at 11:15:05 CET Thu Jun 13 2013 by admin
!
version 12.2
no service pad
service password-encryption
!
isdn switch-type basic-5ess
!
hostname rmt-paris
!
security passwords min-length 8
no logging console
enable secret 5 $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0.
!
username hub password 7 025017705B3907344E 
username admin privilege 15 password 7 10181A325528130F010D24
username guest password 7 124F163C42340B112F3830
!
!
ip ssh authentication-retries 5
ip ssh version 2
!
interface BRI0/0
 ip address 192.168.1.2 255.255.255.0
 no ip directed-broadcast
 encapsulation ppp
 dialer map ip 192.168.1.1 name hub broadcast 5772222
 dialer-group 1
 isdn switch-type basic-5ess
 ppp authentication chap callin
 no shutdown
!
!
interface GigabitEthernet1/15
 ip address 192.168.2.1 255.255.255.0
 no shutdown
!
router bgp 100
 no synchronization
 bgp log-neighbor-changes
 bgp dampening
 network 192.168.2.0 mask 255.255.255.0
 timers bgp 3 9
 redistribute connected
!
ip classless
ip route 0.0.0.0 0.0.0.0 192.168.1.1
!
!
access-list 101 permit ip any any
dialer-list 1 protocol ip list 101
!
no ip http server
no ip http secure-server
!
line con 0
 password 7 144101205C3B29242A3B3C3927
 session-timeout 600
line vty 0 4
 session-timeout 600
 authorization exec SSH
 transport input ssh
```

We found many password is encrypted
```
Type 5 Passwords (MD5 Hash)
Format: enable secret 5 $hash
Security: One-way MD5 hashing
Example: $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0.
Cracking: Requires brute-force/dictionary attacks

Type 7 Passwords (Weak Encryption)
Format: password 7 encrypted_string 
Security: Weak reversible encryption
Example: 025017705B3907344E
Cracking: Instantly reversible with tools
```
* enable secret 5 $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0. (md-5) `Try cracking using hashcat first, is it failed, should we gather another hint again`
* username hub password 7 025017705B3907344E (cisco type-7)
* username admin privilege 15 password 7 10181A325528130F010D24 (cisco type-7)
* username guest password 7 124F163C42340B112F3830 (cisco type-7)

### 2. Try cracking
1. Try MD-5 first
    > enable secret 5 $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0. (md-5) 
      `Try cracking using hashcat first, is it failed, should we gather another hint again`   
    >  
    As we know here this is a `md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5) 2` and have an salt `p8Y6`

2. Lets try to decrypt cisco type 7

3. Define name apps
4. Network Use Sepolia
5. `CREATE APP`
6. Navigate to apps already created `VIEW DETAILS`
7. Select `VIEW KEY`
8. Copy HTTP & WSS

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
