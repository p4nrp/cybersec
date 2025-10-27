 Cisco Type 7 Challenge
### 1. Cisco Type 7 Challenge
<p align="center">
<p align="left">
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

We found two type encryption here
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
* enable secret 5 $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0. (md-5) 
* username hub password 7 025017705B3907344E (cisco type-7)
* username admin privilege 15 password 7 10181A325528130F010D24 (cisco type-7)
* username guest password 7 124F163C42340B112F3830 (cisco type-7)

### 2. Try cracking
1. Try MD-5 first
    > enable secret 5 $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0. (md-5) 
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
   - **admin  :** `6sK0_admin`
   - **hub    :** `6sK0_hub`
   - **guest  :** `6sK0_guest`
   >
   > we got a hint, the every password is using `6sK0_` on the first word
   >
3. Lets try to hashing to md-5, with a hint we got, such as `6sK0_` on the first word, and use salt of encrypted enable password before `p8Y6`

   `openssl passwd -1 -salt p8Y6 6sK0_enable`

   <p align="left">
   <img height="auto" width="auto" src="https://i.imgur.com/0cDIHYm.png">
   </p>

### 3. Conclusion
### the password for user "enable" is `6sK0_enable`
