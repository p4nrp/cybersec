
### Kerberos - Authentication Challenges
<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/HkRws1h.png">
</p>


#### Wireshark filter 
1.
  <p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/hCRg5DP.png">
  </p>


2. we need to get a : `CNameString` `realm` `padata-value.cipher` use it for hashcat Kerberos 5 etype-18 (Pre-Auth) template.

   2.1. You can check hashcat wiki hashes template [HERE](https://hashcat.net/wiki/doku.php?id=example_hashes)
   <p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/HJPdAYS.png">
 </p>

 
3. Assemble it all you got before like this `$krb5pa$18$CNameString$kerberos.realm$kerberos.padata-value.cipher` we use `(Kerberos 5, etype 18, Pre-Auth(Hash-Mode 19900))` change it to  `$krb5pa$18$william.dupond$CATCORP.LOCAL$fc8bbe22b2c967b222ed73dd7616ea71b2ae0c1b0c3688bfff7fecffdebd4054471350cb6e36d3b55ba3420be6c0210b2d978d3f51d1eb4f`
  <p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/IWdFAi8.png">
</p>
  3.1. Save it to .txt 
  <p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/xP3RXmX.png">
</p>


### Assemble Format
```
john.doe::catcorp.local:1944952f5b845db1:5c336c6b69fd2cf7b64eb0bde3102162:01010000000000001a9790044b63da0175304c546c6f34320000000002000e0043004100540043004f005200500001000800440043003000310004001a0063006100740063006f00720070002e006c006f00630061006c000300240044004300300031002e0063006100740063006f00720070002e006c006f00630061006c0005001a0063006100740063006f00720070002e006c006f00630061006c00070008001a9790044b63da010900120063006900660073002f0044004300300031000000000000000000
```

#### Optional Template 
```
User:
Domain:
ServerChallenge:
HMAC-MD5:
NTLMv2Response:
```
# Hashcat command
Save it the format to .txt file and run the command `hashcat -a0 -m5600 smbhash.txt rockyou.txt`
<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/DzL2oEf.png">
</p>
the password is "rootbeer" `john.doe::catcorp.local:1944952f5b845db1:5c336c6b69fd2cf7b64eb0bde3102162:010100000000000xxxxxxx:rootbeer`
<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/KVHbsBt.png">
</p>

# The answer is 
# RM{john.doe@catcorp.local:rootbeer}

# Challenge link 
# https://www.root-me.org/en/Challenges/Network/NTLM-Authentication#pagination_dernieres_validations

