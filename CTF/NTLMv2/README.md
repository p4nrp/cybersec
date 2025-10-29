# Hashcat format

### NTLM - Challenge
<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/j38z1eC.png">
</p>

#### Wireshark filter 
1. <p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/H6FzN1J.png">
  </p>

2. Get the Server Challenge
   <p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/5SptLWJ.png">
 </p>
 
3.1 Get the User,Domain,HMAC-MD5, and NTLMv2Response NOTE! `HMAC-MD5 alias is NTProofStr` the value is : `5c336c6b69fd2cf7b64eb0bde3102162`

3.2 And for NTLMv2Response delete the first 16 byte value such as 
`5c336c6b69fd2cf7b64eb0bde310216201010000000000001a9790044b63da0175304c546c6f34320000000002000e0043004100540043004f005200500001000800440043003000310004001a0063006100740063006f00720070002e006c006f00630061006c000300240044004300300031002e0063006100740063006f00720070002e006c006f00630061006c0005001a0063006100740063006f00720070002e006c006f00630061006c00070008001a9790044b63da010900120063006900660073002f0044004300300031000000000000000000`
to this:
`01010000000000001a9790044b63da0175304c546c6f34320000000002000e0043004100540043004f005200500001000800440043003000310004001a0063006100740063006f00720070002e006c006f00630061006c000300240044004300300031002e0063006100740063006f00720070002e006c006f00630061006c0005001a0063006100740063006f00720070002e006c006f00630061006c00070008001a9790044b63da010900120063006900660073002f0044004300300031000000000000000000`

<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/ptqopr0.png">
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

### Conclusion
### The Flag NTLMv2 password is `RM{john.doe@catcorp.local:rootbeer}`
# Challenge link 
# https://www.root-me.org/en/Challenges/Network/NTLM-Authentication#pagination_dernieres_validations
