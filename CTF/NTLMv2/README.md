### Hashcat format

# NTLM - Challenge
<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/j38z1eC.png">
</p>

# Wireshark filter 
<p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/H6FzN1J.png">
</p>

# The Format
```
john.doe::catcorp.local:1944952f5b845db1:5c336c6b69fd2cf7b64eb0bde3102162:01010000000000001a9790044b63da0175304c546c6f34320000000002000e0043004100540043004f005200500001000800440043003000310004001a0063006100740063006f00720070002e006c006f00630061006c000300240044004300300031002e0063006100740063006f00720070002e006c006f00630061006c0005001a0063006100740063006f00720070002e006c006f00630061006c00070008001a9790044b63da010900120063006900660073002f0044004300300031000000000000000000
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
