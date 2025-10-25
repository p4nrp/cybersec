
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
 
  3.1. Save it to .txt and run it `hashcat -m 19900 filename.txt wordlist.txt`
   <p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/IWdFAi8.png">
</p>
the password is "kittycat12"
  <p align="center">
  <img height="auto" width="auto" src="https://i.imgur.com/xP3RXmX.png">
</p>


# [Challenge Link](https://www.root-me.org/en/Challenges/Network/Kerberos-Authentication?lang=en)


