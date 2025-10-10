| System | IP Address | Role | OS | Services |
|--------|------------|------|----|---------| 
| Gateway | 10.0.2.1 | Network Gateway | VirtualBox NAT | DHCP, DNS |
| Domain Controller | 10.0.2.10 | AD Domain Controller | Windows Server 2019 | AD DS, DNS, DHCP |
| Attacker | 10.0.2.15 | Attack Platform | Kali Linux | Penetration Testing Tools |
| SIEM | 10.0.2.100 | Security Monitoring | Ubuntu 20.04 | ELK Stack, Suricata |
| Vulnerable Linux | 10.0.2.101 | Target System | Ubuntu 20.04 | SSH, HTTP, FTP, MySQL |
| Vulnerable Windows | 10.0.2.102 | Target System | Windows 10 Pro | RDP, SMB, WinRM |
| Web Server | 10.0.2.103 | Web Applications | Ubuntu 20.04 | Apache, DVWA, WebGoat |
