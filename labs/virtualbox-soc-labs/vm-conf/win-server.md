### Domain Controller (10.0.2.10)

# Change the Hostname
```
Rename-Computer -NewName "SOC-DC1" -Restart
```

# common set
```powershell
# Install Active Directory Domain Services
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest -DomainName "soclab.local" -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Force

# Configure DNS forwarders
Add-DnsServerForwarder -IPAddress 8.8.8.8
Add-DnsServerForwarder -IPAddress 8.8.4.4

# Create domain users
New-ADUser -Name "John Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@soclab.local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Jane Smith" -SamAccountName "jsmith" -UserPrincipalName "jsmith@soclab.local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true

# Create service accounts
New-ADUser -Name "SQL Service" -SamAccountName "sqlsvc" -UserPrincipalName "sqlsvc@soclab.local" -AccountPassword (ConvertTo-SecureString "SQLService123!" -AsPlainText -Force) -Enabled $true
```
