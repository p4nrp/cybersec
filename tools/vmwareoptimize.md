# Disable Virtualization Based Security
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f

# Disable Credential Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "LsaCfgFlags" /t REG_DWORD /d 0 /f
