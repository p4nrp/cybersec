sudo rm -rf /etc/vmware-tools
sudo rm -rf /usr/lib/vmware-tools

sudo rm -f /usr/bin/vmware-* /usr/bin/vmtoolsd /usr/bin/vm-support /usr/bin/vmwgfxctrl

sudo apt purge open-vm-tools open-vm-tools-desktop

sudo apt autoremove

FeatureCommand to InstallStandard Tools
sudo apt update && sudo apt install open-vm-tools
Desktop/GUI Tools
sudo apt update && sudo apt install open-vm-tools-desktop
