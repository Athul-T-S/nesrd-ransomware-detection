@echo off
echo Removing NESRD isolation rules...
netsh advfirewall firewall delete rule name="NESRD-BLOCK-OUTBOUND"
netsh advfirewall firewall delete rule name="NESRD-BLOCK-INBOUND"
netsh advfirewall firewall delete rule name="NESRD-ALLOW-MANAGER-OUT"
netsh advfirewall firewall delete rule name="NESRD-ALLOW-MANAGER-IN"
echo Done. Network access restored.
pause