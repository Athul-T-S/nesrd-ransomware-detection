# NESRD Wazuh Setup Script
# Run this once after every Wazuh container restart

Write-Host "Setting up NESRD Wazuh integration..." -ForegroundColor Cyan

# Step 1 - Copy decoder
docker cp D:\project\nesrd\nesrd\nesrd_decoder.xml single-node-wazuh.manager-1:/var/ossec/etc/decoders/nesrd_decoder.xml
Write-Host "Decoder copied" -ForegroundColor Green

# Step 2 - Copy rules
docker cp D:\project\nesrd\nesrd\nesrd_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/nesrd_rules.xml
Write-Host "Rules copied" -ForegroundColor Green

# Step 3 - Fix ossec.conf and create log file
docker exec single-node-wazuh.manager-1 python3 -c "
content = open('/var/ossec/etc/ossec.conf').read()
if 'nesrd_alerts' not in content:
    content = content.replace('</ossec_config>', '''
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/nesrd_alerts.json</location>
  </localfile>
</ossec_config>''', 1)
    open('/var/ossec/etc/ossec.conf', 'w').write(content)
open('/var/ossec/logs/nesrd_alerts.json', 'a').close()
print('Config done')
"
Write-Host "Config updated" -ForegroundColor Green

# Step 4 - Copy alert script
docker cp D:\project\nesrd\nesrd\append_alert.py single-node-wazuh.manager-1:/tmp/append_alert.py
Write-Host "Alert script copied" -ForegroundColor Green

# Step 5 - Restart Wazuh services
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
Write-Host "Wazuh restarted" -ForegroundColor Green

Write-Host "Setup complete! Wazuh is ready to receive NESRD alerts." -ForegroundColor Cyan