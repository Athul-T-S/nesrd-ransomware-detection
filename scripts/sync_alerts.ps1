# Continuously syncs new NESRD alerts into Wazuh container
$source = "D:\project\nesrd\nesrd\logs\nesrd_alerts.json"
$lastSize = 0

Write-Host "Alert sync started - watching $source"

while ($true) {
    if (Test-Path $source) {
        $currentSize = (Get-Item $source).Length
        if ($currentSize -gt $lastSize) {
            # Read only new content
            $content = Get-Content $source -Raw
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
            
            # Copy updated file to container
            docker cp $source single-node-wazuh.manager-1:/var/ossec/logs/nesrd_alerts.json
            Write-Host "$(Get-Date -Format 'HH:mm:ss') Synced $currentSize bytes to Wazuh"
            $lastSize = $currentSize
        }
    }
    Start-Sleep -Seconds 5
}