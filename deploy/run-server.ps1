# Keeps the Expenses server running: if Node exits for any reason, it is restarted after 5 seconds.
param([string]$AppDir = (Resolve-Path "$PSScriptRoot\..").Path)
Set-Location $AppDir
New-Item -ItemType Directory -Force (Join-Path $AppDir 'logs') | Out-Null
$log = Join-Path $AppDir 'logs\server.log'
while ($true) {
  Add-Content -Path $log -Value "[$(Get-Date -Format s)] starting server"
  & node --env-file-if-exists=.env server.js *>> $log
  Add-Content -Path $log -Value "[$(Get-Date -Format s)] server exited with code $LASTEXITCODE; restarting in 5s"
  Start-Sleep -Seconds 5
}
