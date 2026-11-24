# Registers Komfort Expenses as a Windows scheduled task that starts at boot
# (before anyone logs in). deploy\run-server.ps1 restarts Node if it ever exits.
# Run from an elevated PowerShell:  powershell -ExecutionPolicy Bypass -File deploy\install-app-task.ps1
param(
  [string]$AppDir = (Resolve-Path "$PSScriptRoot\..").Path,
  [string]$TaskName = 'KomfortExpenses'
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path (Join-Path $AppDir '.env'))) { throw "Create $AppDir\.env first (copy .env.example)." }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js is not on PATH.' }

$script = Join-Path $AppDir 'deploy\run-server.ps1'
$action   = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -AppDir `"$AppDir`"" -WorkingDirectory $AppDir
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
  -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Registered and started '$TaskName'. Logs: $AppDir\logs\server.log"
