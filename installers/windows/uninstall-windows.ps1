$ErrorActionPreference = 'Stop'
$Root = 'C:\\HHC'
$TaskName = 'HHC Client'
$BrokerTask = 'HHC Interactive Broker'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Administrator privileges required'
}
if ($Root -ne 'C:\\HHC') { throw 'Unexpected HHC root' }

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName $BrokerTask -ErrorAction SilentlyContinue

$Deadline = (Get-Date).AddSeconds(10)
do {
  $Processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like '*C:\\HHC\\app\\launcher.mjs*' -or
    $_.CommandLine -like '*C:\\HHC\\app\\client.mjs*' -or
    $_.CommandLine -like '*C:\\HHC\\hhc-supervisor.ps1*' -or
    $_.CommandLine -like '*C:\\HHC\\hhc-gui-broker.ps1*'
  })
  if ($Processes.Count -eq 0) { break }
  foreach ($proc in $Processes) { Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $Deadline)

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $BrokerTask -Confirm:$false -ErrorAction SilentlyContinue

$StartupCmd = Join-Path ([Environment]::GetFolderPath('CommonStartup')) 'HHC Interactive Broker.cmd'
Remove-Item -LiteralPath $StartupCmd -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $Root) { throw 'HHC root could not be removed completely' }

Write-Host 'HHC client uninstalled from Windows.'
