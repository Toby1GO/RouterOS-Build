param([string]$AppName = 'RouterOSKeygen-v3')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
python build_license_gui.py --name $AppName
if ($LASTEXITCODE -ne 0) { throw 'EXE build failed' }
