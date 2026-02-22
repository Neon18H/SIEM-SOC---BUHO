$ErrorActionPreference = 'Stop'
$BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = 'C:\ProgramData\AgentNocturno'
$AgentDir = Join-Path $InstallDir 'agent'
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item (Join-Path $BaseDir 'config.yml') (Join-Path $InstallDir 'config.yml') -Force
Copy-Item (Join-Path $BaseDir 'agent\*') $AgentDir -Recurse -Force
