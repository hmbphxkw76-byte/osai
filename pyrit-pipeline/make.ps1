# make.ps1 - Windows PowerShell wrapper for GNU Make via WSL
# Usage:
#   .\make.ps1 help       Show all available commands
#   .\make.ps1 run         Run pipeline
#   .\make.ps1 test        Run tests
#   .\make.ps1 clean       Clean temp files

param([Parameter(ValueFromRemainingArguments = $true)] $Args)

$ErrorActionPreference = 'Stop'

# Check if make is available natively
$makeCmd = Get-Command make -ErrorAction SilentlyContinue
if ($makeCmd) {
    & make @Args
    exit $LASTEXITCODE
}

# Check if WSL is available
$wslCmd = Get-Command wsl -ErrorAction SilentlyContinue
if (-not $wslCmd) {
    Write-Host 'Error: make not found and WSL is not available.' -ForegroundColor Red
    Write-Host 'Install make via one of:' -ForegroundColor Yellow
    Write-Host '  1. WSL: wsl --install' -ForegroundColor Cyan
    Write-Host '  2. scoop: scoop install make' -ForegroundColor Cyan
    Write-Host '  3. chocolatey: choco install make' -ForegroundColor Cyan
    exit 1
}

# Convert Windows path to WSL path manually (wslpath has issues with backslashes)
$winPath = (Get-Location).Path
$drive = $winPath.Substring(0, 1).ToLower()
$rest = $winPath.Substring(3) -replace '\\', '/'
$wslPath = "/mnt/$drive/$rest"

wsl make -C $wslPath @Args
