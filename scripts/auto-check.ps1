param(
    [switch]$SkipDocker,
    [switch]$NoRestore
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectDir
$env:MSBUILDDISABLENODEREUSE = "1"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"

$Report = "docs/auto-check-latest.md"
$Lines = [System.Collections.Generic.List[string]]::new()
$Lines.Add("# LucentMist Auto-Check")
$Lines.Add("")
$Lines.Add("> Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
$Lines.Add("")

$Failed = $false

Write-Host "[1/4] dotnet build -c Release" -ForegroundColor Cyan
if ($NoRestore) {
    dotnet build LucentMist.slnx -c Release --no-restore
} else {
    dotnet build LucentMist.slnx -c Release
}
$BuildOk = $LASTEXITCODE -eq 0
if (-not $BuildOk) { $Failed = $true }
$Lines.Add("- Build: $(if ($BuildOk) { 'PASS' } else { 'FAILED' })")

Write-Host "[2/4] dotnet format --verify-no-changes" -ForegroundColor Cyan
dotnet format LucentMist.slnx --verify-no-changes --no-restore
$FormatOk = $LASTEXITCODE -eq 0
if (-not $FormatOk) { $Failed = $true }
$Lines.Add("- Format: $(if ($FormatOk) { 'PASS' } else { 'FAILED' })")

Write-Host "[3/4] dotnet test -c Release --no-build" -ForegroundColor Cyan
dotnet test LucentMist.slnx -c Release --no-build
$TestOk = $LASTEXITCODE -eq 0
if (-not $TestOk) { $Failed = $true }
$Lines.Add("- Test: $(if ($TestOk) { 'PASS' } else { 'FAILED' })")

if (-not $SkipDocker) {
    Write-Host "[4/4] docker compose config" -ForegroundColor Cyan
    docker compose config --quiet
    $DockerOk = $LASTEXITCODE -eq 0
    if (-not $DockerOk) { $Failed = $true }
    $Lines.Add("- Docker config: $(if ($DockerOk) { 'PASS' } else { 'FAILED' })")
} else {
    $Lines.Add("- Docker config: SKIPPED")
}

$Lines.Add("")
$Lines.Add("- Result: $(if ($Failed) { 'FAILED' } else { 'PASS' })")

New-Item -ItemType Directory -Force -Path (Split-Path $Report) | Out-Null
$Lines -join "`n" | Set-Content -LiteralPath $Report -Encoding UTF8

if ($Failed) {
    Write-Host "Auto-check FAILED: $Report" -ForegroundColor Red
    exit 1
}

Write-Host "Auto-check PASS: $Report" -ForegroundColor Green
