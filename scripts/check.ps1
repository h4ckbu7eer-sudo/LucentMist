# LucentMist CI 本地检查脚本 (PowerShell)
# 模拟 GitHub Actions 流水线的完整流程

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $root "..")

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LucentMist CI Check (Local)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$start = Get-Date

# Step 1: Restore
Write-Host "[1/3] Restore dependencies..." -ForegroundColor Yellow
dotnet restore
if ($LASTEXITCODE -ne 0) { Write-Host "RESTORE FAILED" -ForegroundColor Red; exit 1 }
Write-Host "  => OK" -ForegroundColor Green
Write-Host ""

# Step 2: Build (Release)
Write-Host "[2/3] Build (Release)..." -ForegroundColor Yellow
dotnet build -c Release --no-restore
if ($LASTEXITCODE -ne 0) { Write-Host "BUILD FAILED" -ForegroundColor Red; exit 2 }
Write-Host "  => OK" -ForegroundColor Green
Write-Host ""

# Step 3: Test (Release)
Write-Host "[3/3] Run tests..." -ForegroundColor Yellow
dotnet test -c Release --no-build --verbosity normal
if ($LASTEXITCODE -ne 0) { Write-Host "TESTS FAILED" -ForegroundColor Red; exit 3 }
Write-Host "  => OK" -ForegroundColor Green
Write-Host ""

$elapsed = (Get-Date) - $start
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ALL CHECKS PASSED" -ForegroundColor Green
Write-Host "  Time: $($elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
