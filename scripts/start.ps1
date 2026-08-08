# LucentMist 启动脚本 (Windows PowerShell)

param(
    [string]$Command = "help"
)

$projectDir = Split-Path -Parent $PSScriptRoot

function Start-CLI {
    Write-Host "启动 LucentMist CLI..." -ForegroundColor Cyan
    dotnet run --project "$projectDir/src/LucentMist.CLI" @args
}

function Start-API {
    Write-Host "启动 LucentMist API 服务 (http://localhost:5050)..." -ForegroundColor Cyan
    dotnet run --project "$projectDir/src/LucentMist.API"
}

function Build-Project {
    Write-Host "编译 LucentMist..." -ForegroundColor Cyan
    dotnet build "$projectDir/LucentMist.sln"
}

function Run-Tests {
    Write-Host "运行测试..." -ForegroundColor Cyan
    dotnet test "$projectDir/LucentMist.sln"
}

function Show-Help {
    Write-Host @"
LucentMist - 智能网络分析助手

用法: .\start.ps1 [command] [options]

命令:
  build   编译项目
  test    运行测试
  cli     启动 CLI 模式
  api     启动 API 服务
  scan    快速扫描 (需指定目标)
  help    显示此帮助

示例:
  .\start.ps1 build
  .\start.ps1 cli scan 192.168.1.0/24
  .\start.ps1 api
"@ -ForegroundColor Green
}

switch ($Command) {
    "build"  { Build-Project }
    "test"   { Run-Tests }
    "cli"    { Start-CLI }
    "api"    { Start-API }
    "scan"   { dotnet run --project "$projectDir/src/LucentMist.CLI" -- scan @args }
    default  { Show-Help }
}
