# LucentMist Release 构建脚本 (Windows PowerShell)
# 用法: .\scripts\build-release.ps1 [-Version "0.1.0"] [-Runtime "win-x64"]

param(
    [string]$Version = "0.1.0",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $PSScriptRoot
$PublishDir = "$ProjectDir\publish\$Version"

Write-Host @"

╔══════════════════════════════════════════╗
║   LucentMist Release Builder            ║
║   Version: $Version                      ║
║   Runtime: $Runtime                     ║
╚══════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Step 1: 清理
Write-Host "[1/6] 清理旧构建产物..." -ForegroundColor Yellow
if (Test-Path $PublishDir) { Remove-Item -Recurse -Force $PublishDir }
if (Test-Path "$ProjectDir\publish\latest") { Remove-Item -Recurse -Force "$ProjectDir\publish\latest" }
Write-Host "       清理完成" -ForegroundColor Green

# Step 2: 还原
Write-Host "[2/6] 还原 NuGet 包..." -ForegroundColor Yellow
dotnet restore "$ProjectDir\LucentMist.slnx"
if ($LASTEXITCODE -ne 0) { throw "NuGet restore failed" }
Write-Host "       还原完成" -ForegroundColor Green

# Step 3: 编译
Write-Host "[3/6] Release 编译..." -ForegroundColor Yellow
dotnet build "$ProjectDir\LucentMist.slnx" -c Release --no-restore
if ($LASTEXITCODE -ne 0) { throw "Build failed" }
Write-Host "       编译完成 (0 errors)" -ForegroundColor Green

# Step 4: 测试
Write-Host "[4/6] 运行测试..." -ForegroundColor Yellow
dotnet test "$ProjectDir\LucentMist.slnx" -c Release --no-restore --verbosity normal
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
Write-Host "       测试全部通过" -ForegroundColor Green

# Step 5: 发布 CLI
Write-Host "[5/6] 发布 CLI ($Runtime)..." -ForegroundColor Yellow
dotnet publish "$ProjectDir\src\LucentMist.CLI\LucentMist.CLI.csproj" `
    -c Release `
    -o "$PublishDir\cli" `
    --self-contained true `
    -r $Runtime `
    -p:PublishSingleFile=true `
    -p:Version=$Version
if ($LASTEXITCODE -ne 0) { throw "CLI publish failed" }
Write-Host "       CLI 发布完成" -ForegroundColor Green

# Step 6: 发布 API
Write-Host "[6/7] 发布 API ($Runtime)..." -ForegroundColor Yellow
dotnet publish "$ProjectDir\src\LucentMist.API\LucentMist.API.csproj" `
    -c Release `
    -o "$PublishDir\api" `
    --self-contained true `
    -r $Runtime `
    -p:Version=$Version
if ($LASTEXITCODE -ne 0) { throw "API publish failed" }
Write-Host "       API 发布完成" -ForegroundColor Green

# Step 7: 发布 Web
Write-Host "[7/7] 发布 Web ($Runtime)..." -ForegroundColor Yellow
dotnet publish "$ProjectDir\src\LucentMist.Web\LucentMist.Web.csproj" `
    -c Release `
    -o "$PublishDir\web" `
    --self-contained true `
    -r $Runtime `
    -p:Version=$Version
if ($LASTEXITCODE -ne 0) { throw "Web publish failed" }
Write-Host "       Web 发布完成" -ForegroundColor Green

# 复制配置
Copy-Item -Recurse "$ProjectDir\config" "$PublishDir\config"
Copy-Item "$ProjectDir\README.md" "$PublishDir\README.md"

# 创建 latest 链接
New-Item -ItemType Directory -Force -Path "$ProjectDir\publish\latest" | Out-Null
Copy-Item -Recurse "$PublishDir\*" "$ProjectDir\publish\latest"

Write-Host @"

╔══════════════════════════════════════════╗
║   ✅ 构建完成！                          ║
╠══════════════════════════════════════════╣
║   输出: $PublishDir
║                                          ║
║   CLI: $PublishDir\cli\lmist.exe
║   API: $PublishDir\api\LucentMist.API.dll
║   Web: $PublishDir\web\LucentMist.Web.dll
╚══════════════════════════════════════════╝

"@ -ForegroundColor Green
