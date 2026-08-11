param(
    [switch]$SkipDocker
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectDir
$Check = Join-Path $ProjectDir "scripts\auto-check.ps1"

Write-Host "[maintain] Running self-check..." -ForegroundColor Cyan
& $Check -NoRestore -SkipDocker:$SkipDocker
if ($LASTEXITCODE -eq 0) {
    Write-Host "[maintain] PASS - no repair needed" -ForegroundColor Green
    exit 0
}

Write-Host "[maintain] Self-check failed; dispatching Codex repair..." -ForegroundColor Yellow
$prompt = @'
You are maintaining the LucentMist repository at E:\LucentMist.

- The wrapper already ran `scripts/auto-check.ps1 -NoRestore` and it failed.
- Read `docs/auto-check-latest.md` and the relevant source and tests.
- Fix the root cause with minimal, focused changes.
- Do NOT run dotnet, docker, or other heavy build commands. The wrapper will verify.
- Do NOT commit, push, delete user data, or touch unrelated files.
- If you cannot determine a fix, document the blocker in `docs/auto-check-latest.md` and stop.
'@

& "E:\npm-global\codex.ps1" exec --ephemeral --sandbox workspace-write -C $ProjectDir $prompt
if ($LASTEXITCODE -ne 0) {
    Write-Host "[maintain] Codex repair session failed" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[maintain] Re-running self-check..." -ForegroundColor Cyan
& $Check -NoRestore -SkipDocker:$SkipDocker
if ($LASTEXITCODE -eq 0) {
    Write-Host "[maintain] PASS after repair" -ForegroundColor Green
    exit 0
}

Write-Host "[maintain] Still failing after repair" -ForegroundColor Red
exit 1
