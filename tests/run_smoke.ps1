# Top-level smoke runner. Composes:
#   1. cpp/build.ps1           - Release build (clean if -Clean given)
#   2. tests/matrix_cpp_smoke  - out-of-process CLI across JDK x GC matrix
#   3. tests/agent_smoke.py    - in-process agent JS-binding regression
#
# Each stage's exit code is captured; final exit is non-zero if ANY stage
# failed. Skips agent_smoke if matrix smoke broke.
#
# Usage:
#   powershell tests/run_smoke.ps1
#   powershell tests/run_smoke.ps1 -Clean
#   powershell tests/run_smoke.ps1 -SkipMatrix    # quick agent-only run

param(
    [switch]$Clean,
    [switch]$SkipMatrix
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Definition)
$failed = @()

# pwsh (PS7) preferred but powershell.exe (5.1) works too.
$ps = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $ps) { $ps = (Get-Command powershell -ErrorAction SilentlyContinue).Source }
if (-not $ps) { Write-Host "ERROR no PowerShell host found." -ForegroundColor Red; exit 2 }

# --- 1. Build ---
Write-Host ""
Write-Host "===== BUILD =====" -ForegroundColor Cyan
$buildArgs = @('-NoProfile', '-File', "$root\cpp\build.ps1")
if ($Clean) { $buildArgs += '-Clean' }
& $ps @buildArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build FAILED, aborting." -ForegroundColor Red
    exit 1
}

# --- 2. CLI matrix ---
if (-not $SkipMatrix) {
    Write-Host ""
    Write-Host "===== CLI MATRIX SMOKE =====" -ForegroundColor Cyan
    & python "$root\tests\matrix_cpp_smoke.py"
    if ($LASTEXITCODE -ne 0) {
        $failed += "matrix_cpp_smoke"
        Write-Host "matrix_cpp_smoke FAILED" -ForegroundColor Red
    } else {
        Write-Host "matrix_cpp_smoke PASSED" -ForegroundColor Green
    }
}

# --- 3. Agent smoke ---
Write-Host ""
Write-Host "===== AGENT SMOKE =====" -ForegroundColor Cyan
& python "$root\tests\agent_smoke.py"
if ($LASTEXITCODE -ne 0) {
    $failed += "agent_smoke"
    Write-Host "agent_smoke FAILED" -ForegroundColor Red
} else {
    Write-Host "agent_smoke PASSED" -ForegroundColor Green
}

# --- summary ---
Write-Host ""
Write-Host "===== SUMMARY =====" -ForegroundColor Cyan
if ($failed.Count -eq 0) {
    Write-Host "All stages PASS." -ForegroundColor Green
    exit 0
} else {
    $msg = "FAILED: " + ($failed -join ", ")
    Write-Host $msg -ForegroundColor Red
    exit 1
}
