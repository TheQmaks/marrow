# Convenience build wrapper. Resolves cmake.exe from the VS BuildTools layout,
# kills any JVMs that might still hold the agent DLL, and runs configure +
# Release build. Used by tests/run_smoke.ps1 and for day-to-day local builds.
#
# Usage:
#   pwsh build.ps1            # incremental
#   pwsh build.ps1 -Clean     # wipe build/ first
#
# Exit code is the cmake build exit code, so it composes with anything.

param(
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$cmakeExe = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if (-not (Test-Path $cmakeExe)) {
    $cmakeExe = (Get-Command cmake -ErrorAction SilentlyContinue).Source
}
if (-not $cmakeExe) {
    Write-Host "ERROR: cmake.exe not found in PATH or VS BuildTools." -ForegroundColor Red
    exit 1
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $root

# Free the DLL - any java.exe with our agent loaded prevents linker write.
$java = Get-Process java -ErrorAction SilentlyContinue
if ($java) {
    Write-Host "Killing $($java.Count) running java.exe ..." -ForegroundColor Yellow
    $java | Stop-Process -Force
    Start-Sleep -Milliseconds 500
}

if ($Clean) {
    Write-Host "Clean build: removing build/ ..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
}

if (-not (Test-Path build/CMakeCache.txt)) {
    & $cmakeExe -B build -G "Visual Studio 17 2022" -A x64
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& $cmakeExe --build build --config Release
exit $LASTEXITCODE
