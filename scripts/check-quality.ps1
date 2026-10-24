<#
.SYNOPSIS
Runs the Windows Medic quality gate from a clean checkout.

.DESCRIPTION
Executes, in order and stopping at the first failure:
  uv sync --all-groups
  uv run ruff format --check .
  uv run ruff check .
  uv run mypy src tests
  uv run lint-imports
  uv run pytest -m "not windows_integration" --cov --cov-branch

.PARAMETER IncludeWindowsIntegration
Also run `uv run pytest -m windows_integration`, which touches the real Windows OS.

.EXAMPLE
.\scripts\check-quality.ps1
.\scripts\check-quality.ps1 -IncludeWindowsIntegration
#>
[CmdletBinding()]
param(
    [switch]$IncludeWindowsIntegration
)

# Native tools (uv, ruff, pytest) write progress to stderr. Under Windows PowerShell 5.1 a
# "Stop" preference would turn those lines into terminating errors when output is
# redirected, so success/failure is decided purely by each step's exit code.
$ErrorActionPreference = "Continue"
Set-Location (Split-Path -Parent $PSScriptRoot)

$steps = @(
    @{ Name = "uv sync";      Args = @("sync", "--all-groups") },
    @{ Name = "ruff format";  Args = @("run", "ruff", "format", "--check", ".") },
    @{ Name = "ruff check";   Args = @("run", "ruff", "check", ".") },
    @{ Name = "mypy";         Args = @("run", "mypy", "src", "tests") },
    @{ Name = "lint-imports"; Args = @("run", "lint-imports") },
    @{ Name = "pytest";       Args = @("run", "pytest", "-m", "not windows_integration", "--cov", "--cov-branch") }
)
if ($IncludeWindowsIntegration) {
    $steps += @{ Name = "pytest (windows_integration)"; Args = @("run", "pytest", "-m", "windows_integration") }
}

foreach ($step in $steps) {
    Write-Host "==> $($step.Name)" -ForegroundColor Cyan
    & uv @($step.Args)
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $($step.Name) (exit code $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Write-Host "Quality gate passed." -ForegroundColor Green
