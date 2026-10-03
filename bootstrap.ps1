<#
.SYNOPSIS
    Sovereign Security Archive bootstrap script.
.DESCRIPTION
    Scaffolds the full SSA mega-repo, verifies integrity, or runs the
    offline validator. PowerShell 5.1 compatible (no PS7-only syntax).
.PARAMETER Root
    Archive root (default: the current directory).
.PARAMETER Mode
    Init | Verify | Validate | Index | Stats | Clean | Full (default).
.EXAMPLE
    .\bootstrap.ps1
    .\bootstrap.ps1 -Root C:\SSA -Mode Init
    .\bootstrap.ps1 -Mode Verify
#>
[CmdletBinding()]
param(
    [string]$Root = ".",
    [ValidateSet("Init", "Verify", "Validate", "Index", "Stats", "Clean", "Full")]
    [string]$Mode = "Full"
)

$ErrorActionPreference = "Stop"

function Write-Header([string]$text) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Resolve-Python {
    $candidates = @("python", "python3", "py")
    foreach ($c in $candidates) {
        try {
            $null = & $c --version 2>&1
            if ($LASTEXITCODE -eq 0) { return $c }
        } catch { }
    }
    return $null
}

$RootPath = (Resolve-Path -LiteralPath $Root).ProviderPath
Write-Header "Sovereign Security Archive - bootstrap"
Write-Host "  Root : $RootPath"
Write-Host "  Mode : $Mode"

$Python = Resolve-Python
if (-not $Python) {
    Write-Warning "Python not found on PATH. Init/Verify/Validate/Index require Python 3.9+."
    Write-Warning "Install from https://www.python.org/downloads/ or use the Windows installer."
    if ($Mode -eq "Verify") {
        Write-Host "Falling back to directory-only structure check."
        $expected = @(
            "00-governance", "01-intel", "02-payloads", "03-wordlists",
            "04-evasion", "05-engines", "06-defense", "07-tooling",
            "08-threatintel", "09-labs", "10-crosswalk", "11-automation",
            "12-schemas", "13-training", "14-docs"
        )
        $missing = $expected | Where-Object { -not (Test-Path -LiteralPath (Join-Path $RootPath $_)) }
        if ($missing) {
            Write-Host "MISSING: $($missing -join ', ')" -ForegroundColor Red
            exit 2
        }
        Write-Host "All 15 top-level domains present." -ForegroundColor Green
        exit 0
    }
    exit 1
}

Write-Host "  Python: $(& $Python --version 2>&1)"

function Invoke-Ssa([string[]]$cmdArgs) {
    & $Python tools/ssactl.py @cmdArgs --root $RootPath
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

switch ($Mode) {
    "Init" {
        Write-Header "Initializing archive"
        Invoke-Ssa @("init")
    }
    "Verify" {
        Write-Header "Verifying"
        Invoke-Ssa @("verify", "--strict", "--coverage")
    }
    "Validate" {
        Write-Header "Validating schemas"
        Invoke-Ssa @("validate")
    }
    "Index" {
        Write-Header "Building index"
        Invoke-Ssa @("index")
    }
    "Stats" {
        Write-Header "Statistics"
        Invoke-Ssa @("stats")
    }
    "Clean" {
        Write-Header "Cleaning"
        Invoke-Ssa @("clean")
    }
    "Full" {
        Write-Header "Step 1/5 - init"
        Invoke-Ssa @("init")
        Write-Header "Step 2/5 - verify"
        Invoke-Ssa @("verify", "--strict", "--coverage")
        Write-Header "Step 3/5 - validate"
        Invoke-Ssa @("validate")
        Write-Header "Step 4/5 - index"
        Invoke-Ssa @("index")
        Write-Header "Step 5/5 - stats"
        Invoke-Ssa @("stats")
    }
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
