<#
.SYNOPSIS
    Windows Security Log Analyzer using PowerShell
.DESCRIPTION
    Analyzes Security logs, extracts failed/successful logins,
    new accounts, privilege escalation, and brute force attacks.
.PARAMETER LogName
    Log name to analyze (default: Security)
.PARAMETER MaxEvents
    Number of events to fetch (default: 1000)
.PARAMETER OutputPath
    Path to save the report (default: ./reports)
.EXAMPLE
    .\LogAnalyzer.ps1 -LogName Security -MaxEvents 500
#>

param (
    [string]$LogName = "Security",
    [int]$MaxEvents = 1000,
    [string]$OutputPath = "./reports"
)

# ============================================
# 1. Create reports directory
# ============================================
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       Log Analyzer Tool v1.0           " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Log Name   : $LogName"
Write-Host "Max Events : $MaxEvents"
Write-Host "Output Path: $OutputPath"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================
# 2. Collect logs
# ============================================
try {
    $events = Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction Stop
} catch {
    Write-Host "ERROR: Cannot access log '$LogName'." -ForegroundColor Red
    Write-Host "Run PowerShell as Administrator." -ForegroundColor Yellow
    exit 1
}

if (-not $events) {
    Write-Host "No events found in log '$LogName'." -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($events.Count) events." -ForegroundColor Green
Write-Host ""

# ============================================
# 3. Filter events by ID
# ============================================
$failedLogins   = $events | Where-Object { $_.Id -eq 4625 }
$successLogins  = $events | Where-Object { $_.Id -eq 4624 }
$newAccounts    = $events | Where-Object { $_.Id -eq 4720 }
$privilegeEsc   = $events | Where-Object { $_.Id -eq 4672 }
$accountLockout = $events | Where-Object { $_.Id -eq 4740 }
$accountDeleted = $events | Where-Object { $_.Id -eq 4726 }

Write-Host "Event Statistics:" -ForegroundColor Yellow
Write-Host "   Failed Logins (4625)      : $($failedLogins.Count)" -ForegroundColor Red
Write-Host "   Successful Logins (4624)  : $($successLogins.Count)" -ForegroundColor Green
Write-Host "   New Accounts (4720)       : $($newAccounts.Count)" -ForegroundColor Yellow
Write-Host "   Privilege Escalation (4672): $($privilegeEsc.Count)" -ForegroundColor Magenta
Write-Host "   Account Lockouts (4740)   : $($accountLockout.Count)" -ForegroundColor Cyan
Write-Host "   Account Deleted (4726)    : $($accountDeleted.Count)" -ForegroundColor Gray
Write-Host ""

# ============================================
# 4. Detect Suspicious Activity
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Suspicious Activity:" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Cyan

# 4.1 Brute Force Detection
$bruteForce = $null
if ($failedLogins.Count -gt 0) {
    $bruteForce = $failedLogins | Group-Object { 
        try { $_.Properties[18].Value } catch { "Unknown" } 
    } | Where-Object { $_.Count -gt 10 } | Sort-Object Count -Descending

    if ($bruteForce) {
        Write-Host "Potential Brute Force from:" -ForegroundColor Red
        $bruteForce | ForEach-Object {
            Write-Host "   Source: $($_.Name) -> $($_.Count) attempts" -ForegroundColor Yellow
        }
    } else {
        Write-Host "No brute force detected." -ForegroundColor Green
    }
}

# 4.2 New Accounts
if ($newAccounts.Count -gt 0) {
    Write-Host "New Accounts Created:" -ForegroundColor Yellow
    $newAccounts | ForEach-Object {
        $user = $_.Properties[5].Value
        $who = $_.Properties[6].Value
        Write-Host "   $user (created by: $who)" -ForegroundColor White
    }
}

# 4.3 Locked Accounts
if ($accountLockout.Count -gt 0) {
    Write-Host "Locked Accounts:" -ForegroundColor Cyan
    $accountLockout | ForEach-Object {
        $user = $_.Properties[5].Value
        Write-Host "   $user" -ForegroundColor White
    }
}

# 4.4 Deleted Accounts
if ($accountDeleted.Count -gt 0) {
    Write-Host "Deleted Accounts:" -ForegroundColor Gray
    $accountDeleted | ForEach-Object {
        $user = $_.Properties[5].Value
        Write-Host "   $user" -ForegroundColor White
    }
}

# 4.5 Privilege Escalation Alert
if ($privilegeEsc.Count -gt 10) {
    Write-Host "High number of privilege escalations: $($privilegeEsc.Count)" -ForegroundColor Red
}

Write-Host ""

# ============================================
# 5. Save Report
# ============================================
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = "$OutputPath\LogReport_$timestamp.txt"

$reportLines = @()
$reportLines += "========================================"
$reportLines += "Log Analysis Report"
$reportLines += "========================================"
$reportLines += "Date           : $(Get-Date)"
$reportLines += "Log Name       : $LogName"
$reportLines += "Total Events   : $($events.Count)"
$reportLines += ""
$reportLines += "Event Statistics:"
$reportLines += "   Failed Logins (4625)      : $($failedLogins.Count)"
$reportLines += "   Successful Logins (4624)  : $($successLogins.Count)"
$reportLines += "   New Accounts (4720)       : $($newAccounts.Count)"
$reportLines += "   Privilege Escalation (4672): $($privilegeEsc.Count)"
$reportLines += "   Account Lockouts (4740)   : $($accountLockout.Count)"
$reportLines += "   Account Deleted (4726)    : $($accountDeleted.Count)"
$reportLines += ""

if ($bruteForce) {
    $reportLines += "Suspicious Activity - Brute Force:"
    $bruteForce | ForEach-Object {
        $reportLines += "   Source: $($_.Name) -> $($_.Count) attempts"
    }
    $reportLines += ""
}

if ($newAccounts.Count -gt 0) {
    $reportLines += "New Accounts:"
    $newAccounts | ForEach-Object {
        $user = $_.Properties[5].Value
        $who = $_.Properties[6].Value
        $reportLines += "   $user (created by: $who)"
    }
    $reportLines += ""
}

$reportLines | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Report saved to:" -ForegroundColor Green
Write-Host "   $reportFile" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan