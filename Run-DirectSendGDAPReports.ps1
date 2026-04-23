#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Runs Get-DirectSendReport.ps1 against multiple GDAP-delegated tenants in parallel.

.DESCRIPTION
    Reads a list of tenant primary domains (e.g. contoso.onmicrosoft.com) and runs
    Get-DirectSendReport.ps1 against each one as a separate pwsh child process so
    every tenant gets its own Exchange Online session. Concurrency is throttled
    with -MaxParallel.

    Each tenant's CSV is named "<short>-directsend.csv" where <short> is the
    tenant's primary domain with ".onmicrosoft.com" stripped off. Per-tenant
    transcript logs are written next to the CSVs with the suffix ".log".

    The default tenant list file (tenants.txt next to this script) is gitignored
    because it typically contains real customer domains. Each child process
    pre-connects with -DisableWAM to work around the WAM GDAP token bug that
    produces "The role assigned to user ... isn't supported in this scenario".

    GDAP requirements: your partner-tenant user must be in a security group
    that is granted the Exchange Administrator Entra role on each target
    customer tenant via an active GDAP relationship.

.PARAMETER Tenants
    Array of tenant primary domains. If omitted, tenants are read from -TenantFile.

.PARAMETER TenantFile
    Path to a text file with one tenant per line. Blank lines and lines starting
    with '#' are ignored. Default: tenants.txt next to this script.

.PARAMETER OutputDir
    Directory to write CSVs and logs into. Default: the script's directory.

.PARAMETER MaxParallel
    Maximum number of tenants to process concurrently. Default: 5.

.PARAMETER ScriptArgs
    Extra arguments forwarded verbatim to Get-DirectSendReport.ps1 for every
    tenant (e.g. -Days 30, -IncludeInternalRelay). -DelegatedOrganization and
    -OutputPath are set automatically and must not be included here.

.PARAMETER DisableWAM
    Pre-connect each child session with Connect-ExchangeOnline -DisableWAM
    before handing off to the main script. Needed when the WAM GDAP token bug
    ("The role assigned to user ... isn't supported in this scenario") appears.
    Default: $true.

.EXAMPLE
    ./Run-DirectSendGDAPReports.ps1

    Reads tenants.txt next to the script, fans out up to 5 in parallel, and
    writes per-tenant CSVs and logs into the script's directory.

.EXAMPLE
    ./Run-DirectSendGDAPReports.ps1 -Tenants agmaasindy.onmicrosoft.com,contoso.onmicrosoft.com -MaxParallel 3 -ScriptArgs @('-Days','30')
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Tenants,

    [Parameter()]
    [string]$TenantFile,

    [Parameter()]
    [string]$OutputDir,

    [Parameter()]
    [ValidateRange(1, 20)]
    [int]$MaxParallel = 5,

    [Parameter()]
    [string[]]$ScriptArgs,

    [Parameter()]
    [bool]$DisableWAM = $true
)

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $PSCommandPath
$mainScript = Join-Path $here 'Get-DirectSendReport.ps1'

if (-not (Test-Path $mainScript)) {
    throw "Main script not found at: $mainScript"
}

if (-not $OutputDir) { $OutputDir = $here }
$OutputDir = (Resolve-Path $OutputDir).Path

if (-not $Tenants -or $Tenants.Count -eq 0) {
    if (-not $TenantFile) { $TenantFile = Join-Path $here 'tenants.txt' }
    if (-not (Test-Path $TenantFile)) {
        throw "No -Tenants supplied and tenant file not found: $TenantFile"
    }
    $Tenants = Get-Content $TenantFile |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') }
}

if (-not $Tenants -or $Tenants.Count -eq 0) {
    throw 'No tenants to process. Populate .claude/tenants.txt or pass -Tenants.'
}

# Map tenant -> short name used in output filenames.
function Get-TenantShortName {
    param([string]$Tenant)
    $t = $Tenant.Trim().ToLower()
    if ($t.EndsWith('.onmicrosoft.com')) {
        $t = $t.Substring(0, $t.Length - '.onmicrosoft.com'.Length)
    }
    # Strip anything non-alphanumeric so the filename is safe everywhere.
    return ($t -replace '[^a-z0-9\-]', '-')
}

$pwshPath = (Get-Process -Id $PID).Path
if (-not $pwshPath) { $pwshPath = 'pwsh' }

Write-Host ""
Write-Host "Tenants:     $($Tenants.Count)" -ForegroundColor Cyan
Write-Host "MaxParallel: $MaxParallel" -ForegroundColor Cyan
Write-Host "OutputDir:   $OutputDir" -ForegroundColor Cyan
Write-Host "DisableWAM:  $DisableWAM" -ForegroundColor Cyan
if ($ScriptArgs) { Write-Host "ScriptArgs:  $($ScriptArgs -join ' ')" -ForegroundColor Cyan }
Write-Host ""

$jobs = @()
foreach ($tenant in $Tenants) {
    $short    = Get-TenantShortName $tenant
    $csvPath  = Join-Path $OutputDir ("{0}-directsend.csv" -f $short)
    $logPath  = Join-Path $OutputDir ("{0}-directsend.log" -f $short)

    $scriptBlock = {
        param($MainScript, $Tenant, $CsvPath, $LogPath, $Extra, $UseDisableWAM)

        $ErrorActionPreference = 'Continue'
        Start-Transcript -Path $LogPath -Force | Out-Null
        try {
            Write-Host "[$Tenant] pre-connecting (DisableWAM=$UseDisableWAM)..."
            $connect = @{
                DelegatedOrganization = $Tenant
                ShowBanner            = $false
            }
            if ($UseDisableWAM) { $connect['DisableWAM'] = $true }
            $exoCmd = Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue
            if ($exoCmd -and $exoCmd.Parameters.ContainsKey('UseRPSSession')) {
                $connect['UseRPSSession'] = $false
            }
            Connect-ExchangeOnline @connect

            $argList = @('-DelegatedOrganization', $Tenant, '-OutputPath', $CsvPath)
            if ($Extra) { $argList += $Extra }

            Write-Host "[$Tenant] running: $MainScript $($argList -join ' ')"
            & $MainScript @argList
            $code = $LASTEXITCODE
            Write-Host "[$Tenant] done (exit=$code) -> $CsvPath"
        }
        catch {
            Write-Host "[$Tenant] ERROR: $_" -ForegroundColor Red
            throw
        }
        finally {
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
            Stop-Transcript | Out-Null
        }
    }

    # Throttle: wait until we have a free slot.
    while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MaxParallel) {
        Start-Sleep -Seconds 2
        # Drain any finished jobs so the log shows progress promptly.
        foreach ($done in $jobs | Where-Object { $_.State -ne 'Running' -and -not $_.HasBeenReported }) {
            Write-Host "----- [$($done.Tenant)] finished with state $($done.Job.State) -----" -ForegroundColor Yellow
            $done | Add-Member -NotePropertyName HasBeenReported -NotePropertyValue $true -Force
        }
    }

    $job = Start-Job -Name "DirectSend-$short" -ScriptBlock $scriptBlock `
        -ArgumentList $mainScript, $tenant, $csvPath, $logPath, $ScriptArgs, $DisableWAM
    $jobs += [pscustomobject]@{
        Tenant           = $tenant
        Short            = $short
        Job              = $job
        CsvPath          = $csvPath
        LogPath          = $logPath
        HasBeenReported  = $false
    }
    Write-Host "[$tenant] queued (job $($job.Id)) -> $csvPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "All $($jobs.Count) tenants queued. Waiting for completion..." -ForegroundColor Cyan

# Wait for everything and surface results as jobs finish.
while (($jobs | Where-Object { $_.Job.State -eq 'Running' }).Count -gt 0) {
    Start-Sleep -Seconds 3
}

$summary = foreach ($j in $jobs) {
    $state = $j.Job.State
    $err   = $null
    try {
        Receive-Job -Job $j.Job -Keep -ErrorAction SilentlyContinue | Out-Null
    } catch { $err = $_.ToString() }
    if ($j.Job.ChildJobs[0].JobStateInfo.Reason) {
        $err = $j.Job.ChildJobs[0].JobStateInfo.Reason.Message
    }
    $csvSize = if (Test-Path $j.CsvPath) { (Get-Item $j.CsvPath).Length } else { 0 }
    [pscustomobject]@{
        Tenant  = $j.Tenant
        State   = $state
        CsvKB   = [math]::Round($csvSize / 1KB, 1)
        Log     = $j.LogPath
        Error   = $err
    }
    Remove-Job -Job $j.Job -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host '===== Summary =====' -ForegroundColor Cyan
$summary | Format-Table -AutoSize
