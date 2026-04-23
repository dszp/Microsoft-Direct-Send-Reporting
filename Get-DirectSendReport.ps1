#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Reports Direct Send traffic that would be blocked if "Reject Direct Send" is enabled.

.DESCRIPTION
    Default behavior: list every message that would be blocked by Microsoft's "Reject
    Direct Send" feature -- i.e., anonymous SMTP deliveries to the tenant MX with a
    sender in an accepted domain and a recipient in an accepted domain, where EOP
    did not attribute the connection to a configured inbound connector AND logged it
    as an anonymous connection (ProxiedClientHostname is populated).

    This is the audit view for planning a "Reject Direct Send" rollout: most entries
    are spam, but any legitimate traffic here needs to be allowlisted (via an inbound
    connector with an IP restriction) before Reject Direct Send is turned on globally,
    or the legitimate traffic will be blocked along with the spam.

    Filtering pipeline (all four pass = message is in the report by default):
      1. ConnectorId is the "\Default " pattern in the Detail event XML -- no custom
         inbound connector matched. This is Microsoft's authoritative Direct Send
         signal, taken from the Get-MessageTraceDetailV2 Receive event's Data blob.
      2. FromIP is populated -- the message came from an external SMTP connection
         (authenticated internal email has no FromIP).
      3. Sender and recipient domains are both accepted domains for the tenant.
      4. ProxiedClientHostname is populated -- EOP treated the connection as
         anonymous inbound. Empty ProxiedClientHostname means EOP classified the
         traffic differently (typically an on-prem/hybrid relay that Reject Direct
         Send does NOT affect; see -IncludeInternalRelay to see those).

    Output includes a Category column:
      SpamLikely        - ProxiedClientHostname is a bracketed IP like [127.0.0.1].
                          Signature of a spammer providing no valid HELO hostname.
      AnonymousExternal - A real hostname (legitimate mail service or sophisticated
                          spam). Worth a closer look before allowlisting.

    Output also includes RdsAffected (True/False/empty): whether Reject Direct Send
    will actually block the message. RDS evaluates the P1 envelope sender
    (ReturnPath), not the P2 header From. ESPs like Postmark/SendGrid that use a
    custom return-path subdomain (e.g., bounces.yourdomain.com) slide past RDS
    because subdomains aren't automatically accepted domains. The ReturnPath
    column surfaces the envelope sender so you can see the pattern directly.

    With -IncludeInternalRelay, a third category appears:
      InternalRelay     - ProxiedClientHostname is empty. EOP did not classify the
                          connection as anonymous inbound, so Reject Direct Send will
                          NOT affect it. Typically on-prem Exchange hybrid relays or
                          authenticated paths that share the default connector route
                          but are not the Direct Send abuse surface.

    Coverage: up to 90 days. Ranges over 10 days are auto-chunked (V2 limit: 10 days).

    Minimum required role: Exchange Administrator (GDAP or direct) or Global Admin.

    Rate limits: Get-MessageTraceDetailV2 is throttled to 100 requests per 5-minute
    rolling window. The script uses a sliding-window limiter: the first 100 candidates
    process quickly, then pacing kicks in. For 500 candidates, expect ~20 minutes.

    After the rows are emitted, the script prints two console summaries:
      * Top sources grouped by ProxiedClientHostname, with per-row Category coloring.
        Use this to identify clusters needing an inbound connector before rollout.
      * DMARC policy (p= and pct=) per accepted domain, looked up via Resolve-DnsName
        on Windows or nslookup on macOS/Linux. p=reject or p=quarantine (pct=100) is
        the safe baseline before enabling Reject Direct Send with shared-cert inbound
        connectors; p=none undermines the defense-in-depth.

    When -OutputPath is specified, the same two summaries are also appended to the
    CSV itself (below the data rows, separated by a blank row and a marker row) so
    the complete report lives in a single file. In that mode $results is NOT also
    emitted to the pipeline -- the default table formatter would otherwise scroll
    the console summaries off the top of the terminal.

.PARAMETER DelegatedOrganization
    Customer tenant domain or tenant ID for GDAP/CSP delegated connections.
    Omit when connecting directly as Global Admin or Exchange Admin in the target tenant.

.PARAMETER Days
    Number of days back from today to search. Range: 1-90. Default: 10.
    Values over 10 are automatically split into 10-day query windows.

.PARAMETER OutputPath
    Optional path for CSV export. If omitted, results are written to the pipeline/console.

.PARAMETER AcceptedDomains
    Override the auto-detected accepted domain list. If omitted, the script calls
    Get-AcceptedDomain to retrieve them. Useful when access is restricted or you want
    to limit the search to specific domains only.

.PARAMETER NewSession
    Disconnect any existing Exchange Online session before connecting. Use this when
    you need to authenticate with different credentials than the current session.

.PARAMETER ShowSchema
    Diagnostic mode. Connects, queries one recent message, and dumps the full property
    list from Get-MessageTraceV2 and Get-MessageTraceDetailV2 so you can inspect what
    fields are actually available in your tenant. Exits without running the audit.

.PARAMETER IncludeInternalRelay
    Also include rows where EOP did not classify the connection as anonymous inbound
    (empty ProxiedClientHostname). These messages hit the default connector route but
    Reject Direct Send does NOT affect them. Use when investigating all traffic on
    the default connector path -- for example, to find an on-prem relay that should
    be formalized with a named inbound connector.

.PARAMETER UseWAM
    Opt in to Connect-ExchangeOnline's WAM (Web Account Manager) broker. By
    default this script passes -DisableWAM, which forces the browser-based
    interactive flow instead of the Windows native account picker. The default
    also avoids the known WAM GDAP token bug that produces "The role assigned
    to user ... isn't supported in this scenario" even when the role is correct.
    Use -UseWAM only if you specifically want the WAM broker (e.g. cached
    Windows account SSO) and you are not hitting the GDAP token bug. Ignored
    on macOS/Linux and on module versions that don't expose the parameter.

.PARAMETER NoDeepInspect
    Skip the per-candidate Get-MessageTraceDetailV2 lookup. This avoids the rate-limit
    delay but loses the authoritative ConnectorId check, the ProxiedClientHostname-
    based categorization, and the SCL score. Results then rely on the primary trace's
    FromIP + accepted-domain filters alone, which cannot distinguish Reject-Direct-
    Send-affected traffic from other default-connector traffic.

    Use for fast prototyping over large date ranges or when you already know the
    result set from a prior deep-inspection run.

.EXAMPLE
    # Default: see what would be blocked by Reject Direct Send over the last 10 days
    .\Get-DirectSendReport.ps1 -OutputPath .\DirectSend.csv

.EXAMPLE
    # GDAP / CSP partner, 30-day audit of a customer tenant
    .\Get-DirectSendReport.ps1 -DelegatedOrganization contoso.onmicrosoft.com -Days 30 -OutputPath .\contoso.csv

.EXAMPLE
    # Include default-connector traffic that Reject Direct Send wouldn't affect
    # (useful for finding on-prem relays that should have a named inbound connector)
    .\Get-DirectSendReport.ps1 -Days 30 -IncludeInternalRelay

.EXAMPLE
    # Fast mode: skip per-message detail calls. Broader result set, less accurate.
    .\Get-DirectSendReport.ps1 -Days 90 -NoDeepInspect

.EXAMPLE
    # Diagnose what fields are available in this tenant's message trace output
    .\Get-DirectSendReport.ps1 -ShowSchema

.NOTES
    Version: 1.5.0

    To diagnose output schema, run this after connecting:
      Get-MessageTraceV2 -ResultSize 1 | Format-List *

    The authoritative ConnectorId field for Direct Send lives inside the
    Get-MessageTraceDetailV2 Receive event's Data XML (not on the summary record).
    It matches the pattern "<server>\Default <server>" when no configured inbound
    connector matched -- that's the Direct Send path per Microsoft's Reject Direct
    Send documentation.

    Changelog:
      1.5.0 (2026-04-23) - Progressive backoff on Get-MessageTraceDetailV2
                           throttling. Previously a single 60s cooldown
                           and one retry -- insufficient when the identity
                           quota (100/5min per user, shared across parallel
                           GDAP tenants) stayed exhausted. Now retries up
                           to 3 times with 60s -> 180s -> 300s cooldowns
                           and clears the local sliding-window between
                           retries so the next call doesn't immediately
                           re-saturate. Each cooldown is logged visibly so
                           long pauses aren't mistaken for hangs.
      1.4.1 (2026-04-23) - Quiet DMARC lookup noise in transcripts. Switch
                           Resolve-DnsName to -ErrorAction SilentlyContinue
                           (NXDOMAIN no longer raises a caught terminating
                           error that Start-Transcript logs as a failure)
                           and merge nslookup stderr into stdout via 2>&1
                           (pwsh 7 on Windows does not reliably honor
                           2>$null for native command stderr). Behavior
                           unchanged: missing _dmarc records still report
                           p=no record.
      1.4.0 (2026-04-23) - Default Connect-ExchangeOnline to -DisableWAM so
                           Windows auth goes through the browser instead of
                           the native WAM account picker (which also trips
                           the known WAM GDAP token bug). Add -UseWAM switch
                           to opt back in to the WAM broker for cached-SSO
                           scenarios.
      1.3.0 (2026-04-23) - Add ReturnPath domain summary block to both the
                           console output and the appended CSV summary rows.
      1.2.0 (2026-04-23) - Surface the P1 envelope sender as the ReturnPath
                           column and compute RdsAffected by evaluating the
                           envelope sender against accepted domains (Reject
                           Direct Send keys off P1, not the P2 header From;
                           ESPs using a custom return-path subdomain slip past).
      1.1.0 (2026-04-22) - When -OutputPath is set, append the source and DMARC
                           summaries as additional CSV rows below the data
                           rows (separated by a marker row) and suppress the
                           pipeline output so the console summaries stay on
                           screen instead of being scrolled off by the table
                           formatter.
      1.0.1 (2026-04-22) - Document the post-run console summaries in the
                           script help. No behavior change.
      1.0.0 (2026-04-22) - Initial release. Four-stage Direct Send filter
                           (Default connector pattern, populated FromIP,
                           accepted-domain sender + recipient, populated
                           ProxiedClientHostname) with SpamLikely /
                           AnonymousExternal / InternalRelay categorization,
                           10-day window chunking up to 90 days, sliding
                           100-per-5-min rate limiter on the Detail lookup,
                           macOS/Linux REST support, GDAP/CSP delegation via
                           -DelegatedOrganization, and post-run source + DMARC
                           console summaries.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DelegatedOrganization,

    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$Days = 10,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string[]]$AcceptedDomains,

    [Parameter()]
    [switch]$NewSession,

    [Parameter()]
    [switch]$ShowSchema,

    [Parameter()]
    [switch]$IncludeInternalRelay,

    [Parameter()]
    [switch]$NoDeepInspect,

    [Parameter()]
    [switch]$UseWAM
)

$ErrorActionPreference = 'Stop'

#region Helper: DMARC record lookup

# Cross-platform DMARC lookup. Tries Resolve-DnsName (Windows) first, then falls
# back to nslookup (everywhere). Returns an object with Policy ('none' | 'quarantine'
# | 'reject' | 'no record' | 'unparseable'), Pct (int, defaults to 100 per spec),
# and the raw Record text.
function Get-DmarcInfo {
    param([Parameter(Mandatory)][string]$Domain)

    $result = [PSCustomObject]@{
        Domain = $Domain
        Policy = 'no record'
        Pct    = $null
        Record = $null
    }

    $record = $null

    if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        # -ErrorAction SilentlyContinue (not Stop + try/catch) so NXDOMAIN does
        # not surface as a caught terminating error -- Start-Transcript logs
        # every terminating error even when caught, which makes "_dmarc.<domain>
        # does not exist" look like a script failure in the per-tenant log.
        $txtRecords = Resolve-DnsName -Name "_dmarc.$Domain" -Type TXT -ErrorAction SilentlyContinue
        if ($txtRecords) {
            foreach ($r in $txtRecords) {
                $full = if ($r.Strings) { $r.Strings -join '' } elseif ($r.Text) { $r.Text } else { '' }
                if ($full -match '^v=DMARC1') { $record = $full; break }
            }
        }
    }

    if (-not $record) {
        # Merge nslookup stderr into stdout (2>&1) rather than 2>$null. Native
        # command stderr on pwsh 7 / Windows does not reliably honor 2>$null
        # and leaks "*** UnKnown can't find _dmarc.<domain>: Non-existent
        # domain" into the transcript. Merging keeps it inside $output, which
        # we only scan for DMARC1 lines.
        try {
            $output = & nslookup -type=TXT "_dmarc.$Domain" 2>&1 | Out-String
            if ($output -match '"(v=DMARC1[^"]*)"') {
                $record = $Matches[1]
            } elseif ($output -match '(v=DMARC1[^\r\n]*)') {
                $record = $Matches[1]
            }
        } catch { }
    }

    if ($record) {
        $result.Record = $record
        if ($record -match 'p\s*=\s*(none|quarantine|reject)') {
            $result.Policy = $Matches[1].ToLower()
        } else {
            $result.Policy = 'unparseable'
        }
        if ($record -match 'pct\s*=\s*(\d+)') {
            $result.Pct = [int]$Matches[1]
        } else {
            $result.Pct = 100
        }
    }

    return $result
}

#endregion

#region Connection

# Warn if the module version is too old for reliable macOS/Linux support.
# REST-based cmdlets (no WSMan required) became the default in v3.2.0.
$installedModule = Get-Module ExchangeOnlineManagement -ListAvailable |
    Sort-Object Version -Descending | Select-Object -First 1
if ($installedModule -and $installedModule.Version -lt [Version]'3.2.0') {
    Write-Warning "ExchangeOnlineManagement v$($installedModule.Version) detected. v3.2.0 or later is required on macOS/Linux."
    Write-Warning 'Run: Install-Module ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser'
}

$connectParams = @{ ShowBanner = $false }
if ($DelegatedOrganization) {
    $connectParams['DelegatedOrganization'] = $DelegatedOrganization
}

# UseRPSSession:$false forces REST-based auth (no WSMan/WinRM) on all platforms.
# The parameter exists in v3.0-3.3; removed in v3.4+ where REST is the only mode.
# Without this, older module versions default to WSMan which is unavailable on macOS/Linux.
$exoCmd = Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue
if ($exoCmd -and $exoCmd.Parameters.ContainsKey('UseRPSSession')) {
    $connectParams['UseRPSSession'] = $false
}

# On Windows, Connect-ExchangeOnline defaults to the WAM broker, which pops a
# native Windows account picker instead of a browser and also trips the known
# WAM GDAP token bug ("The role assigned to user ... isn't supported in this
# scenario"). Default here is to pass -DisableWAM so auth goes through the
# browser; -UseWAM opts back in to the WAM broker.
if (-not $UseWAM -and $exoCmd -and $exoCmd.Parameters.ContainsKey('DisableWAM')) {
    $connectParams['DisableWAM'] = $true
}

$existingConnection = $null
try {
    # Get-ConnectionInformation was added in ExchangeOnlineManagement v3.0
    $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Connected' } |
        Select-Object -First 1
} catch { }

if ($NewSession -and $existingConnection) {
    Write-Host "Disconnecting existing session ($($existingConnection.Organization)) for fresh login..." -ForegroundColor Cyan
    Disconnect-ExchangeOnline -Confirm:$false
    $existingConnection = $null
}

if (-not $existingConnection) {
    Write-Host 'Connecting to Exchange Online...' -ForegroundColor Cyan
    Connect-ExchangeOnline @connectParams
} elseif ($DelegatedOrganization -and $existingConnection.Organization -notlike "*$DelegatedOrganization*") {
    Write-Warning "Current session is '$($existingConnection.Organization)' but '$DelegatedOrganization' was requested. Reconnecting."
    Disconnect-ExchangeOnline -Confirm:$false
    Connect-ExchangeOnline @connectParams
} else {
    Write-Host "Using existing Exchange Online session: $($existingConnection.Organization)" -ForegroundColor Cyan
}

#endregion

#region Diagnostic schema dump

if ($ShowSchema) {
    $bar = '=' * 70
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host 'SCHEMA DIAGNOSTIC MODE' -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor Cyan
    Write-Host ''

    # Find one message to inspect -- try last 48h, then expand to 7 days if nothing found
    $sample = Get-MessageTraceV2 -StartDate (Get-Date).AddHours(-48) -EndDate (Get-Date) -ResultSize 1
    if (-not $sample) {
        Write-Host 'No messages in last 48h, expanding to 7 days...' -ForegroundColor Gray
        $sample = Get-MessageTraceV2 -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -ResultSize 1
    }
    if (-not $sample) {
        throw 'No messages found in the last 7 days. Cannot inspect schema.'
    }

    Write-Host '--- Get-MessageTraceV2 output (one record) ---' -ForegroundColor Yellow
    $sample | Format-List *
    Write-Host ''

    Write-Host '--- Property names only ---' -ForegroundColor Yellow
    ($sample | Select-Object -First 1).PSObject.Properties | ForEach-Object {
        '{0,-30} {1}' -f $_.Name, $_.TypeNameOfValue
    }
    Write-Host ''

    # Now pull the detail events for the same message
    Write-Host '--- Get-MessageTraceDetailV2 events (all events for this message) ---' -ForegroundColor Yellow
    $traceId = $sample.MessageTraceId
    $recipient = $sample.RecipientAddress
    Write-Host "MessageTraceId   : $traceId" -ForegroundColor Gray
    Write-Host "RecipientAddress : $recipient" -ForegroundColor Gray
    Write-Host ''

    $details = Get-MessageTraceDetailV2 -MessageTraceId $traceId -RecipientAddress $recipient
    if (-not $details) {
        Write-Warning 'Get-MessageTraceDetailV2 returned no results for this message.'
    } else {
        $details | Format-List *

        Write-Host ''
        Write-Host '--- Detail event property names only ---' -ForegroundColor Yellow
        ($details | Select-Object -First 1).PSObject.Properties | ForEach-Object {
            '{0,-30} {1}' -f $_.Name, $_.TypeNameOfValue
        }
    }

    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host 'Diagnostic complete. Share the output above to identify usable fields.' -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor Cyan
    return
}

#endregion

#region Schema detection
# Get-MessageTraceV2 output properties are not documented; discover them from a live record
# before committing to property names that drive the filter and pagination logic.

Write-Host 'Detecting Get-MessageTraceV2 output schema...' -ForegroundColor Cyan

$schemaRecord = Get-MessageTraceV2 -StartDate (Get-Date).AddHours(-24) -EndDate (Get-Date) -ResultSize 1

$connectorPropName = $null
$receivedPropName  = $null

if ($schemaRecord) {
    $props = ($schemaRecord | Select-Object -First 1).PSObject.Properties.Name
    Write-Verbose "Discovered properties: $($props -join ', ')"

    # Connector property -- blank for Direct Send, populated for authenticated/relay
    $connectorPropName = $props | Where-Object { $_ -match '(?i)connector' } | Select-Object -First 1

    # Received timestamp -- used for pagination (EndDate = last record's received time)
    $receivedPropName = $props | Where-Object { $_ -match '(?i)received' } | Select-Object -First 1
}

if (-not $connectorPropName) {
    Write-Warning @'
No connector-related property found in Get-MessageTraceV2 output.
Run this to inspect available properties:
  Get-MessageTraceV2 -ResultSize 1 | Format-List *

Results will be filtered by accepted sender domain only (connector filter not applied).
This may include non-Direct-Send messages. Verify your results manually.
'@
} else {
    Write-Host "Connector filter property : $connectorPropName" -ForegroundColor Cyan
}

if (-not $receivedPropName) {
    if (-not $schemaRecord) {
        Write-Warning 'No messages found in last 24h for schema detection. Assuming property names: Received, ConnectorId.'
        $receivedPropName  = 'Received'
        $connectorPropName = $connectorPropName ?? 'ConnectorId'
    } else {
        throw @"
No received-timestamp property found in output.
Run: Get-MessageTraceV2 -ResultSize 1 | Format-List *
to identify the correct property, then pass it to the script.
"@
    }
} else {
    Write-Host "Received timestamp property: $receivedPropName" -ForegroundColor Cyan
}

#endregion

#region Accepted domains

if ($PSBoundParameters.ContainsKey('AcceptedDomains') -and $AcceptedDomains.Count -gt 0) {
    $domainSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $AcceptedDomains) {
        $null = $domainSet.Add($d.TrimStart('@').ToLower())
    }
    Write-Host "Using provided accepted domains: $($domainSet -join ', ')" -ForegroundColor Cyan
} else {
    Write-Host 'Detecting accepted domains...' -ForegroundColor Cyan
    $domainSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Get-AcceptedDomain | ForEach-Object { $null = $domainSet.Add($_.DomainName.ToLower()) }
    Write-Host "Found $($domainSet.Count) accepted domain(s): $($domainSet -join ', ')" -ForegroundColor Cyan
}

if ($domainSet.Count -eq 0) {
    throw 'No accepted domains found or provided. Use -AcceptedDomains to specify them manually.'
}

#endregion

#region Build 10-day query windows (newest first)

$now        = Get-Date
$rangeEnd   = $now.Date.AddDays(1).AddSeconds(-1)   # 23:59:59 today
$rangeStart = $now.Date.AddDays(-$Days)

$chunks = [System.Collections.Generic.List[hashtable]]::new()
$windowEnd = $rangeEnd
while ($windowEnd -gt $rangeStart) {
    $windowStart = $windowEnd.Date.AddDays(-9)       # 10 calendar days per window
    if ($windowStart -lt $rangeStart) { $windowStart = $rangeStart }
    $chunks.Add(@{ Start = $windowStart; End = $windowEnd })
    $windowEnd = $windowStart.AddSeconds(-1)
}

Write-Host "Searching $Days day(s) across $($chunks.Count) query window(s)..." -ForegroundColor Cyan

#endregion

#region Query and filter

$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$seenIds    = [System.Collections.Generic.HashSet[string]]::new()
$chunkNum   = 0

foreach ($chunk in $chunks) {
    $chunkNum++
    Write-Host "  [$chunkNum/$($chunks.Count)] $($chunk.Start.ToString('yyyy-MM-dd')) to $($chunk.End.ToString('yyyy-MM-dd'))" -ForegroundColor Gray

    $chunkWindowEnd    = $chunk.End
    $startingRecipient = $null

    do {
        $queryParams = @{
            StartDate  = $chunk.Start
            EndDate    = $chunkWindowEnd
            ResultSize = 5000
        }
        # Pagination: per docs, use StartingRecipientAddress + updated EndDate (last record's received time)
        if ($startingRecipient) {
            $queryParams['StartingRecipientAddress'] = $startingRecipient
        }

        $batch = @(Get-MessageTraceV2 @queryParams)

        foreach ($msg in $batch) {
            # Filter 1: no connector = unauthenticated path (Direct Send via MX)
            # Skip filter 1 if connector property wasn't found in schema detection
            $passesConnectorFilter = (-not $connectorPropName) -or [string]::IsNullOrEmpty($msg.$connectorPropName)
            if (-not $passesConnectorFilter) { continue }

            # Filter 2: FromIP must be non-empty
            # Authenticated internal email (OWA, Outlook, MAPI) has no external SMTP source,
            # so FromIP is blank in the trace. Direct Send always has a source IP because the
            # device physically opened a TCP/SMTP connection to the MX endpoint.
            # This is what excludes legitimate internal emails from the results after
            # Direct Send is disabled -- they share blank ConnectorId but have no FromIP.
            if ([string]::IsNullOrEmpty($msg.FromIP)) { continue }

            $senderDomain = if ($msg.SenderAddress -match '@(.+)$') { $Matches[1].ToLower() } else { '' }
            $recipientDomain = if ($msg.RecipientAddress -match '@(.+)$') { $Matches[1].ToLower() } else { '' }

            # Filter 3: sender must claim an accepted domain
            # Filter 4: recipient must also be an accepted domain
            # Direct Send arrives at the tenant MX and delivers to an INTERNAL mailbox.
            # External recipients cannot receive via Direct Send -- the device would send
            # to their MX directly, not through this tenant's MX first.
            if (-not ($senderDomain -and $domainSet.Contains($senderDomain))) { continue }
            if (-not ($recipientDomain -and $domainSet.Contains($recipientDomain))) { continue }

            $traceId = $msg.MessageTraceId.ToString()
            if ($seenIds.Add($traceId)) {
                $allResults.Add([PSCustomObject]@{
                    DateTime = $msg.$receivedPropName
                    From = $msg.SenderAddress
                    To = $msg.RecipientAddress
                    Subject = $msg.Subject
                    Status = $msg.Status
                    FromIP = $msg.FromIP
                    MessageTraceId = $traceId
                })
            }
        }

        # Pagination: if full page returned, advance window using last record's values
        if ($batch.Count -eq 5000) {
            $last              = $batch | Select-Object -Last 1
            $chunkWindowEnd    = $last.$receivedPropName
            $startingRecipient = $last.RecipientAddress
        }

    } while ($batch.Count -eq 5000)

    # Brief pause between chunks -- rate limit is 100 requests per 5-minute window
    if ($chunkNum -lt $chunks.Count) {
        Start-Sleep -Milliseconds 500
    }
}

#endregion

#region Deep inspection (authoritative ConnectorId from Detail event Data XML)

if (-not $NoDeepInspect -and $allResults.Count -gt 0) {
    Write-Host ''
    Write-Host "Deep inspection: pulling detail events for $($allResults.Count) candidate(s)..." -ForegroundColor Cyan
    Write-Host 'Rate-limited to 100 requests per 5 minutes. Sliding-window pacing.' -ForegroundColor Gray

    $deepResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $excludedCustomConnector = 0
    $excludedInternalRelay = 0

    # Sliding-window rate limiter: 100 requests per 300 seconds.
    # Track timestamps of every detail call; before each new call, purge timestamps
    # older than 5 minutes, and if we're still at 100, wait until the oldest slides
    # out of the window. This lets the first 100 burst through, then paces after.
    $windowSize = 100
    $windowSeconds = 300
    $requestTimes = [System.Collections.Generic.Queue[DateTime]]::new()

    for ($i = 0; $i -lt $allResults.Count; $i++) {
        $record = $allResults[$i]
        $pct = [int](($i / $allResults.Count) * 100)
        Write-Progress -Activity 'Deep inspection' -Status "$($i + 1) / $($allResults.Count) -- kept $($deepResults.Count)" -PercentComplete $pct

        # Sliding-window rate limit: purge expired, wait if at capacity
        $now = Get-Date
        while ($requestTimes.Count -gt 0 -and ($now - $requestTimes.Peek()).TotalSeconds -gt $windowSeconds) {
            [void]$requestTimes.Dequeue()
        }
        if ($requestTimes.Count -ge $windowSize) {
            $waitSeconds = [Math]::Ceiling($windowSeconds - ($now - $requestTimes.Peek()).TotalSeconds) + 2
            Write-Progress -Activity 'Deep inspection' -Status "Rate limit: waiting ${waitSeconds}s (at request $($i + 1) / $($allResults.Count))" -PercentComplete $pct
            Start-Sleep -Seconds $waitSeconds
            [void]$requestTimes.Dequeue()
        }
        $requestTimes.Enqueue((Get-Date))

        $connectorId = ''
        $proxiedClientIP = ''
        $proxiedClientHostname = ''
        $returnPath = ''
        $scl = $null
        $events = @()

        # Throttle recovery: "surpassed the permitted limit" is Microsoft's
        # identity-level 100/5min limit for Get-MessageTraceDetailV2. When the
        # wrapper runs multiple GDAP tenants in parallel as the same partner
        # user they share one quota, so the local sliding-window here cannot
        # see or prevent cross-process saturation. Progressive backoff (60s ->
        # 180s -> 300s, up to 3 retries) and clear the local window each time
        # so we don't burn the retry re-hammering the same saturated bucket.
        $throttleBackoffs = @(60, 180, 300)
        $maxAttempts = $throttleBackoffs.Count + 1
        $throttleAttempts = 0
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            try {
                $events = @(Get-MessageTraceDetailV2 -MessageTraceId $record.MessageTraceId -RecipientAddress $record.To -ErrorAction Stop)
                break
            } catch {
                if ($_.Exception.Message -match 'surpassed the permitted limit' -and $throttleAttempts -lt $throttleBackoffs.Count) {
                    $wait = $throttleBackoffs[$throttleAttempts]
                    $throttleAttempts++
                    Write-Host ''
                    Write-Host "Throttled at request $($i + 1)/$($allResults.Count); cooling down ${wait}s (retry $throttleAttempts/$($throttleBackoffs.Count))" -ForegroundColor Yellow
                    Write-Progress -Activity 'Deep inspection' -Status "Throttled; cooling down ${wait}s (retry $throttleAttempts/$($throttleBackoffs.Count))" -PercentComplete $pct
                    Start-Sleep -Seconds $wait
                    $requestTimes.Clear()
                    $requestTimes.Enqueue((Get-Date))
                    continue
                }
                Write-Warning "Detail lookup failed for $($record.MessageTraceId): $($_.Exception.Message)"
                break
            }
        }

        # Parse Receive event Data XML for ConnectorId and CustomData blob
        $receive = $events | Where-Object { $_.Event -eq 'Receive' } | Select-Object -First 1
        if ($receive -and $receive.Data) {
            try {
                $xml = [xml]$receive.Data
                foreach ($mep in $xml.root.MEP) {
                    switch ($mep.Name) {
                        'ConnectorId' { $connectorId = [string]$mep.String }
                        'ReturnPath' { $returnPath = [string]$mep.String }
                        'CustomData' {
                            $blob = [string]$mep.Blob
                            if ($blob -match 'ProxiedClientIPAddress=([^;]+)') { $proxiedClientIP = $Matches[1] }
                            if ($blob -match 'ProxiedClientHostname=([^;]+)') { $proxiedClientHostname = $Matches[1] }
                        }
                    }
                }
            } catch {
                Write-Verbose "Failed to parse Receive Data XML for $($record.MessageTraceId): $_"
            }
        }

        # Parse Spam event for SCL if present (only for flagged messages)
        $spamEvent = $events | Where-Object { $_.Event -eq 'Spam' } | Select-Object -First 1
        if ($spamEvent -and $spamEvent.Data) {
            try {
                $xml = [xml]$spamEvent.Data
                $sclMep = $xml.root.MEP | Where-Object { $_.Name -eq 'SCL' } | Select-Object -First 1
                if ($sclMep) { $scl = [int]$sclMep.Integer }
            } catch {
                Write-Verbose "Failed to parse Spam Data XML for $($record.MessageTraceId): $_"
            }
        }

        # Authoritative filter: the "\Default " pattern in ConnectorId means no configured
        # inbound connector matched -- this is the Direct Send / anonymous MX path per
        # Microsoft's Reject Direct Send documentation. Custom connector (CodeTwo, hybrid,
        # partner relay) names don't contain this pattern and are excluded here.
        if ($connectorId -and $connectorId -notmatch '\\Default\s') {
            $excludedCustomConnector++
            continue
        }

        # Classify based on ProxiedClientHostname pattern.
        # Anonymous external SMTP connections leave EOP logging a "proxied client"
        # hostname. Spammers rarely provide a valid HELO hostname, so EOP records
        # the source IP in brackets -- the "[127.0.0.1]" / "[<ip>]" pattern is the
        # signature of Direct Send spam. Normal hostnames (google.com, etc.) are
        # plausible for legitimate external mail services. Empty means EOP did
        # not treat this as anonymous inbound -- typically an on-prem/hybrid
        # relay that Reject Direct Send does NOT affect.
        $category = if ($proxiedClientHostname -match '^\[.+\]$') { 'SpamLikely' }
                    elseif ($proxiedClientHostname) { 'AnonymousExternal' }
                    else { 'InternalRelay' }

        # Default: exclude InternalRelay (not affected by Reject Direct Send).
        # Pass -IncludeInternalRelay to see it.
        if ($category -eq 'InternalRelay' -and -not $IncludeInternalRelay) {
            $excludedInternalRelay++
            continue
        }

        # Reject Direct Send evaluates the P1 envelope sender (ReturnPath), not the
        # P2 header From. ESPs like Postmark, SendGrid, and Mailgun that use a custom
        # return-path subdomain (e.g., pmsv-bounces.servantvoice.com) slide through
        # RDS even though their From header is an accepted domain, because the
        # subdomain isn't itself an accepted domain. Compute RdsAffected honestly
        # from ReturnPath so users can see which rows are actually at risk vs. which
        # just *look* at-risk based on the From header filter alone.
        $returnPathDomain = if ($returnPath -match '@(.+)$') { $Matches[1].ToLower() } else { '' }
        $rdsAffected = $null
        if ($returnPathDomain) {
            $rdsAffected = $domainSet.Contains($returnPathDomain)
        }

        $deepResults.Add([PSCustomObject]@{
            DateTime = $record.DateTime
            From = $record.From
            To = $record.To
            Subject = $record.Subject
            Status = $record.Status
            Category = $category
            RdsAffected = $rdsAffected
            FromIP = $record.FromIP
            ConnectorId = $connectorId
            ReturnPath = $returnPath
            ProxiedClientIP = $proxiedClientIP
            ProxiedClientHostname = $proxiedClientHostname
            SCL = $scl
            MessageTraceId = $record.MessageTraceId
        })
    }

    Write-Progress -Activity 'Deep inspection' -Completed
    Write-Host "  Inspected $($allResults.Count); excluded $excludedCustomConnector via custom connector, $excludedInternalRelay internal relay; kept $($deepResults.Count)." -ForegroundColor Cyan

    $allResults = $deepResults
}

#endregion

#region Output

$results = $allResults | Sort-Object DateTime -Descending

$bar = '=' * 54
Write-Host ''
Write-Host $bar -ForegroundColor Cyan
if ($connectorPropName) {
    Write-Host "Direct Send messages found : $($results.Count)"    -ForegroundColor $(if ($results.Count -gt 0) { 'Yellow' } else { 'Green' })
} else {
    Write-Host "Domain-matched messages    : $($results.Count) (connector filter not applied -- see warnings above)" -ForegroundColor Yellow
}
Write-Host "Date range (UTC)           : $($rangeStart.ToString('yyyy-MM-dd')) to $($now.ToString('yyyy-MM-dd'))"
Write-Host "Accepted domains searched  : $($domainSet -join ', ')"
Write-Host $bar -ForegroundColor Cyan

# Source summary -- group by ProxiedClientHostname so the user can see
# at a glance which IPs/hostnames account for the traffic. This is the
# key view for planning a Reject Direct Send rollout: clusters of the
# same hostname on legitimate-looking entries usually indicate a service
# that needs an inbound connector before cutover (CodeTwo, on-prem
# relay, transactional mail provider, etc.).
if ($results.Count -gt 0 -and ($results | Get-Member -Name ProxiedClientHostname -ErrorAction SilentlyContinue)) {
    Write-Host ''
    Write-Host 'Top sources (ProxiedClientHostname):' -ForegroundColor Cyan

    $grouped = $results | ForEach-Object {
        # Flatten each row to (hostname, category, rdsAffected) so the grouping
        # can aggregate the actually-RDS-affected count per hostname cluster.
        # Blank hostnames show as "<empty>" for visibility.
        [PSCustomObject]@{
            Hostname = if ([string]::IsNullOrEmpty($_.ProxiedClientHostname)) { '<empty>' } else { $_.ProxiedClientHostname }
            Category = $_.Category
            RdsAffected = $_.RdsAffected
        }
    } | Group-Object Hostname | Sort-Object Count -Descending

    # Compute the longest hostname length for padding. Measure-Object -Maximum on
    # string properties is version-sensitive, so compute directly with Select-Object.
    $longestHost = 0
    foreach ($g in $grouped) {
        if ($g.Name.Length -gt $longestHost) { $longestHost = $g.Name.Length }
    }
    $colWidth = [Math]::Max(20, [Math]::Min(48, $longestHost))

    foreach ($g in $grouped) {
        $category = ($g.Group | Select-Object -First 1).Category
        $color = switch ($category) {
            'SpamLikely'        { 'Red' }
            'AnonymousExternal' { 'Yellow' }
            'InternalRelay'     { 'Gray' }
            default             { 'White' }
        }
        # Count how many rows in this cluster would actually be blocked by RDS
        # (ReturnPath domain matches an accepted domain). The remainder have a
        # subdomain or external ReturnPath and slide past RDS automatically.
        $rdsCount = @($g.Group | Where-Object { $_.RdsAffected -eq $true }).Count
        $rdsTag = if ($g.Group.Count -eq 0) { '' }
                  elseif ($rdsCount -eq $g.Group.Count) { '  [RDS blocks all]' }
                  elseif ($rdsCount -eq 0) { '  [RDS blocks none]' }
                  else { "  [RDS blocks $rdsCount/$($g.Group.Count)]" }
        $hostDisplay = if ($g.Name.Length -gt $colWidth) { $g.Name.Substring(0, $colWidth - 1) + '…' } else { $g.Name }
        $padded = $hostDisplay.PadRight($colWidth)
        $countStr = $g.Count.ToString().PadLeft(5)
        Write-Host "  $padded  $countStr  $category$rdsTag" -ForegroundColor $color
    }

    Write-Host ''
    Write-Host 'Color key: Red = SpamLikely, Yellow = AnonymousExternal, Gray = InternalRelay' -ForegroundColor DarkGray
    Write-Host 'Clusters of the same AnonymousExternal hostname often represent a legitimate' -ForegroundColor DarkGray
    Write-Host 'service (signature platform, relay, transactional mail) that will be blocked by' -ForegroundColor DarkGray
    Write-Host 'Reject Direct Send unless an inbound connector is configured with its IPs.' -ForegroundColor DarkGray
    Write-Host 'The [RDS blocks N/M] tag shows actual impact: ESPs using a custom return-path' -ForegroundColor DarkGray
    Write-Host 'subdomain (Postmark-style) will show [RDS blocks none] -- no action needed.' -ForegroundColor DarkGray
    Write-Host $bar -ForegroundColor Cyan
}

# ReturnPath domain summary -- group by the P1 envelope sender domain, with a
# classification against the accepted-domain set. RDS blocks exact-match accepted
# domains; subdomains of accepted domains and external domains pass through.
# This is the most direct view of "who will be affected by RDS" for the admin.
$returnPathGrouped = $null
if ($results.Count -gt 0 -and ($results | Get-Member -Name ReturnPath -ErrorAction SilentlyContinue)) {
    Write-Host ''
    Write-Host 'ReturnPath (P1 envelope sender) domains:' -ForegroundColor Cyan

    $returnPathGrouped = $results | ForEach-Object {
        $rpDomain = if ($_.ReturnPath -match '@(.+)$') { $Matches[1].ToLower() } else { '<empty>' }
        [PSCustomObject]@{
            Domain = $rpDomain
            Full = $_.ReturnPath
        }
    } | Group-Object Domain | Sort-Object Count -Descending

    # Classify each domain against accepted-domain set
    $rpClassified = foreach ($g in $returnPathGrouped) {
        $classification = if ($g.Name -eq '<empty>') { 'unknown' }
                          elseif ($domainSet.Contains($g.Name)) { 'accepted' }
                          else {
                              $isSubdomain = $false
                              foreach ($accepted in $domainSet) {
                                  if ($g.Name.EndsWith(".$accepted")) { $isSubdomain = $true; break }
                              }
                              if ($isSubdomain) { 'subdomain' } else { 'external' }
                          }
        [PSCustomObject]@{
            Domain = $g.Name
            Count = $g.Count
            Classification = $classification
        }
    }

    $rpColWidth = 0
    foreach ($r in $rpClassified) {
        if ($r.Domain.Length -gt $rpColWidth) { $rpColWidth = $r.Domain.Length }
    }
    $rpColWidth = [Math]::Max(20, [Math]::Min(48, $rpColWidth))

    foreach ($r in $rpClassified) {
        $color = switch ($r.Classification) {
            'accepted'  { 'Red' }
            'subdomain' { 'Green' }
            'external'  { 'Cyan' }
            'unknown'   { 'DarkGray' }
            default     { 'White' }
        }
        $rdsBehavior = switch ($r.Classification) {
            'accepted'  { '[RDS BLOCKS]      accepted domain' }
            'subdomain' { '[RDS passes]      subdomain of accepted' }
            'external'  { '[RDS passes]      external domain' }
            'unknown'   { '[RDS unknown]     empty/unparseable' }
            default     { '' }
        }
        $domainDisplay = if ($r.Domain.Length -gt $rpColWidth) { $r.Domain.Substring(0, $rpColWidth - 1) + '…' } else { $r.Domain }
        $padded = $domainDisplay.PadRight($rpColWidth)
        $countStr = $r.Count.ToString().PadLeft(5)
        Write-Host "  $padded  $countStr  $rdsBehavior" -ForegroundColor $color
    }

    Write-Host ''
    Write-Host 'Only Red (accepted-domain) rows are impacted by Reject Direct Send.' -ForegroundColor DarkGray
    Write-Host 'Green (subdomain) and Cyan (external) rows slide past RDS automatically -- no' -ForegroundColor DarkGray
    Write-Host 'allowlist work needed. For Red rows, create an inbound connector OR ask the' -ForegroundColor DarkGray
    Write-Host 'sender to switch to a custom return-path subdomain (like Postmark does).' -ForegroundColor DarkGray
    Write-Host $bar -ForegroundColor Cyan
}

# DMARC policy check per accepted domain. When Reject Direct Send is enabled with
# shared-certificate connectors (e.g., *.smtp.sendgrid.net), defense-in-depth
# depends on DMARC enforcement -- p=none undermines the approach because auth
# failures aren't acted on, letting any tenant of the shared service potentially
# spoof accepted domains through the allowlisted path.
Write-Host ''
Write-Host 'DMARC policy per accepted domain:' -ForegroundColor Cyan

$domainColWidth = 0
foreach ($d in $domainSet) {
    if ($d.Length -gt $domainColWidth) { $domainColWidth = $d.Length }
}
if ($domainColWidth -lt 20) { $domainColWidth = 20 }

foreach ($domain in ($domainSet | Sort-Object)) {
    $info = Get-DmarcInfo -Domain $domain

    $color = switch ($info.Policy) {
        'reject' { 'Green' }
        'quarantine' { if ($info.Pct -lt 100) { 'Yellow' } else { 'Green' } }
        'none' { 'Red' }
        'no record' { 'Red' }
        default { 'Gray' }
    }

    $policyDisplay = "p=$($info.Policy)"
    if ($info.Policy -in @('none', 'quarantine', 'reject') -and $info.Pct -lt 100) {
        $policyDisplay += " (pct=$($info.Pct))"
    }

    $padded = $domain.PadRight($domainColWidth)
    Write-Host "  $padded  $policyDisplay" -ForegroundColor $color
}

Write-Host ''
Write-Host 'DMARC guidance:' -ForegroundColor DarkGray
Write-Host '  p=reject or p=quarantine (pct=100) is the safe baseline before enabling' -ForegroundColor DarkGray
Write-Host '  Reject Direct Send with shared-cert inbound connectors. p=none means auth' -ForegroundColor DarkGray
Write-Host '  failures are NOT acted on and an allowlisted shared cert could be abused.' -ForegroundColor DarkGray
Write-Host $bar -ForegroundColor Cyan

if ($OutputPath) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    # Append the source summary and DMARC block to the CSV as additional rows
    # so the full report is preserved in a single artifact. The appended section
    # uses the same row schema as the data but with a marker in the first column
    # so it's easy to filter out in Excel (sort/filter on DateTime) or parse.
    $csvAppend = [System.Collections.Generic.List[string]]::new()
    $csvAppend.Add('')
    $csvAppend.Add('"--- SUMMARY ---"')
    $csvAppend.Add('"Top sources (ProxiedClientHostname)","Count","Category","RdsBlocks"')
    if ($grouped) {
        foreach ($g in $grouped) {
            $cat = ($g.Group | Select-Object -First 1).Category
            $rdsCount = @($g.Group | Where-Object { $_.RdsAffected -eq $true }).Count
            $rdsBlocks = "$rdsCount/$($g.Group.Count)"
            $name = $g.Name -replace '"', '""'
            $csvAppend.Add('"' + $name + '","' + $g.Count + '","' + $cat + '","' + $rdsBlocks + '"')
        }
    }
    $csvAppend.Add('')
    $csvAppend.Add('"--- RETURNPATH DOMAINS ---"')
    $csvAppend.Add('"Domain","Count","Classification","RdsBehavior"')
    if ($rpClassified) {
        foreach ($r in $rpClassified) {
            $rdsBehavior = switch ($r.Classification) {
                'accepted' { 'blocks' }
                'subdomain' { 'passes' }
                'external' { 'passes' }
                'unknown' { 'unknown' }
                default { '' }
            }
            $domainCell = $r.Domain -replace '"', '""'
            $csvAppend.Add('"' + $domainCell + '","' + $r.Count + '","' + $r.Classification + '","' + $rdsBehavior + '"')
        }
    }
    $csvAppend.Add('')
    $csvAppend.Add('"--- DMARC POLICY ---"')
    $csvAppend.Add('"Domain","Policy","Pct","Record"')
    foreach ($domain in ($domainSet | Sort-Object)) {
        $info = Get-DmarcInfo -Domain $domain
        $policyCell = "p=$($info.Policy)"
        $pctCell = if ($null -ne $info.Pct) { $info.Pct.ToString() } else { '' }
        $recordCell = if ($info.Record) { ($info.Record -replace '"', '""') } else { '' }
        $csvAppend.Add('"' + $domain + '","' + $policyCell + '","' + $pctCell + '","' + $recordCell + '"')
    }
    Add-Content -Path $OutputPath -Value $csvAppend -Encoding UTF8

    $resolved = if (Test-Path $OutputPath) { (Resolve-Path $OutputPath).Path } else { $OutputPath }
    Write-Host ''
    Write-Host "Results exported to: $resolved" -ForegroundColor Green
    # Don't emit $results to the pipeline when a file was requested. Otherwise
    # the default table formatter prints every row at the end, scrolling the
    # source summary and DMARC block off the top of the terminal.
} else {
    $results
}

#endregion
