#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Creates an Exchange Online inbound connector that allowlists a third-party
    sending service by IP, expanding any CIDR blocks larger than /24 into a list
    of /24 chunks first.

.DESCRIPTION
    Companion to Get-DirectSendReport.ps1. After the audit identifies a
    legitimate third-party sender (an ESP, a relay service, a marketing
    platform) currently delivering anonymously through the Direct Send path,
    use this script to create a named partner inbound connector that
    allowlists that service's IP ranges so the traffic survives a
    "Reject Direct Send" rollout.

    Why /24 expansion: New-InboundConnector accepts CIDR notation in
    -SenderIPAddresses, but in practice Exchange Online only honors entries
    of /24 or smaller. Larger blocks (e.g. /19, /20) are silently ignored
    or rejected at create time. This script expands every input CIDR with
    a prefix length less than 24 into the equivalent set of contiguous /24
    blocks. CIDR entries already at /24 (or smaller, e.g. /32 for a single
    host) are passed through unchanged.

    What the script does NOT do:
      * It does not set -SenderDomains by default. Pass -SenderDomains to
        scope the connector to specific accepted domains (recommended). If
        you omit it, Exchange's default applies, which is broader than you
        usually want -- review the README's "Allowlisting Legitimate Sources"
        section before running without -SenderDomains.
      * It does not check whether a connector with the same name already
        exists. New-InboundConnector will fail if one does; remove it first
        or pass a different -Name.
      * It does not enable or disable the connector beyond New-InboundConnector
        defaults (newly created connectors are enabled).

    The script uses -RequireTls $true and -RestrictDomainsToIPAddresses $true
    by default, matching the IP-only connector pattern documented in the
    project README. -ConnectorType defaults to Partner.

.PARAMETER ServiceName
    Friendly name of the third-party sending service (e.g. "SMTP.com",
    "SendGrid", "Mailgun"). Used to build the connector -Name and -Comment
    when those are not explicitly overridden.

.PARAMETER CidrRanges
    One or more CIDR ranges to allowlist. Mix prefix lengths freely;
    blocks larger than /24 (i.e. prefix < 24) are auto-expanded into /24
    chunks, and entries already /24 or smaller are passed through unchanged.
    Examples: "192.40.160.0/19", "74.91.80.0/20", "203.0.113.0/24",
    "198.51.100.42/32".

.PARAMETER Name
    Override the connector -Name. Defaults to "<ServiceName> Relay".

.PARAMETER Comment
    Override the connector -Comment. Defaults to a generated string that
    notes the service name and the original CIDR list (so a future admin
    inspecting the connector can see what was expanded).

.PARAMETER SenderDomains
    List of accepted domains the connector should match. If omitted, the
    script calls Get-AcceptedDomain after connecting and uses every
    accepted domain in the tenant *except* the routing/onmicrosoft domains
    (anything matching '*.onmicrosoft.com', which always includes the
    tenant.onmicrosoft.com and tenant.mail.onmicrosoft.com routing domains
    Microsoft attaches automatically). The resulting list is logged
    before the connector is created so you can confirm before continuing.

    The combination of -RestrictDomainsToIPAddresses $true with
    -SenderDomains tells Exchange "for mail claiming any of these
    domains, require the source IP to be in -SenderIPAddresses; otherwise
    reject." That is exactly the anti-spoofing posture you want for a
    vendor relay connector: only the legitimate vendor IPs may impersonate
    your own accepted domains.

    Do NOT pass '*'. With wildcard SenderDomains and
    -RestrictDomainsToIPAddresses $true, the rejection rule applies to
    mail claiming ANY domain -- which would block normal external MX
    traffic (Gmail, customer replies, vendor cold email, everything) that
    does not happen to originate from the allowlisted IPs. The script
    refuses '*' for that reason; pass explicit domains or omit the
    parameter to auto-populate from Get-AcceptedDomain.

    Override this default by passing an explicit list (e.g.
    'contoso.com','contoso.net') when you want a narrower scope -- e.g.
    only the brand domain that vendor sends as, ignoring sibling
    accepted domains the vendor never uses. Pass an explicit list that
    INCLUDES an onmicrosoft.com entry if you specifically want to allow
    the vendor to send as the routing domain (rare and not recommended).

    Note on subdomain return-path patterns: Exchange's SenderDomains
    matching is NOT recursive -- 'contoso.com' matches mail with envelope
    sender exactly in contoso.com, not 'bounces.contoso.com' or any other
    subdomain. ESPs that use a custom bounce subdomain (e.g.
    SendGrid/Postmark with 'bounces.<yourdomain>') therefore slide past
    this connector entirely (it does not apply to them) and continue
    through normal EOP flow. That is the same blind spot Reject Direct
    Send has and is the reason Get-DirectSendReport.ps1 surfaces the P1
    envelope ReturnPath domain in its summary.

.PARAMETER ConnectorType
    Connector type passed to New-InboundConnector. Default: Partner.
    Use OnPremises for an on-prem relay scenario.

.PARAMETER RequireTls
    Whether to require opportunistic TLS on inbound connections. Default: $true.

.PARAMETER Posture
    Selects between two connector postures. Default: 'Permissive'.

    Both postures successfully exempt the vendor's mail from Reject Direct
    Send (which is the audit's primary goal). The difference is in
    connector-layer anti-spoofing:

    'Strict' -- the IP list is enforced as a *filter* on top of
        sender-domain matching. The connector applies to mail claiming any
        of the -SenderDomains values; for that mail, the source IP MUST be
        in -SenderIPAddresses or the mail is REJECTED at the connector.
        Defense-in-depth: even before Reject Direct Send, mail claiming
        your tenant's domains from anywhere except the allowlisted IPs is
        rejected. Pair with explicit -SenderDomains (or omit -SenderDomains
        to auto-populate from Get-AcceptedDomain). '*' is rejected in this
        posture because it would also reject all external mail not from
        the allowlisted IPs (Gmail, customer replies, etc.).

        Underlying cmdlet flags: -RestrictDomainsToIPAddresses $true.
        Maps to the EAC radio "By verifying that the sender domain
        matches one of the following domains" with the IP-rejection
        security restriction also enabled.

    'Permissive' -- the IP list is the *identification* mechanism. The
        connector applies only to mail that arrives from one of
        -SenderIPAddresses; everything else does not match this connector
        at all and falls through to normal EOP flow (Reject Direct Send,
        SPF, DMARC, content filtering -- all still apply). -SenderDomains
        defaults to '*' here (correct in this mode -- it means "any
        envelope domain coming from these IPs is treated as partner
        mail"). There is no connector-layer rejection for spoofed-domain
        mail from other IPs.

        Underlying cmdlet flags: -RestrictDomainsToIPAddresses $false,
        -SenderDomains '*'. Maps to the EAC radio "By verifying that the
        IP address of the sending server matches".

    Choosing between them: Strict is "belt and suspenders" -- the
    connector itself rejects impersonation attempts at SMTP time.
    Permissive is "just exempt the vendor from Reject Direct Send" --
    cleaner connector, no list of accepted domains to keep in sync,
    relies on Reject Direct Send / SPF / DMARC as the spoofing defense.
    Strict requires you to update -SenderDomains every time a new
    accepted domain is onboarded (the script auto-populates from
    Get-AcceptedDomain at create-time but the connector itself does
    not auto-refresh later).

.PARAMETER DelegatedOrganization
    Customer tenant domain or tenant ID for GDAP/CSP delegated connections.
    Omit when connecting directly as Global Admin or Exchange Admin in the
    target tenant.

.PARAMETER UseWAM
    Opt in to Connect-ExchangeOnline's WAM (Web Account Manager) broker.
    By default this script passes -DisableWAM, mirroring Get-DirectSendReport.ps1,
    so Windows auth goes through the browser and side-steps the known WAM
    GDAP token bug. Ignored on macOS/Linux and on module versions that do
    not expose -DisableWAM.

.PARAMETER NoDisconnect
    Skip the trailing Disconnect-ExchangeOnline. Useful if you want to chain
    additional commands in the same session after the connector is created.

.PARAMETER SkipOverlapCheck
    Skip the existing-connector overlap check. By default the script calls
    Get-InboundConnector after connecting and compares every IP-restricted
    connector's SenderIPAddresses against the proposed /24 set, then warns
    (and prompts) when it finds overlap so the same IPs are not allowlisted
    twice under two different connector names. Use this only when you have
    already verified the existing connector layout out-of-band.

.PARAMETER Force
    Suppress the interactive confirmation prompt that fires when the overlap
    check finds existing connector(s) covering some of the same /24 ranges.
    Without -Force the script halts at the prompt and waits for a Y/N
    response; with -Force it proceeds straight to New-InboundConnector after
    emitting the warning. Has no effect when no overlap is detected.

.EXAMPLE
    # SMTP.com (the original use case), Permissive posture (default) --
    # expand /19 and /20 into 48 /24 blocks; the IP list is the partner
    # identification mechanism, -SenderDomains defaults to '*', no
    # connector-layer rejection of spoofed-domain mail (Reject Direct Send
    # and DMARC handle that). Equivalent to the EAC radio "By verifying
    # that the IP address of the sending server matches".
    .\New-Exchange365-InboundConnectorByIPRanges.ps1 `
        -ServiceName 'SMTP.com' `
        -CidrRanges '192.40.160.0/19','74.91.80.0/20'

.EXAMPLE
    # Strict posture -- the IP list is enforced as a filter on top of
    # -SenderDomains matching. Auto-populate -SenderDomains from
    # Get-AcceptedDomain (every accepted domain except '*.onmicrosoft.com'
    # routing domains). Rejects mail claiming any of those domains that
    # does not arrive from SMTP.com IPs at SMTP time.
    .\New-Exchange365-InboundConnectorByIPRanges.ps1 `
        -ServiceName 'SMTP.com' `
        -CidrRanges '192.40.160.0/19','74.91.80.0/20' `
        -Posture Strict

.EXAMPLE
    # Strict posture with an explicit -SenderDomains list (overrides the
    # Get-AcceptedDomain auto-population).
    .\New-Exchange365-InboundConnectorByIPRanges.ps1 `
        -ServiceName 'SMTP.com' `
        -CidrRanges '192.40.160.0/19','74.91.80.0/20' `
        -SenderDomains 'contoso.com','contoso.net' `
        -Posture Strict

.EXAMPLE
    # Generic vendor with documented /24 ranges already -- no expansion happens,
    # entries pass through unchanged.
    .\New-Exchange365-InboundConnectorByIPRanges.ps1 `
        -ServiceName 'AcmeRelay' `
        -CidrRanges '203.0.113.0/24','198.51.100.0/24'

.EXAMPLE
    # GDAP delegated, custom connector name and comment.
    .\New-Exchange365-InboundConnectorByIPRanges.ps1 `
        -ServiceName 'SMTP.com' `
        -CidrRanges '192.40.160.0/19','74.91.80.0/20' `
        -SenderDomains 'customer.com' `
        -Name 'SMTP.com (allowlisted 2026-04-24)' `
        -DelegatedOrganization customer.onmicrosoft.com

.EXAMPLE
    # Dry-run -- print the expanded /24 list and the New-InboundConnector
    # parameter set without actually creating anything.
    .\New-Exchange365-InboundConnectorByIPRanges.ps1 `
        -ServiceName 'SMTP.com' `
        -CidrRanges '192.40.160.0/19','74.91.80.0/20' `
        -SenderDomains 'contoso.com' `
        -WhatIf

.NOTES
    Version: 1.0.0

    Changelog:
      1.0.0 (2026-04-27) - Initial release. Generalize the original SMTP.com-
                           specific scratch script into a reusable helper.
                           Parameters: -ServiceName, -CidrRanges,
                           -SenderDomains, -Name, -Comment, -ConnectorType,
                           -RequireTls, -Posture (Strict | Permissive),
                           -DelegatedOrganization, -UseWAM, -NoDisconnect,
                           -SkipOverlapCheck, -Force; SupportsShouldProcess
                           for -WhatIf; inline "Known service IP ranges"
                           reference block (below). Two postures supported:
                           Permissive (default) treats the IP list as the
                           partner identification mechanism (-SenderDomains
                           defaults to '*'; no connector-layer rejection --
                           Reject Direct Send / SPF / DMARC handle
                           spoofing; this matches the EAC radio "By
                           verifying that the IP address of the sending
                           server matches"); Strict treats the IP list as
                           an enforcement filter on -SenderDomains-matched
                           mail (auto-populates accepted domains from
                           Get-AcceptedDomain when -SenderDomains is
                           omitted; rejects '*' because that combination
                           would block all external mail not from the
                           allowlisted IPs). Pre-create
                           overlap check inspects existing IP-restricted
                           inbound connectors and warns plus prompts when
                           proposed /24 ranges already overlap an
                           existing connector.
#>

# ---------------------------------------------------------------------------
# Known service IP ranges (reference)
# ---------------------------------------------------------------------------
# Curated list of source URLs for third-party senders an admin is likely to
# allowlist with this script. Verify each source page before relying on it --
# providers update their published ranges. Add new entries here so future
# users have a single place to look up the canonical list.
#
# SMTP.com
#   Ranges (as of original script authorship):
#       192.40.160.0/19
#       74.91.80.0/20
#   Source: https://knowledge.smtp.com/s/article/SPF-setup-for-SMTP-com-customers
#   Notes : The published SPF mechanisms are the authoritative source. Both
#           ranges are larger than /24 and therefore must be expanded -- this
#           script handles that automatically.
#
# Template for adding more services:
#   <Service Name>
#     Ranges:
#         <cidr1>
#         <cidr2>
#     Source: <vendor docs URL>
#     Notes : <anything noteworthy -- prefix sizes, regional splits, IPv6
#             availability, rotation cadence, etc.>
#
# ---------------------------------------------------------------------------

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceName,

    [Parameter(Mandatory = $true)]
    [string[]]$CidrRanges,

    [string]$Name,

    [string]$Comment,

    [string[]]$SenderDomains,

    [ValidateSet('Partner', 'OnPremises')]
    [string]$ConnectorType = 'Partner',

    [bool]$RequireTls = $true,

    [ValidateSet('Strict', 'Permissive')]
    [string]$Posture = 'Permissive',

    [string]$DelegatedOrganization,

    [switch]$UseWAM,

    [switch]$NoDisconnect,

    [switch]$SkipOverlapCheck,

    [switch]$Force
)

# ---- CIDR expansion helper ----

function Get-Slash24Coverage {
    <#
    .SYNOPSIS
        Return the set of /24 CIDR strings covered by an arbitrary list of
        SenderIPAddresses-style entries (single IPs, /N CIDRs). Used to
        compute overlap between proposed and existing connector ranges.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Entries
    )

    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($entry in $Entries) {
        if (-not $entry) { continue }
        $trimmed = $entry.Trim()
        if (-not $trimmed) { continue }

        if ($trimmed -match '^([0-9]{1,3}(?:\.[0-9]{1,3}){3})$') {
            $ip = $Matches[1]
            $prefix = 32
        } elseif ($trimmed -match '^([0-9]{1,3}(?:\.[0-9]{1,3}){3})/([0-9]{1,2})$') {
            $ip = $Matches[1]
            $prefix = [int]$Matches[2]
        } else {
            Write-Verbose "Skipping unrecognized entry '$trimmed' for /24 coverage."
            continue
        }
        if ($prefix -lt 0 -or $prefix -gt 32) { continue }

        $bytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
        if ($prefix -ge 24) {
            $bytes[3] = 0
            [void]$set.Add(("{0}/24" -f ($bytes -join '.')))
        } else {
            [Array]::Reverse($bytes)
            $startInt = [BitConverter]::ToUInt32($bytes, 0)
            $count = [int][Math]::Pow(2, 24 - $prefix)
            for ($i = 0; $i -lt $count; $i++) {
                $n = $startInt + ($i * 256)
                $b = [BitConverter]::GetBytes([uint32]$n)
                [Array]::Reverse($b)
                [void]$set.Add(("{0}/24" -f ($b -join '.')))
            }
        }
    }
    return $set
}

function Expand-CidrToSlash24 {
    <#
    .SYNOPSIS
        Expand a CIDR block with prefix < 24 into the contiguous list of /24
        sub-blocks. Pass-through for prefix >= 24.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Cidr
    )

    if ($Cidr -notmatch '^\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*/\s*([0-9]{1,2})\s*$') {
        throw "Invalid CIDR notation: '$Cidr' (expected 'A.B.C.D/N')."
    }
    $ip = $Matches[1]
    $prefix = [int]$Matches[2]
    if ($prefix -lt 0 -or $prefix -gt 32) {
        throw "Invalid CIDR prefix '/$prefix' in '$Cidr' (must be 0-32)."
    }

    if ($prefix -ge 24) {
        # Already /24 or smaller (more specific) -- pass through unchanged.
        return ,"$ip/$prefix"
    }

    $bytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [Array]::Reverse($bytes)
    $startInt = [BitConverter]::ToUInt32($bytes, 0)
    $count = [int][Math]::Pow(2, 24 - $prefix)

    0..($count - 1) | ForEach-Object {
        $n = $startInt + ($_ * 256)
        $b = [BitConverter]::GetBytes([uint32]$n)
        [Array]::Reverse($b)
        "$($b -join '.')/24"
    }
}

# ---- Resolve posture and validate -SenderDomains up front ----

$restrictToIPs = ($Posture -eq 'Strict')
Write-Host ("Posture: {0} (-RestrictDomainsToIPAddresses {1})" -f $Posture, $restrictToIPs)

# '*' is only catastrophic in Strict posture (-RestrictDomainsToIPAddresses $true).
# In Permissive posture the IP list is the identification mechanism and '*' is correct.
if ($restrictToIPs -and $SenderDomains -and ($SenderDomains -contains '*')) {
    throw "-SenderDomains '*' is rejected in Strict posture. That combination tells Exchange to reject every external sender (Gmail, customer replies, etc.) that does not come from the allowlisted IPs, which breaks normal inbound MX flow. Either pass an explicit list of your tenant's accepted domains (or omit -SenderDomains to auto-populate from Get-AcceptedDomain), or pass -Posture Permissive to use IP-based partner identification (in which case '*' is the correct value)."
}

# ---- Expand all input CIDRs ----

$expanded = foreach ($cidr in $CidrRanges) {
    Expand-CidrToSlash24 -Cidr $cidr
}
$expanded = @($expanded)

if ($expanded.Count -eq 0) {
    throw "No /24 entries were produced from -CidrRanges. Check the input."
}

Write-Host ("Expanded {0} input CIDR range(s) into {1} /24 entries." -f $CidrRanges.Count, $expanded.Count)

# ---- Build connector parameter set (without -SenderDomains; resolved post-connect) ----

if (-not $Name) {
    $Name = "$ServiceName Relay"
}
if (-not $Comment) {
    $Comment = "$ServiceName relay - expanded {0} input CIDR(s) ({1}) to {2} /24 block(s)" -f `
        $CidrRanges.Count, ($CidrRanges -join ', '), $expanded.Count
}

$connectorParams = @{
    Name                         = $Name
    ConnectorType                = $ConnectorType
    SenderIPAddresses            = $expanded
    RequireTls                   = $RequireTls
    RestrictDomainsToIPAddresses = $restrictToIPs
    Comment                      = $Comment
}

# ---- Connect to Exchange Online ----

$connectParams = @{
    ShowBanner = $false
}
if ($DelegatedOrganization) {
    $connectParams['DelegatedOrganization'] = $DelegatedOrganization
}
$disableWamSupported = (Get-Command Connect-ExchangeOnline).Parameters.ContainsKey('DisableWAM')
if ($disableWamSupported -and -not $UseWAM) {
    $connectParams['DisableWAM'] = $true
}
if ($IsMacOS -or $IsLinux) {
    $useRpsParam = (Get-Command Connect-ExchangeOnline).Parameters.ContainsKey('UseRPSSession')
    if ($useRpsParam) {
        $connectParams['UseRPSSession'] = $false
    }
}

Write-Host "Connecting to Exchange Online..."
Connect-ExchangeOnline @connectParams | Out-Null

# ---- Resolve -SenderDomains based on posture ----

if ($SenderDomains) {
    Write-Host ("Using -SenderDomains as supplied: {0}" -f ($SenderDomains -join ', '))
} elseif ($restrictToIPs) {
    Write-Host "No -SenderDomains supplied (Strict posture); querying Get-AcceptedDomain..."
    try {
        $allAccepted = @(Get-AcceptedDomain -ErrorAction Stop | Select-Object -ExpandProperty DomainName)
    } catch {
        throw "Could not retrieve accepted domains via Get-AcceptedDomain: $_. Pass -SenderDomains explicitly to bypass auto-population."
    }
    $SenderDomains = @($allAccepted | Where-Object { $_ -and ($_ -notlike '*.onmicrosoft.com') })
    $excluded = @($allAccepted | Where-Object { $_ -like '*.onmicrosoft.com' })
    if ($excluded.Count -gt 0) {
        Write-Host ("  Excluded {0} routing domain(s): {1}" -f $excluded.Count, ($excluded -join ', '))
    }
    if ($SenderDomains.Count -eq 0) {
        throw "Get-AcceptedDomain returned no usable accepted domains after filtering '*.onmicrosoft.com'. Pass -SenderDomains explicitly with a non-empty list."
    }
    Write-Host ("  Auto-populated -SenderDomains ({0}): {1}" -f $SenderDomains.Count, ($SenderDomains -join ', '))
} else {
    Write-Host "No -SenderDomains supplied (Permissive posture); defaulting to '*' (IP list is the partner identification)."
    $SenderDomains = @('*')
}
$connectorParams['SenderDomains'] = $SenderDomains

# ---- Overlap check against existing inbound connectors ----

if (-not $SkipOverlapCheck) {
    Write-Host "Checking existing inbound connectors for overlapping IP ranges..."
    $proposedSet = Get-Slash24Coverage -Entries $expanded

    $existing = @()
    try {
        $existing = @(Get-InboundConnector -ErrorAction Stop | Where-Object {
            $_.SenderIPAddresses -and $_.SenderIPAddresses.Count -gt 0
        })
    } catch {
        Write-Warning "Could not enumerate existing inbound connectors for overlap check: $_"
        Write-Warning "Proceeding without overlap check. Use -SkipOverlapCheck to silence this warning, or investigate the underlying error."
        $existing = @()
    }

    $overlaps = foreach ($conn in $existing) {
        $existingSet = Get-Slash24Coverage -Entries ([string[]]$conn.SenderIPAddresses)
        $shared = New-Object 'System.Collections.Generic.List[string]'
        foreach ($s in $proposedSet) {
            if ($existingSet.Contains($s)) { [void]$shared.Add($s) }
        }
        if ($shared.Count -gt 0) {
            [pscustomobject]@{
                Name      = $conn.Name
                Identity  = $conn.Identity
                Enabled   = $conn.Enabled
                Shared    = $shared
                TotalEx   = $existingSet.Count
            }
        }
    }
    $overlaps = @($overlaps)

    if ($overlaps.Count -gt 0) {
        foreach ($o in $overlaps) {
            $sample = ($o.Shared | Select-Object -First 5) -join ', '
            $more = if ($o.Shared.Count -gt 5) { ", ..." } else { '' }
            Write-Warning ("Existing inbound connector '{0}' (Enabled={1}) overlaps the proposed ranges: {2} of {3} /24 block(s) are already covered (e.g. {4}{5}). The new connector may duplicate or conflict with this one." -f `
                $o.Name, $o.Enabled, $o.Shared.Count, $o.TotalEx, $sample, $more)
        }
        Write-Warning "Recommended: inspect the overlapping connector(s) with 'Get-InboundConnector | Format-List Name,Enabled,SenderIPAddresses,SenderDomains,Comment', verify whether the existing IP ranges still match what the vendor publishes, remove the existing connector with 'Remove-InboundConnector -Identity <name>' if it is stale, then re-run this script."

        if (-not $Force) {
            $continueChoice = $PSCmdlet.ShouldContinue(
                "An existing inbound connector already covers some of the proposed /24 ranges. Continue creating '$Name' anyway?",
                'Overlapping inbound connector detected'
            )
            if (-not $continueChoice) {
                Write-Host "Aborted by user. No connector was created. Re-run after resolving the overlap, or pass -Force / -SkipOverlapCheck to bypass this prompt."
                if (-not $NoDisconnect) {
                    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
                }
                return
            }
        }
    } else {
        Write-Host "No overlapping IP ranges found in existing inbound connectors."
    }
}

# ---- Create the connector ----

$target = "Inbound connector '$Name' (ConnectorType=$ConnectorType, $($expanded.Count) /24 entries)"
if ($PSCmdlet.ShouldProcess($target, 'New-InboundConnector')) {
    try {
        New-InboundConnector @connectorParams | Out-Null
        Write-Host "Created inbound connector '$Name'."
    } catch {
        Write-Error "Failed to create inbound connector '$Name': $_"
        if (-not $NoDisconnect) {
            Disconnect-ExchangeOnline -Confirm:$false | Out-Null
        }
        throw
    }
} else {
    Write-Host "WhatIf: would create inbound connector with parameters:"
    $connectorParams.GetEnumerator() | Sort-Object Key | ForEach-Object {
        if ($_.Key -eq 'SenderIPAddresses') {
            Write-Host ("  {0,-30} = <{1} entries> (first 5: {2}{3})" -f `
                $_.Key, $_.Value.Count, (($_.Value | Select-Object -First 5) -join ', '), `
                $(if ($_.Value.Count -gt 5) { ', ...' } else { '' }))
        } else {
            Write-Host ("  {0,-30} = {1}" -f $_.Key, ($_.Value -join ', '))
        }
    }
}

# ---- Done ----

if (-not $NoDisconnect) {
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}
