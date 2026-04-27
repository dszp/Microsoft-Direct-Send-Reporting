# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This repo ships two scripts whose versions are tracked independently in each
script's `.NOTES` block. The repo-level version below tracks the highest
notable change across both. Current component versions:

- `Get-DirectSendReport.ps1` — **1.5.1** (core auditor)
- `Run-DirectSendGDAPReports.ps1` — **1.3.0** (parallel GDAP fan-out wrapper)
- `New-Exchange365-InboundConnectorByIPRanges.ps1` — **1.0.0** (IP-allowlist inbound connector helper)

## [1.7.0] - 2026-04-27

### Added

- `New-Exchange365-InboundConnectorByIPRanges.ps1` 1.0.0: new helper for the
  remediation step after the audit. Creates an Exchange Online inbound
  connector that allowlists a third-party sending service by IP, expanding
  any input CIDR larger than /24 into the equivalent set of /24 blocks first
  (Exchange Online only honors /24-or-smaller entries in
  `-SenderIPAddresses` in practice). Generalizes the previously SMTP.com-
  hardcoded scratch script into a reusable tool: `-ServiceName`,
  `-CidrRanges`, `-SenderDomains`, `-Name`, `-Comment`, `-ConnectorType`,
  `-RequireTls`, `-Posture` (Strict | Permissive), `-DelegatedOrganization`,
  `-UseWAM`, `-NoDisconnect`, `-SkipOverlapCheck`, and `-Force` parameters;
  `SupportsShouldProcess` for `-WhatIf` dry-runs. Two postures supported,
  selected via `-Posture`:
  - **Permissive** (default) — `-RestrictDomainsToIPAddresses $false` with
    `-SenderDomains '*'`. The IP list is the partner *identification*
    mechanism: only mail from those IPs matches the connector, everything
    else falls through to normal EOP / Reject Direct Send / SPF / DMARC.
    Matches the EAC radio "By verifying that the IP address of the
    sending server matches".
  - **Strict** — `-RestrictDomainsToIPAddresses $true` with an explicit
    `-SenderDomains` list. The IP list is enforced as a *filter* on
    `-SenderDomains`-matched mail: spoofed-domain mail from other IPs is
    rejected at SMTP time. When `-SenderDomains` is omitted in Strict
    posture, the script auto-populates from `Get-AcceptedDomain` (every
    accepted domain in the tenant except `*.onmicrosoft.com` routing
    domains). `'*'` is rejected outright in Strict posture because that
    combination would block all external mail not from the allowlisted
    IPs and break normal MX flow.

  Pre-create overlap check enumerates existing IP-restricted inbound
  connectors via `Get-InboundConnector`, computes their /24 coverage, and
  warns plus prompts when the proposed ranges overlap an existing
  connector so the same IPs are not allowlisted under two different
  connector names; `-Force` skips the prompt and `-SkipOverlapCheck`
  skips the check entirely. Defaults `Connect-ExchangeOnline` to
  `-DisableWAM` (matching `Get-DirectSendReport.ps1` 1.4.0) so Windows
  auth uses the browser flow and avoids the WAM GDAP token bug. Includes
  an inline "Known service IP ranges" reference block documenting the
  SMTP.com ranges and source URL, with a template for adding more
  services.

## [1.6.1] - 2026-04-23

### Changed

- `Get-DirectSendReport.ps1` 1.5.1: timestamp the deep-inspection
  messages so a `Start-Transcript` log is readable without guessing
  elapsed time. Throttle lines now include `[HH:mm:ss]` and an estimated
  resume time (e.g. `resume ~18:47:12`), and every 100 successful detail
  lookups emits a `[HH:mm:ss] Progress: N/total processed; kept X, ...`
  heartbeat line. Lets an operator tell "still pacing normally" from
  "actually stuck" at a glance when tailing a long run.

## [1.6.0] - 2026-04-23

### Changed

- `Run-DirectSendGDAPReports.ps1` 1.3.0: `-MaxParallel` default changes
  from 5 to 1 (sequential). `Get-MessageTraceDetailV2` is throttled to
  100 requests per 5 minutes *per user/identity*, not per tenant, so
  running multiple GDAP tenants in parallel as the same partner user
  divides one quota across them instead of adding throughput. Sequential
  is the correct default for shared-identity flows. Override with
  `-MaxParallel N` when you know you won't saturate the identity quota
  (small tenants, short `-Days`, or `-NoDeepInspect`). README updated
  to drop `-MaxParallel 5` from the example invocations.
- `Get-DirectSendReport.ps1` 1.5.0: progressive backoff on
  `Get-MessageTraceDetailV2` throttling. Previously a single 60s
  cooldown and one retry; now up to 3 retries with 60s → 180s → 300s
  cooldowns and the local sliding-window is cleared between retries so
  the next call doesn't immediately re-saturate the identity quota.
  Each cooldown is logged visibly so long pauses aren't mistaken for
  hangs.

## [1.5.1] - 2026-04-23

### Fixed

- `Get-DirectSendReport.ps1` 1.4.1: quiet the DMARC lookup noise that made
  per-tenant transcripts look like script failures when `_dmarc.<domain>`
  did not exist. `Resolve-DnsName` now uses `-ErrorAction SilentlyContinue`
  (NXDOMAIN no longer raises a caught terminating error that
  `Start-Transcript` logs) and the `nslookup` fallback merges stderr into
  stdout via `2>&1` (pwsh 7 on Windows does not reliably honor `2>$null`
  for native-command stderr, so `*** UnKnown can't find _dmarc.<domain>`
  was leaking into the transcript). Behavior is unchanged: missing DMARC
  records still report `p=no record` and the run continues.

## [1.5.0] - 2026-04-23

### Fixed

- `Run-DirectSendGDAPReports.ps1` 1.2.0: parameter-binding bug that caused
  every tenant to fail with
  `"Cannot process argument transformation on parameter 'Days'. Cannot convert value '<tenant>.onmicrosoft.com' to type 'System.Int32'"`.
  Child args were built as an array and splatted, but PowerShell array
  splatting is positional-only — `-Name` tokens inside the array are NOT
  interpreted as parameter names, so `-DelegatedOrganization` bound
  to position 0 as a literal string and the tenant value landed on
  `-Days`. Switched to hashtable splatting for the fixed named args and
  parse `-ScriptArgs` tokens into the same hashtable so forwarded args
  bind by name.

### Changed

- `Get-DirectSendReport.ps1` 1.4.0: default `Connect-ExchangeOnline` to
  `-DisableWAM` so Windows auth goes through the browser instead of the
  native WAM account picker. The default also avoids the known WAM GDAP
  token bug (`"The role assigned to user ... isn't supported in this scenario"`).
  New `-UseWAM` switch opts back in to the WAM broker for cached-SSO
  scenarios. Ignored on macOS/Linux and on module versions that don't
  expose `-DisableWAM`.
- `Run-DirectSendGDAPReports.ps1` 1.2.0: now forwards `-UseWAM` to the
  child script when the wrapper's `-DisableWAM` is `$false`, so
  pre-connect and child-script auth stay in sync with the main script's
  new DisableWAM-by-default behavior.

## [1.4.0] - 2026-04-23

### Added

- `Run-DirectSendGDAPReports.ps1` 1.1.0: new `-LogDir` parameter to control
  where per-tenant transcript logs are written. Logs now default to a
  `logs/` subfolder under `-OutputDir` (created automatically) instead of
  sitting next to the CSVs. Relative `-LogDir` values are resolved against
  `-OutputDir`. `logs/` is gitignored.

## [1.3.1] - 2026-04-23

### Fixed

- `Run-DirectSendGDAPReports.ps1` 1.0.1: the `-MaxParallel` throttle was
  inspecting `$_.State` on the wrapper objects rather than `$_.Job.State`,
  so the running-count always evaluated to zero and every tenant's
  `Connect-ExchangeOnline` browser prompt opened at once. Now correctly
  limits concurrent jobs to `-MaxParallel`.

## [1.3.0] - 2026-04-23

### Added

- `Get-DirectSendReport.ps1` 1.3.0: ReturnPath domain summary — a new console
  block and appended CSV summary rows that group results by the P1 envelope
  sender's domain so ESP bounce-subdomain patterns (e.g. `bounces.customer.com`)
  are visible at a glance.
- `Run-DirectSendGDAPReports.ps1` 1.0.0: new companion wrapper for partners
  auditing multiple GDAP-delegated customer tenants in parallel. Spawns one
  `pwsh` child per tenant via `Start-Job` (process isolation so each tenant
  gets its own Exchange Online session), throttles via `-MaxParallel`, reads
  tenant lists from a gitignored `tenants.txt`, names outputs per tenant, and
  pre-connects each child session with `-DisableWAM` to work around the WAM
  GDAP token bug that otherwise produces
  `"The role assigned to user ... isn't supported in this scenario"`.

## [1.2.0] - 2026-04-23

### Added

- `Get-DirectSendReport.ps1` 1.2.0: new `ReturnPath` and `RdsAffected` output
  columns. `ReturnPath` surfaces the P1 envelope sender (distinct from the P2
  header From); `RdsAffected` evaluates Reject Direct Send coverage based on
  the envelope sender against accepted domains. This exposes ESPs that use a
  custom return-path subdomain and would therefore slip past Reject Direct
  Send even when the display From looks in-tenant.

## [1.1.0] - 2026-04-22

### Changed

- `Get-DirectSendReport.ps1` 1.1.0: when `-OutputPath` is set, the source and
  DMARC summaries are now appended to the CSV as additional rows below the
  data (separated by a blank row and a marker row), and pipeline output is
  suppressed so the console summaries remain on screen instead of being
  scrolled off by the default table formatter.

## [1.0.1] - 2026-04-22

### Changed

- `Get-DirectSendReport.ps1` 1.0.1: documentation-only update — the post-run
  console summaries are now documented in the script's comment-based help.
  No behavior change.

## [1.0.0] - 2026-04-22

### Added

- Initial release of `Get-DirectSendReport.ps1`: four-stage Direct Send filter
  (Default-connector pattern in the Receive event Data XML, populated
  `FromIP`, accepted-domain sender and recipient, populated
  `ProxiedClientHostname`); `SpamLikely` / `AnonymousExternal` /
  `InternalRelay` categorization; 10-day `Get-MessageTraceV2` window
  auto-chunking up to 90 days; sliding 100-requests-per-5-minute rate limiter
  on `Get-MessageTraceDetailV2`; macOS/Linux REST-only auth support; GDAP/CSP
  delegation via `-DelegatedOrganization`; `-ShowSchema` diagnostic mode; and
  post-run source + DMARC console summaries.
