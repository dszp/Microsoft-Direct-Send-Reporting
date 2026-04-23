# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This repo ships two scripts whose versions are tracked independently in each
script's `.NOTES` block. The repo-level version below tracks the highest
notable change across both. Current component versions:

- `Get-DirectSendReport.ps1` — **1.3.0** (core auditor)
- `Run-DirectSendGDAPReports.ps1` — **1.0.0** (parallel GDAP fan-out wrapper)

## [Unreleased]

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
