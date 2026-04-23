# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A single-purpose PowerShell audit toolkit for Microsoft 365 Exchange Online. It identifies which inbound messages would be blocked if Microsoft's "Reject Direct Send" feature were enabled, so admins can allowlist legitimate senders (via inbound connectors) before enabling the block. There is no build system, no test suite, no package — it's two `.ps1` scripts and a README.

Two scripts:

- `Get-DirectSendReport.ps1` — the core auditor. Runs against one tenant (direct login or one GDAP `-DelegatedOrganization`).
- `Run-DirectSendGDAPReports.ps1` — a parallel fan-out wrapper. For partners auditing many customer tenants, it spawns one `pwsh` child process per tenant from `tenants.txt` so each tenant gets an isolated Exchange Online session, throttled by `-MaxParallel`.

Extensive user-facing docs live in `README.md`; extensive inline docs and comment-based help live at the top of `Get-DirectSendReport.ps1`. Read both before changing detection logic.

## Running / common invocations

```powershell
# Default audit (last 10 days, direct connection)
.\Get-DirectSendReport.ps1 -OutputPath .\DirectSend.csv

# GDAP delegated, longer window
.\Get-DirectSendReport.ps1 -DelegatedOrganization contoso.onmicrosoft.com -Days 30 -OutputPath .\contoso.csv

# Dump what EOP schemas this tenant actually returns (debugging)
.\Get-DirectSendReport.ps1 -ShowSchema

# Parallel across many GDAP tenants listed in tenants.txt
.\Run-DirectSendGDAPReports.ps1 -MaxParallel 5
```

Module requirement: `ExchangeOnlineManagement` v3.2.0+. On macOS/Linux, the main script auto-sets `UseRPSSession:$false` on module versions 3.0–3.3 because REST-only is required there (no WSMan).

## Detection pipeline (the part that matters)

The "message is Direct Send" classification is a **four-stage AND filter** and changing any stage changes the audit's meaning:

1. `ConnectorId` matches the `"\Default "` pattern, extracted from the `Get-MessageTraceDetailV2` **Receive event's Data XML** — not the summary record. This is Microsoft's authoritative signal for "no custom inbound connector matched."
2. `FromIP` is populated (external SMTP; authenticated internal mail has none).
3. Sender **and** recipient domains are both accepted domains for the tenant.
4. `ProxiedClientHostname` is populated (EOP classified the inbound connection as anonymous). Empty means on-prem/hybrid relay territory — Reject Direct Send does NOT affect those, surfaced only with `-IncludeInternalRelay` as the `InternalRelay` category.

`-NoDeepInspect` skips stage 1 and stage 4 because they require the per-message Detail call; results revert to FromIP + accepted-domain filters alone and lose authoritative classification.

Also: `RdsAffected` evaluates the **P1 envelope sender (ReturnPath)**, not the P2 header From — ESPs using a custom return-path subdomain (`bounces.customer.com`) slip past Reject Direct Send because subdomains aren't automatically accepted domains. The `ReturnPath` column surfaces this.

## API constraints baked into the code

- **10-day window limit** on `Get-MessageTraceV2`. `-Days` up to 90 is auto-chunked into 10-day windows (newest first) in the `#region Build 10-day query windows` block.
- **100 requests per 5-minute rolling window** on `Get-MessageTraceDetailV2`. The deep-inspection region (`#region Deep inspection`) uses a sliding-window limiter, not a naive sleep — first 100 candidates run fast, then pacing kicks in. Expect roughly 20 min for 500 candidates. Do not replace this with a simpler throttle without replicating the sliding window.
- The script's layout (`#region` blocks) mirrors the pipeline: Connection → Schema detection → Accepted domains → Window build → Query/filter → Deep inspection → Output. Changes usually live inside one region.

## GDAP specifics (partner / multi-tenant scenarios)

- Minimum Entra role the delegated user needs: **Exchange Administrator** (least-privilege) or Global Admin. Global Reader / Service Support Admin / Helpdesk Admin fail with `"The role assigned to user ... isn't supported in this scenario"`.
- There is a known Microsoft WAM bug where GDAP flows drop required WIDS claims and produce the exact same error even when the role is correct. Workaround is `-DisableWAM` on `Connect-ExchangeOnline`. `Run-DirectSendGDAPReports.ps1` pre-connects each child with `-DisableWAM $true` by default for this reason.
- The wrapper uses `Start-Job` (separate pwsh processes), not `ForEach-Object -Parallel` (same-process runspaces), because Exchange Online session state is process-global and would cross-contaminate between tenants in a shared runspace. If you rewrite the parallelism, preserve process isolation.
- MSAL token cache is on-disk (Keychain on macOS). First run against a new tenant prompts interactively; subsequent runs are silent until tokens expire. Running `-MaxParallel 5` against unseeded tenants opens 5 simultaneous browser prompts — advise `-MaxParallel 1` first to seed, then ramp up.

## Docs + versioning workflow (required for any user-visible change)

There is no build system or test suite, so documentation *is* the release artifact. Any change that alters behavior, flags, output, or operator workflow must update all of the following in the **same commit** — never just one of them:

1. **Script version + changelog at the top of the changed script's `.NOTES` block.** `Get-DirectSendReport.ps1` and `Run-DirectSendGDAPReports.ps1` each carry their own `Version:` line and inline changelog. Bump the component's version using SemVer against *its own* prior version (patch for docs-only/internal fix with no user-visible change, minor for new flags or behavior changes, major for breaking changes). Add a dated entry describing *why* — readers look here first when a tenant run behaves differently than last week.
2. **`CHANGELOG.md` at the repo root.** Add a new `## [x.y.z] - YYYY-MM-DD` section using the highest component bump as the repo version (e.g., if the wrapper goes 1.1.0 → 1.2.0 and the main script goes 1.3.0 → 1.4.0, the repo bumps to 1.5.0 or higher). Also update the "Current component versions" list near the top so it matches what's in each script's `.NOTES`. Sections follow Keep a Changelog: `Added` / `Changed` / `Fixed` / `Removed`.
3. **`README.md`** if the change is user-facing — new flags, changed defaults, new failure modes worth warning about, invocation examples that would now mislead. Skim the usage and troubleshooting sections; don't leave stale example commands or outdated behavior claims.
4. **Comment-based help for new/renamed parameters.** Add/update the corresponding `.PARAMETER <Name>` block at the top of the script so `Get-Help` stays accurate. If a parameter's default changes, update the `.PARAMETER` text too (don't let it contradict the param block).
5. **CLAUDE.md (this file)** only when the change invalidates guidance here — renamed flags referenced above, detection-pipeline changes, new gotchas a future session needs. Don't restate the changelog.

If a change genuinely doesn't warrant a version bump (e.g., fixing a typo in a comment), say so explicitly rather than silently skipping the workflow. When in doubt, bump.

## Repo hygiene

`tenants.txt` in the root is the customer list consumed by the wrapper and is **gitignored** because it contains real customer domains. `.gitignore` also blanket-ignores dot-files (`.*`) with a `!.gitignore` re-include, plus `*.csv` and `*.txt` for report outputs. When adding new tracked files, avoid names that would be swept up by those patterns.
