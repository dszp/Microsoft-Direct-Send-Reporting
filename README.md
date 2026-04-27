# Microsoft Direct Send Reporting

PowerShell script to audit emails delivered via Microsoft Direct Send in an Exchange Online tenant, using either GDAP delegated access (CSP/partner) or direct admin credentials. No app registration required.

**Primary use case:** audit what traffic would be blocked if you enable Microsoft's "Reject Direct Send" feature, so you can allowlist any legitimate senders before rolling it out globally.

## Contents

- [What is Direct Send?](#what-is-direct-send)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Run Against Many GDAP Tenants in Parallel](#run-against-many-gdap-tenants-in-parallel)
- [Parameters](#parameters)
- [Output Fields](#output-fields)
- [Interpreting the Results](#interpreting-the-results)
  - [Source summary](#source-summary)
  - [Reading the Category column](#reading-the-category-column)
  - [Missing traffic you expected to see](#missing-traffic-you-expected-to-see)
- [ReturnPath Domain Summary](#returnpath-domain-summary)
- [DMARC Policy Check](#dmarc-policy-check)
- [The `InternalRelay` Category](#the-internalrelay-category)
- [How Detection Works](#how-detection-works)
- [Allowlisting Legitimate Sources Before Enabling Reject Direct Send](#allowlisting-legitimate-sources-before-enabling-reject-direct-send)
  - [The rejection criterion (what matters and what doesn't)](#the-rejection-criterion-what-matters-and-what-doesnt)
  - [Two matching methods](#two-matching-methods)
  - [Finding a vendor's TLS certificate subject](#finding-a-vendors-tls-certificate-subject)
  - [Example: allowlisting a SendGrid-based vendor](#example-allowlisting-a-sendgrid-based-vendor-eg-service-titan)
  - [Example: allowlisting a vendor with a dedicated cert](#example-allowlisting-a-vendor-with-a-dedicated-cert)
  - [Example: allowlisting by IP only](#example-allowlisting-by-ip-only)
  - [Helper script: `New-Exchange365-InboundConnectorByIPRanges.ps1`](#helper-script-new-exchange365-inboundconnectorbyiprangesps1)
    - [When to use it](#when-to-use-it)
    - [Strict vs Permissive posture](#strict-vs-permissive-posture)
    - [Auto-populating `-SenderDomains` (Strict only)](#auto-populating--senderdomains-strict-only)
    - [Pre-create overlap check](#pre-create-overlap-check)
    - [Subdomain return-path blind spot](#subdomain-return-path-blind-spot)
  - [Allowlisting multiple email providers](#allowlisting-multiple-email-providers-sendgrid-mailgun-postmark-etc)
  - [IMPORTANT: DMARC must be enforced](#important-dmarc-must-be-enforced)
  - [Verifying a connector matches correctly](#verifying-a-connector-matches-correctly)
  - [Rollout order](#rollout-order)
  - [Blocking Direct Send (the actual setting)](#blocking-direct-send-the-actual-setting)
- [Rate Limits and Runtime](#rate-limits-and-runtime)
- [Coverage and Limitations](#coverage-and-limitations)
- [Diagnosing Output Schema](#diagnosing-output-schema)
- [Why the Detail Lookup Sometimes Returns Nothing](#why-the-detail-lookup-sometimes-returns-nothing)
- [Further Investigation](#further-investigation)
- [Alternative: Historical Search (Async, Fully Documented)](#alternative-historical-search-async-fully-documented)
- [References](#references)

## What is Direct Send?

Direct Send occurs when devices or applications connect directly to a tenant's MX record (e.g., `tenant.mail.protection.outlook.com`) over port 25 **without SMTP authentication**, using an accepted domain as the sender. These messages:

- Bypass SPF, DKIM, and DMARC validation
- Bypass anti-impersonation controls
- Can spoof any address in the tenant's accepted domains
- Are indistinguishable at the header level from authenticated internal mail

This is different from:
- **SMTP Client Submission** (port 587, authenticated — tracked via the SMTP AUTH Clients report)
- **Authenticated relay via configured inbound connector** (uses a named connector with IP restriction — the preferred replacement for Direct Send)

Microsoft's [Reject Direct Send feature](https://techcommunity.microsoft.com/blog/exchange/introducing-more-control-over-direct-send-in-exchange-online/4408790) blocks these anonymous connections when enabled, but any legitimate traffic using this path will be blocked along with the spam unless you allowlist the sending IPs via a configured inbound connector.

## Requirements

- **PowerShell module:** `ExchangeOnlineManagement` **v3.2.0 or later** (required for macOS/Linux)
- **Permissions:** Exchange Administrator role (or Global Administrator)
- **For GDAP/CSP:** An active GDAP relationship with the Exchange Administrator role delegated to your partner tenant

Install or update the module:
```powershell
Install-Module ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser
```

### macOS / Linux

The module requires REST-based authentication (no WSMan/WinRM) on non-Windows platforms. The script handles this automatically by passing `UseRPSSession:$false` when connecting on module versions 3.0–3.3, and in v3.4+ REST is the only available mode. If you see the error _"This parameter set requires WSMan"_, your module is too old — update it with the command above.

## Quick Start

### Default — what will Reject Direct Send block?

```powershell
.\Get-DirectSendReport.ps1 -OutputPath .\DirectSend.csv
```

By default, this returns every message that would be blocked if "Reject Direct Send" were enabled — anonymous SMTP to your MX with an accepted-domain sender. Review the list and allowlist any legitimate sources (via a configured inbound connector) before enabling Reject Direct Send.

### GDAP / CSP partner, longer audit window

```powershell
.\Get-DirectSendReport.ps1 -DelegatedOrganization contoso.onmicrosoft.com -Days 30 -OutputPath .\contoso.csv
```

### Include default-connector traffic that Reject Direct Send won't affect

```powershell
.\Get-DirectSendReport.ps1 -Days 30 -IncludeInternalRelay
```

Adds `InternalRelay` rows — messages that hit the default connector route but where EOP did not log the connection as anonymous inbound (on-prem/hybrid relays, ARC-trusted paths). These won't be blocked by Reject Direct Send, but are worth knowing about if you want to formalize them with a named inbound connector.

### Fast mode — skip per-message detail lookups

```powershell
.\Get-DirectSendReport.ps1 -Days 90 -NoDeepInspect
```

Skips the `Get-MessageTraceDetailV2` call per candidate. Much faster but loses the authoritative `ConnectorId` classification, the `ProxiedClientHostname`-based spam categorization, and `SCL` scores. Useful for quick scans over large date ranges.

### Diagnose output schema in your tenant

```powershell
.\Get-DirectSendReport.ps1 -ShowSchema
```

Dumps the full property list from `Get-MessageTraceV2` and `Get-MessageTraceDetailV2` for one recent message. Use this when troubleshooting schema assumptions.

### Capture results as a variable for further analysis

```powershell
$results = .\Get-DirectSendReport.ps1 -Days 30
$results | Where-Object { $_.Category -eq 'AnonymousExternal' }
$results | Group-Object FromIP | Sort-Object Count -Descending
```

## Run Against Many GDAP Tenants in Parallel

For partners auditing many customer tenants at once, `Run-DirectSendGDAPReports.ps1` wraps the main script and fans out across a list of tenants, each in its own `pwsh` child process (so every tenant gets an isolated Exchange Online session). Output is written to one CSV per tenant, named `<short>-directsend.csv` where `<short>` is the tenant's primary domain with `.onmicrosoft.com` stripped off. A matching `.log` file captures the transcript for that tenant.

```powershell
# List customer tenants one per line in tenants.txt (gitignored by default):
#   contoso.onmicrosoft.com
#   fabrikam.onmicrosoft.com

.\Run-DirectSendGDAPReports.ps1
```

Forward extra arguments to the main script via `-ScriptArgs`:

```powershell
.\Run-DirectSendGDAPReports.ps1 -ScriptArgs @('-Days','30','-IncludeInternalRelay')
```

Notes:

- **`-MaxParallel` defaults to 1 (sequential).** `Get-MessageTraceDetailV2` is throttled to 100 requests per 5 minutes *per user/identity*, not per tenant, so when a partner user runs multiple GDAP-delegated tenants in parallel they share one quota — parallelism divides the same 100/5min across N tenants rather than adding throughput, and tends to trip the `"Your recent queries have surpassed the permitted limit"` error. On throttle, the script now backs off progressively (60s → 180s → 300s, up to 3 retries) and clears its local window between retries. Raise `-MaxParallel` only if you know you won't saturate the identity quota (small tenants, short `-Days`, or `-NoDeepInspect`).
- The wrapper pre-connects each child session with `Connect-ExchangeOnline -DisableWAM` to work around the WAM GDAP token bug that produces `"The role assigned to user ... isn't supported in this scenario"`. Pass `-DisableWAM $false` to opt out.
- Your partner-tenant user must be in a security group that is granted the **Exchange Administrator** Entra role on each target customer tenant via an active GDAP relationship. Other roles (Global Reader, Service Support Admin, etc.) will fail with the same error message.
- The first run against a new tenant typically prompts interactively once per tenant to seed the MSAL token cache; subsequent runs are silent until tokens expire.
- `tenants.txt` is listed in `.gitignore` because it usually contains real customer domains.

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-DelegatedOrganization` | string | (none) | Customer tenant domain or ID for GDAP/CSP connections. Omit to connect directly. |
| `-Days` | int (1–90) | `10` | Days back from today to search. Values over 10 are auto-chunked into 10-day windows. |
| `-OutputPath` | string | (none) | CSV export path. When set, the CSV contains the message rows plus the source summary and DMARC block appended as additional rows (separated by a blank row and `--- SUMMARY ---` / `--- DMARC POLICY ---` marker rows), and the script's post-run summaries remain on screen instead of being scrolled off by the pipeline output. When omitted, results are emitted to the pipeline (for capture with `$r = .\Get-DirectSendReport.ps1 ...`). |
| `-AcceptedDomains` | string[] | (auto) | Override the accepted domain list. If omitted, auto-detected via `Get-AcceptedDomain`. |
| `-NewSession` | switch | `$false` | Disconnect any existing session before connecting. Use to switch credentials. |
| `-ShowSchema` | switch | `$false` | Diagnostic mode: dump `Format-List *` for one record, then exit. |
| `-IncludeInternalRelay` | switch | `$false` | Also include rows Reject Direct Send will NOT affect (empty `ProxiedClientHostname`). |
| `-NoDeepInspect` | switch | `$false` | Skip per-candidate `Get-MessageTraceDetailV2` lookup. Faster but less accurate. |

## Output Fields

Default columns (every run):

| Field | Description |
|---|---|
| `DateTime` | UTC timestamp when Exchange Online received the message |
| `From` | Sender address (accepted-domain for Direct Send) |
| `To` | Recipient address (accepted-domain — external recipients are excluded) |
| `Subject` | Message subject |
| `Status` | Delivery status: `Delivered`, `Failed`, `Quarantined`, `FilteredAsSpam`, etc. |
| `FromIP` | Source IP of the device/server that connected to the MX record |
| `MessageTraceId` | GUID for follow-up via `Get-MessageTraceDetailV2` |

Additional columns (unless `-NoDeepInspect` is used):

| Field | Description |
|---|---|
| `Category` | `SpamLikely` (bracketed-IP hostname like `[127.0.0.1]` — definitive spam signature), `AnonymousExternal` (real hostname — legitimate external service or sophisticated spam), or `InternalRelay` (shown only with `-IncludeInternalRelay`). |
| `RdsAffected` | `True` / `False` / empty. Whether Reject Direct Send will actually block this specific message. RDS evaluates the **envelope sender** (`ReturnPath`, aka `MAIL FROM`, aka P1 sender), not the `From:` header. A row can have an accepted-domain `From` (and therefore appear in the report) but a subdomain or external `ReturnPath` — in which case RDS doesn't touch it. `True` means RDS will block; `False` means it won't; empty means we couldn't determine (detail lookup failed or ReturnPath missing). |
| `ConnectorId` | From the Detail event's `Data` XML. Always matches the `\Default ` pattern in results (no configured inbound connector). Rows with custom connector names are excluded before categorization. |
| `ReturnPath` | The P1 envelope sender from the Detail event's `Data` XML — the actual `MAIL FROM:` address the sender presented at SMTP time. This is what RDS evaluates. A ReturnPath of `billing@servantvoice.com` (bare accepted domain) triggers RDS; `pm_bounces@pmsv-bounces.servantvoice.com` (subdomain of accepted domain, but not itself an accepted domain) does not. Many ESPs (Postmark, SendGrid, Mailgun, Amazon SES) use a custom return-path subdomain as a best-practice bounce-handling mechanism — a convenient side effect is that they bypass RDS automatically without needing an inbound connector. |
| `ProxiedClientIP` | The pre-EOP source IP from the `CustomData` blob. Usually matches `FromIP`. |
| `ProxiedClientHostname` | The HELO hostname the sender claimed. `[127.0.0.1]` or other bracketed IP = no valid hostname = classic spam. Real hostname = likely legitimate. Empty = EOP did not classify the connection as anonymous inbound. |
| `SCL` | Spam Confidence Level (0–9) from the `Spam` event, if one was generated. |

### Why `From` (P2) and `ReturnPath` (P1) can differ — and why it matters

The script's initial candidate filter matches on the `From:` header domain (the P2 sender) being an accepted domain, because that's the visible "sent from us" appearance and all that's available on the primary Get-MessageTraceV2 summary. But Reject Direct Send evaluates the **envelope sender**, which is the P1 `MAIL FROM:` — a separate field that's only visible inside the Detail event's `Data` XML.

These two are the same for basic Direct Send (device → MX, both P1 and P2 are your accepted domain). They differ for ESPs using a custom return-path subdomain:

| ESP / Source | P2 `From:` header | P1 `ReturnPath` | `RdsAffected` |
|---|---|---|---|
| A printer via Direct Send | `printer@contoso.com` | `printer@contoso.com` | **True** |
| Inbound spam spoofing you | `ceo@contoso.com` | `ceo@contoso.com` (spoofed) | **True** |
| Postmark (custom return-path) | `billing@contoso.com` | `pm_bounces@pmsv-bounces.contoso.com` | **False** |
| SendGrid default | `notifications@contoso.com` | `bounces.u12345.wl.sendgrid.net` (external) | **False** |
| Cognito Forms (your-domain config) | `support@contoso.com` | `support@contoso.com` | **True** |

Sort your CSV by `RdsAffected` (or `True` values of it) to see just the rows that actually need an inbound connector. Everything with `RdsAffected = False` is already RDS-safe — no action needed. This is the single most useful column for prioritizing allowlist work.

## Interpreting the Results

### Source summary

At the end of each run, the script prints a grouped summary of the `ProxiedClientHostname` values that account for the returned rows. This is the most useful view for planning a Reject Direct Send rollout — clusters of the same hostname usually represent a distinct source (legitimate service, specific spammer, or unknown system) that needs an individual disposition.

Example output:

```
Top sources (ProxiedClientHostname):
  [127.0.0.1]                              23  SpamLikely
  us2-emailsignatures-cloud.codetwo.com    15  AnonymousExternal
  [198.51.100.42]                           8  SpamLikely
  [203.0.113.89]                            3  SpamLikely
  mail-qt1-x82d.google.com                  2  AnonymousExternal
  smtp.known-vendor.example.com             1  AnonymousExternal
```

How to read it:
- **`[127.0.0.1]`, `[198.51.100.42]`, `[203.0.113.89]`** — bracketed IPs in the hostname column mean the sender did not provide a valid HELO hostname at SMTP connection time, so EOP just logged the raw source IP in brackets. Legitimate mail servers always provide a real HELO. These are almost always spam/abuse, and Reject Direct Send will block them correctly.
- **`us2-emailsignatures-cloud.codetwo.com` (15 messages)** — a real hostname from a known service (a CodeTwo email-signature server in this example). The fact that it appears in this report **at all** means CodeTwo's reinjected mail is not matching a configured inbound connector in your tenant — it's flowing through the same default/anonymous path as the spam. When Reject Direct Send is enabled, this legitimate flow will be blocked. **Action:** create or fix an inbound connector with CodeTwo's sending IPs allowlisted before rollout, otherwise your internal signed mail will stop flowing.
- **`mail-qt1-x82d.google.com`, `smtp.known-vendor.example.com`** — single or low-count rows with real hostnames from recognizable service domains. Usually external mail from a legitimate service that doesn't have a configured inbound connector. Review and decide: does this source need to keep flowing via the anonymous path? If yes, allowlist it. If no, Reject Direct Send will correctly block it.

### Reading the `Category` column

| Category | `ProxiedClientHostname` | What it tells you |
|---|---|---|
| `SpamLikely` | Any bracketed IP (`[127.0.0.1]`, `[1.2.3.4]`, etc.) | No valid HELO hostname — strong spam/abuse signal. The brackets are EOP's "I couldn't get a valid hostname" formatting. |
| `AnonymousExternal` | Real hostname (`*.codetwo.com`, `mail-*.google.com`, vendor domains, etc.) | Anonymous SMTP inbound that **did** provide a HELO. Could be a legitimate service that needs allowlisting, or well-configured spam. Requires human review. |
| `InternalRelay` (hidden by default) | Empty | EOP did not classify the connection as anonymous inbound — Reject Direct Send will NOT affect it. Usually on-prem or hybrid relay. |

**`AnonymousExternal` is not a "probably legitimate" label** — it's a "real hostname, needs review" bucket. Recognizable service domains (your email-signature vendor, known mail providers) sitting in this bucket are the entries you need to allowlist before enabling Reject Direct Send, or they'll be blocked along with the spam.

### Missing traffic you expected to see

If your signature platform processes *all* internal mail but only a small subset appears in this report, you likely have **two** inbound paths configured — one that matches the connector (and thus doesn't appear here) and one that falls through to the default anonymous path (which does). Double-check the sending IP ranges of your signature provider against your inbound connector's IP allowlist; the ones appearing here are coming from IPs that your connector doesn't match.

## ReturnPath Domain Summary

Between the source summary and the DMARC block, the script prints a grouping of every `ReturnPath` (P1 envelope sender) domain found in the results, classified by its relationship to your accepted-domain set. This is the most direct "who gets blocked by RDS" view.

Example output:

```
ReturnPath (P1 envelope sender) domains:
  contoso.com                         58  [RDS BLOCKS]      accepted domain
  pmsv-bounces.contoso.com            47  [RDS passes]      subdomain of accepted
  bounces.u12345.wl.sendgrid.net      12  [RDS passes]      external domain
  mta.us.mailgun-custom.com            8  [RDS passes]      external domain
  <empty>                              2  [RDS unknown]     empty/unparseable
```

Categories:
- **`accepted` (red) — RDS BLOCKS.** The ReturnPath domain exactly matches an accepted domain. These are the messages that Reject Direct Send will actually block. Every cluster here needs disposition: create an inbound connector for legitimate sources, and let the malicious ones get blocked.
- **`subdomain` (green) — RDS passes.** The ReturnPath domain is a subdomain of an accepted domain but isn't itself in your accepted-domains list. This is the "custom return-path subdomain" ESP best practice (Postmark's `pmsv-bounces.contoso.com`, Amazon SES's `N.eu-west-1.amazonses.com`, etc.). RDS ignores these automatically. No action needed.
- **`external` (cyan) — RDS passes.** ReturnPath uses a completely different domain from any of your accepted domains. Usually an ESP's default bounce domain or a bounce handling service. RDS doesn't care about these. No action needed.
- **`unknown` (gray) — RDS indeterminate.** ReturnPath was empty or we couldn't parse it. Uncommon — usually indicates a detail lookup failure or malformed trace data.

**How to act on this view:**
- Every red row is the full list of allowlisting work you have. Cross-reference against the source summary's cluster hostnames to identify the sender for each. Build one inbound connector per legitimate provider.
- Red rows that you can't identify — or where the sender is obviously abusive — don't need a connector. They'll be correctly blocked when RDS enables.
- Green/cyan rows tell you who's already doing the right thing (custom return-path subdomain). If one of these is a provider you weren't sure about, this is the definitive "they're fine" signal — skip them.
- If you see a red cluster that you expect to be green (e.g., your Postmark traffic showing accepted-domain ReturnPath), it means that provider's setup in your tenant hasn't been switched to their custom-return-path mode — often a per-account toggle in the provider's UI.

## DMARC Policy Check

After the source summary, the script prints the DMARC policy discovered in DNS for each accepted domain. This is a go/no-go indicator for safely enabling Reject Direct Send with shared-certificate inbound connectors (see the [allowlisting section](#important-dmarc-must-be-enforced) for why this matters).

Example output:

```
DMARC policy per accepted domain:
  contoso.com                    p=reject
  contoso.onmicrosoft.com        no record
  subsidiary.contoso.com         p=quarantine (pct=25)
  legacy.contoso.com             p=none
```

How to read it (colors in the console):

- **Green (`p=reject`, or `p=quarantine` with `pct=100`)** — DMARC enforcement is in place. Authentication failures are acted on, which is the defense-in-depth you need when allowlisting shared-cert connectors.
- **Yellow (`p=quarantine` with `pct<100`)** — partial enforcement. The DMARC rollout is in progress. Raise `pct` to `100` before enabling Reject Direct Send with shared-cert connectors.
- **Red (`p=none`, or `no record`)** — DMARC is NOT enforcing. A shared-cert connector is risky at this state because any other customer of the shared service (e.g., any SendGrid customer if you're allowlisting `*.smtp.sendgrid.net`) could potentially send as your domain through the connector, and the normal DMARC backstop that would catch alignment failures is not active. Fix DMARC first, or use narrower IP-based matching instead.

The lookup works cross-platform — it uses `Resolve-DnsName` on Windows and falls back to `nslookup` on macOS/Linux.

## The `InternalRelay` Category

With `-IncludeInternalRelay`, you'll see messages that hit the default connector route but don't have a `ProxiedClientHostname`. These are typically:

- An on-premises Exchange hybrid server whose old outbound path to EOP is still quietly accepting traffic even after the hybrid connector was removed
- A third-party service (printer management platform, CRM, etc.) that was once allowlisted and still flows despite no formal connector
- ARC (Authenticated Received Chain) trust from an upstream hop that EOP recognizes
- Any other path where EOP decided at receive-time that the connection was trusted enough to not treat as anonymous

These won't be blocked by Reject Direct Send — EOP doesn't classify them as Direct Send at receive-time. If you see them in `-IncludeInternalRelay` output, it's a sign of legacy mail flow that should be formalized with a named inbound connector (IP-restricted) so they don't silently break when the underlying trust mechanism changes.

## How Detection Works

The script applies a layered filter pipeline. In the default run, all of these must pass:

1. **Blank or "Default" connector** — the primary `Get-MessageTraceV2` summary doesn't expose `ConnectorId` directly, so the script reads it from the `Receive` event's `Data` XML via `Get-MessageTraceDetailV2`. Direct Send connections show the pattern `<server>\Default <server>` (EOP backend server + "Default" keyword, meaning no configured inbound connector matched). Custom connector names (CodeTwo, hybrid, partner relays) fail this filter and are excluded.

2. **Non-empty `FromIP`** — authenticated internal mail (OWA/Outlook/MAPI) has no external SMTP source and no `FromIP`. Direct Send always has one because the device physically opened a TCP connection to the MX endpoint.

3. **Sender and recipient both in accepted domains** — Direct Send physically cannot deliver to an external recipient (it goes to your MX, which only accepts internal mail). External-recipient rows, outbound relayed mail, and CodeTwo signature-reinjections to external recipients are all excluded here.

4. **`ProxiedClientHostname` is populated** (default only — disabled with `-IncludeInternalRelay`) — EOP logs a `ProxiedClientHostname` in the `Receive` event's `CustomData` blob when it classifies the inbound connection as anonymous. Empty means EOP did NOT treat the message as anonymous inbound, so Reject Direct Send will NOT affect it.

## Allowlisting Legitimate Sources Before Enabling Reject Direct Send

Every `AnonymousExternal` cluster in your report that represents legitimate mail (signature platforms like CodeTwo, transactional providers like SendGrid / FieldOps / Mailchimp, on-prem relays, etc.) will be **blocked** along with the spam the moment you enable Reject Direct Send — unless you first create a matching inbound connector that attributes that traffic to a named connector instead of the default anonymous path.

### The rejection criterion (what matters and what doesn't)

Reject Direct Send blocks messages based on **one** condition: the message is attributed to no mail flow connector AND the envelope sender (P1 Mail From) is an accepted domain. Per Microsoft's [official documentation](https://techcommunity.microsoft.com/blog/exchange/introducing-more-control-over-direct-send-in-exchange-online/4408790):

> "Anonymous in this context means that the messages are not attributed to any mail flow connector when they are sent to Exchange Online."

**SPF pass, DKIM signature, and DMARC alignment do NOT bypass Reject Direct Send.** Even a message that would pass SPF perfectly because its source is in your domain's SPF record will still be blocked if it doesn't match an inbound connector. This is counterintuitive but important — don't assume a legitimate third-party sender will "just work" because email auth is correctly configured.

### Two matching methods

An inbound connector can match incoming mail in two ways:

| Method | Parameter | When to use |
|---|---|---|
| **TLS certificate** | `-TlsSenderCertificateName` + `-RestrictDomainsToCertificate $true` | Preferred. Survives IP drift, cryptographically stronger. Requires knowing the cert subject the sender presents. |
| **Source IP** | `-SenderIPAddresses` + `-RestrictDomainsToIPAddresses $true` | Fallback when the vendor's TLS cert is too broad (shared across many customers you don't want to allowlist). Requires tracking IP ranges over time. |

You can also combine both on the same connector for the tightest match.

### Finding a vendor's TLS certificate subject

```bash
openssl s_client -connect smtp.vendor.example.com:25 -starttls smtp -servername smtp.vendor.example.com 2>/dev/null |
  openssl x509 -noout -subject -ext subjectAltName
```

Look at the `subject=CN=...` line and the Subject Alternative Names. For SendGrid's shared infrastructure this returns `CN=*.smtp.sendgrid.net`. A vendor with a dedicated cert will have their own domain instead.

### CRITICAL: `-SenderDomains` must be your specific accepted domains

For partner/allowlist connectors of this type, **`-SenderDomains` must be an explicit list of your own accepted domains** — the domains the vendor is sending *as*. Do NOT use `'*'` as the value. Combined with `-RestrictDomainsToCertificate $true` (or `-RestrictDomainsToIPAddresses $true`), a wildcard `-SenderDomains` tells Exchange "for mail from **any** domain, require this cert/IP — reject anything else." That will block virtually all inbound mail (Gmail, customer replies, everything) because nothing but the allowlisted vendor presents that cert. The TLS-cert / IP match is the authentication; `-SenderDomains` scopes which envelope senders the connector applies to.

### Example: allowlisting a SendGrid-based vendor (e.g., FieldOps)

Your report shows rows like:
```
4/17/2026 6:14:59 PM,user@example.com,recipient@example.com,Q3 Proposal – Project #4412,Delivered,AnonymousExternal,
  149.72.203.5,...\Default ...,149.72.203.5,o21.ptrNNNN.sendgrid.fieldops.example.com,,fda2c75a-...
```

The `ProxiedClientHostname` ending in `.sendgrid.fieldops.example.com` tells you the vendor (FieldOps) uses SendGrid to send on your domain's behalf. To preserve this flow:

```powershell
New-InboundConnector `
    -Name 'SendGrid (FieldOps)' `
    -ConnectorType Partner `
    -SenderDomains 'contoso.com', 'contoso.net' `
    -TlsSenderCertificateName '*.smtp.sendgrid.net' `
    -RestrictDomainsToCertificate $true `
    -RequireTls $true `
    -CloudServicesMailEnabled $false `
    -Enabled $true
```

Replace `contoso.com, contoso.net` with your own accepted domains that the vendor is sending *as*. The `*.smtp.sendgrid.net` cert is SendGrid's shared wildcard — any SendGrid customer sending mail claiming to be from one of your accepted domains will match this connector. That's only safe with DMARC enforcement (see below). If that's too broad, narrow further with `-SenderIPAddresses` listing the CIDR blocks the vendor actually uses, or combine both.

### Example: allowlisting a vendor with a dedicated cert

If the vendor has a dedicated cert (e.g., `subject=CN=*.mail.vendor-example.com`), use that instead — it's narrower and vendor-specific:

```powershell
New-InboundConnector `
    -Name 'Vendor name' `
    -ConnectorType Partner `
    -SenderDomains 'contoso.com', 'contoso.net' `
    -TlsSenderCertificateName '*.mail.vendor-example.com' `
    -RestrictDomainsToCertificate $true `
    -RequireTls $true `
    -CloudServicesMailEnabled $false `
    -Enabled $true
```

### Example: allowlisting by IP only

When TLS cert matching isn't viable — typically because the vendor's TLS cert subject isn't published, rotates, or doesn't match a stable wildcard, but the vendor *does* publish a fixed list of sending CIDR ranges (commonly via SPF) — fall back to an IP-only connector:

```powershell
New-InboundConnector `
    -Name 'Vendor name' `
    -ConnectorType OnPremises `
    -SenderDomains 'contoso.com', 'contoso.net' `
    -SenderIPAddresses '149.72.203.0/24','167.89.0.0/24' `
    -RestrictDomainsToIPAddresses $true `
    -RequireTls $true `
    -Enabled $true
```

### Helper script: `New-Exchange365-InboundConnectorByIPRanges.ps1`

This repo includes a PowerShell helper that creates the IP-only connector for you, with a few important conveniences over typing `New-InboundConnector` by hand.

#### When to use it

Reach for this script when:

- The vendor's TLS certificate subject is unknown, undocumented, or rotates often, but their **sending IP ranges are published** (typically via their SPF record or vendor documentation), so a TLS-cert connector isn't viable; **and**
- One or more of those CIDR ranges has a prefix shorter than `/24` (e.g. SMTP.com lists `192.40.160.0/19` and `74.91.80.0/20` in their SPF). Exchange Online's `-SenderIPAddresses` only honors entries of `/24` or smaller in practice — a `/19` has to be expanded into 32 contiguous `/24` blocks before the connector will actually match traffic from those IPs. The script automates that expansion.

Minimum invocation:

```powershell
.\New-Exchange365-InboundConnectorByIPRanges.ps1 `
    -ServiceName 'SMTP.com' `
    -CidrRanges '192.40.160.0/19','74.91.80.0/20'
```

Other niceties: `-DelegatedOrganization` for GDAP, `-WhatIf` for a dry-run, the same `-DisableWAM`-by-default Windows auth flow as the audit script, and an inline "Known service IP ranges" reference block at the top of the file (currently SMTP.com) with a template for adding more services.

#### Strict vs Permissive posture

The script can create the connector in either of two configurations, selected by `-Posture`. Both successfully exempt the vendor's mail from Reject Direct Send (which is the audit's primary goal). They differ in connector-layer anti-spoofing:

| | **Permissive** (default) | **Strict** |
|---|---|---|
| Underlying flag | `-RestrictDomainsToIPAddresses $false` | `-RestrictDomainsToIPAddresses $true` |
| `-SenderDomains` value | `'*'` | Explicit list (your accepted domains) |
| What the IP list does | Identifies the partner: only mail from these IPs matches the connector | Filters mail already claimed by `-SenderDomains`: must come from these IPs or be rejected |
| Behavior for spoofed-domain mail from other IPs | Doesn't match this connector — falls through to normal EOP / Reject Direct Send / SPF / DMARC | Rejected at SMTP time by this connector |
| Maintenance burden | None — connector covers all current and future accepted domains automatically | Must update `-SenderDomains` (or recreate) every time a new accepted domain is onboarded |
| EAC radio button | "By verifying that the IP address of the sending server matches" | "By verifying that the sender domain matches one of the following domains" + "Reject messages if they don't come from within these IP address ranges" |

Permissive is the default because it's the simpler posture and most operators rely on Reject Direct Send + SPF/DMARC for spoofing defense anyway. Pick Strict when you want belt-and-suspenders connector-layer rejection of impersonation attempts:

```powershell
# Permissive (default) -- IP-based identification, no domain rejection
.\New-Exchange365-InboundConnectorByIPRanges.ps1 `
    -ServiceName 'SMTP.com' `
    -CidrRanges '192.40.160.0/19','74.91.80.0/20'

# Strict -- IP enforcement filter on accepted-domain matches
.\New-Exchange365-InboundConnectorByIPRanges.ps1 `
    -ServiceName 'SMTP.com' `
    -CidrRanges '192.40.160.0/19','74.91.80.0/20' `
    -Posture Strict
```

The script refuses `-SenderDomains '*'` in Strict posture — that combination tells Exchange to reject every external sender that does not come from the allowlisted IPs, which breaks normal MX flow ([CRITICAL warning](#critical--senderdomains-must-be-your-specific-accepted-domains)).

#### Auto-populating `-SenderDomains` (Strict only)

In Strict posture, if you omit `-SenderDomains`, the script calls `Get-AcceptedDomain` after connecting and uses every accepted domain in the tenant *except* `*.onmicrosoft.com` routing domains (`tenant.onmicrosoft.com` and `tenant.mail.onmicrosoft.com` are filtered out automatically). The resulting list is logged before the connector is created so you can confirm what was selected. Pass an explicit list (e.g. `-SenderDomains 'contoso.com','contoso.net'`) when you want a narrower scope — explicit values always override the auto-population.

In Permissive posture, `-SenderDomains` defaults to `'*'` (the IP list is the security boundary, so a wildcard is correct) and explicit values are still accepted if you want to scope the connector further.

#### Pre-create overlap check

Before creating the connector the script enumerates existing IP-restricted inbound connectors with `Get-InboundConnector`, computes their `/24` coverage, and compares it against the proposed ranges. If any existing connector already covers some of the same `/24` blocks, the script warns with the existing connector's name, lists how many `/24` blocks overlap, and prompts before continuing.

The recommended response is to abort, review the overlapping connector with `Get-InboundConnector | Format-List Name,Enabled,SenderIPAddresses,SenderDomains,Comment`, decide whether the existing one should be kept or removed (`Remove-InboundConnector -Identity <name>`), then re-run. Pass `-Force` to skip the prompt or `-SkipOverlapCheck` to skip the check entirely.

#### Subdomain return-path blind spot

Exchange's `-SenderDomains` matching is **not** recursive. `contoso.com` matches mail with envelope sender exactly in `contoso.com`, not `bounces.contoso.com` or any other subdomain. ESPs that use a custom bounce subdomain (SendGrid/Postmark with `bounces.<yourdomain>`, etc.) therefore slide past a Strict-posture connector keyed on root accepted domains entirely — it does not apply to them, and they continue through normal EOP flow without being blocked or rejected.

That is the same blind spot Reject Direct Send has, and is exactly why `Get-DirectSendReport.ps1` surfaces the P1 envelope `ReturnPath` domain in its summary: that column tells you which providers will not be covered by an accepted-domain-keyed connector. (Permissive-posture connectors are not affected — they identify by IP, not domain.)

### Allowlisting multiple email providers (SendGrid, Mailgun, Postmark, etc.)

When multiple transactional providers send mail as your accepted domains, **create one connector per provider**. Multiple connectors sharing the same `-SenderDomains` but different `-TlsSenderCertificateName` values is fine and intended — Exchange evaluates each connector's match criteria independently:

```powershell
# SendGrid
New-InboundConnector `
    -Name 'SendGrid' `
    -ConnectorType Partner `
    -SenderDomains 'contoso.com', 'contoso.net' `
    -TlsSenderCertificateName '*.smtp.sendgrid.net' `
    -RestrictDomainsToCertificate $true `
    -RequireTls $true `
    -CloudServicesMailEnabled $false `
    -Enabled $true

# Mailgun
New-InboundConnector `
    -Name 'Mailgun' `
    -ConnectorType Partner `
    -SenderDomains 'contoso.com', 'contoso.net' `
    -TlsSenderCertificateName '*.mailgun.org' `
    -RestrictDomainsToCertificate $true `
    -RequireTls $true `
    -CloudServicesMailEnabled $false `
    -Enabled $true

# Postmark
New-InboundConnector `
    -Name 'Postmark' `
    -ConnectorType Partner `
    -SenderDomains 'contoso.com', 'contoso.net' `
    -TlsSenderCertificateName '*.postmarkapp.com' `
    -RestrictDomainsToCertificate $true `
    -RequireTls $true `
    -CloudServicesMailEnabled $false `
    -Enabled $true

# Amazon SES
New-InboundConnector `
    -Name 'Amazon SES' `
    -ConnectorType Partner `
    -SenderDomains 'contoso.com', 'contoso.net' `
    -TlsSenderCertificateName '*.amazonses.com' `
    -RestrictDomainsToCertificate $true `
    -RequireTls $true `
    -CloudServicesMailEnabled $false `
    -Enabled $true
```

**The cert subjects above are educated guesses based on common patterns. Verify each one live before creating the connector** using the `openssl s_client` command from [Finding a vendor's TLS certificate subject](#finding-a-vendors-tls-certificate-subject), targeted at each provider's SMTP endpoint (`smtp.mailgun.org`, `smtp.postmarkapp.com`, `email-smtp.<region>.amazonaws.com`, etc.).

**Shared infrastructure matters.** When two different application vendors both use SendGrid (e.g., FieldOps + a CRM + a scheduling tool), they share the same cert and match the same SendGrid connector. One SendGrid connector covers them all — it doesn't need to know which downstream SaaS is using SendGrid. The security implication is that the SendGrid connector effectively allowlists *any* SendGrid customer sending as your domains; the [DMARC enforcement](#important-dmarc-must-be-enforced) requirement is what blocks other SendGrid customers from spoofing you through the allowlisted path.

**When the cert approach doesn't cleanly work.** Some providers rotate through many cert subjects, use a CDN/edge layer with a generic cert unrelated to the vendor brand, or deliver via multiple services. In those cases, fall back to `-SenderIPAddresses` with the vendor's documented CIDR blocks, or combine both cert and IP on the same connector (the match is OR, not AND — either condition matching is sufficient).

**Identifying which providers you need.** Run the audit — the source summary's `AnonymousExternal` rows show you who's sending. The hostname domain usually reveals the provider:

```
o21.ptrNNNN.sendgrid.<appvendor>.com  → SendGrid
m1234.mailgun.net                     → Mailgun
pm.mtasv.net                          → Postmark
mail-xx.amazonses.com                 → Amazon SES
us2-emailsignatures-cloud.codetwo.com → CodeTwo signature service
```

One connector per real-service cluster. `SpamLikely` clusters stay unallowlisted — Reject Direct Send blocks them correctly.

### IMPORTANT: DMARC must be enforced

When you allowlist a shared-infrastructure cert like `*.smtp.sendgrid.net`, you're delegating the "is this sender legitimate" decision to two things:

1. **The vendor's sender verification** (SendGrid, Mailchimp, etc. require customers to prove DNS control via CNAMEs before allowing sends from a domain)
2. **Your DMARC policy**

The inbound connector **only** tells EOP "this isn't anonymous, don't hit it with Reject Direct Send." Normal SPF/DKIM/DMARC validation still runs. If an attacker at another tenant of the same shared service tries to spoof your domain, they'll fail DMARC alignment (they don't have your DKIM private key and your SPF won't authorize their sending ID) — but **only if your DMARC policy actually rejects or quarantines failures.**

The script shows your current DMARC status per accepted domain in the [DMARC Policy Check](#dmarc-policy-check) section of the output. You can also check manually:

```powershell
Resolve-DnsName -Name "_dmarc.yourdomain.com" -Type TXT | Select-Object -ExpandProperty Strings
```

You want to see `p=reject` or `p=quarantine`. If it says `p=none`, the shared-cert connector approach is risky — fix DMARC first (or use narrower IP-based matching instead).

Recommended DMARC progression if you're at `p=none`:
1. Deploy DMARC reporting (`rua=mailto:...`), monitor for 2–4 weeks
2. Once all legitimate sources are aligned, move to `p=quarantine; pct=10`
3. Gradually raise `pct` to 100
4. Move to `p=reject`

### Verifying a connector matches correctly

After creating a connector, re-run the audit over a period where the vendor has sent mail. Rows matching the connector should drop out of the default report (and appear as `InternalRelay` with `-IncludeInternalRelay`). You can confirm directly by inspecting a trace's Detail event — the `ConnectorId` in the `Receive` event's `Data` XML should now show your connector's name instead of `<server>\Default <server>`.

### Rollout order

1. Run this report over 90 days (`-Days 90`)
2. For every `AnonymousExternal` cluster in the summary, decide: legitimate (create a connector), unknown (investigate), or spam (ignore)
3. Create inbound connectors for all legitimate sources
4. Verify DMARC is `p=reject` or `p=quarantine` for every accepted domain (the script's DMARC section shows this directly)
5. Re-run the audit and confirm all expected legitimate clusters have dropped out
6. Enable Reject Direct Send on the tenant
7. Continue running weekly audits for a month to catch any drift (new vendor IPs, new services users have onboarded, etc.)

### Blocking Direct Send (the actual setting)

Once your allowlist is in place:

```powershell
Set-OrganizationConfig -RejectDirectSend $true
```

See [Introducing more control over Direct Send in Exchange Online](https://techcommunity.microsoft.com/blog/exchange/introducing-more-control-over-direct-send-in-exchange-online/4408790) for the full rollout guidance.

## Rate Limits and Runtime

`Get-MessageTraceDetailV2` is throttled to **100 requests per 5-minute rolling window**. The script uses a sliding-window limiter:

- First 100 candidates process in a burst
- After that, pacing kicks in — the next request waits until the oldest of the last 100 slides out of the 5-minute window
- If a throttle error is still returned (e.g., other admins sharing the tenant quota), the script waits 60 seconds and retries once

Rough runtime expectations (deep inspection enabled):

| Candidates | Approx runtime |
|---|---|
| ≤100 | under 1 minute |
| 200 | ~5 minutes |
| 500 | ~20 minutes |
| 1000 | ~45 minutes |

Use `-NoDeepInspect` for fast passes over large date ranges — you lose the categorization but the summary trace query isn't rate-limited the same way.

## Coverage and Limitations

| Aspect | Detail |
|---|---|
| Maximum lookback | 90 days |
| Data per query | 10 days (script auto-chunks longer ranges) |
| Max results per summary chunk | 5,000 (script paginates automatically) |
| Detail rate limit | 100 requests per 5-minute rolling window |
| Timestamps | UTC |
| Cmdlet status | `Get-MessageTraceV2` is GA; legacy `Get-MessageTrace` is deprecated March 18, 2026 |

## Diagnosing Output Schema

If results look off, dump the actual message trace fields your tenant returns:

```powershell
.\Get-DirectSendReport.ps1 -ShowSchema
```

This shows `Format-List *` output for one `Get-MessageTraceV2` record plus every event from `Get-MessageTraceDetailV2` for that message. The `Receive` event's `Data` field is XML containing `ConnectorId`, `CustomData` (with `ProxiedClientIPAddress` / `ProxiedClientHostname`), and other MEP entries.

## Why the Detail Lookup Sometimes Returns Nothing

`Get-MessageTraceDetailV2` has **two mandatory parameters**: `MessageTraceId` and `RecipientAddress`. Passing only one returns empty results silently — no error, no data. Always provide both:

```powershell
Get-MessageTraceDetailV2 -MessageTraceId <guid> -RecipientAddress user@contoso.com
```

## Further Investigation

Look up the full trace history for a specific row:

```powershell
Get-MessageTraceDetailV2 `
    -MessageTraceId <MessageTraceId from results> `
    -RecipientAddress <To address from results> |
  Format-List *
```

The `Receive` event's `Data` field contains ConnectorId, source IP details (including `ProxiedClientIPAddress` behind EOP's proxy layer), HELO hostname, and TLS info.

## Alternative: Historical Search (Async, Fully Documented)

For a Microsoft-documented approach that doesn't depend on undocumented schema, use `Start-HistoricalSearch` with `-ConnectorType NoConnector`:

```powershell
Start-HistoricalSearch `
    -ReportTitle "DirectSend_$(Get-Date -Format 'yyyyMMdd')" `
    -StartDate (Get-Date).AddDays(-90) `
    -EndDate (Get-Date) `
    -ReportType ConnectorReport `
    -ConnectorType NoConnector `
    -Direction Received `
    -NotifyAddress admin@contoso.com

Get-HistoricalSearch | Sort-Object SubmitDate -Descending | Select-Object -First 5
```

The report is async and delivered as a CSV to the notify address. Useful for compliance-grade audits.

## References

Background reading on Direct Send, its abuse patterns, and Microsoft's new controls:

- [Introducing more control over Direct Send in Exchange Online](https://techcommunity.microsoft.com/blog/exchange/introducing-more-control-over-direct-send-in-exchange-online/4408790) — Microsoft Exchange Team. The official announcement of the Reject Direct Send feature, with the authoritative definition of what gets blocked and guidance on allowlisting via inbound connectors.
- [Direct Send vs. sending directly to an Exchange Online tenant](https://techcommunity.microsoft.com/blog/exchange/direct-send-vs-sending-directly-to-an-exchange-online-tenant/4439865) — Microsoft Exchange Team. Clarifies the technical distinction between Direct Send (accepted-domain sender, no connector) and other forms of anonymous delivery to the tenant MX; includes the Advanced Hunting KQL signature `Connectors == "" and isnotempty(SenderIPv4)`.
- [Stop Spoofing Yourself! Disabling M365 Direct Send](https://www.blackhillsinfosec.com/disabling-m365-direct-send/) — Patterson Cake, Black Hills Information Security (Aug 2025). Walkthrough of the abuse pattern and how to disable Direct Send, written from the defender-perspective.
- [Spoofing Microsoft 365 Like It's 1995](https://www.blackhillsinfosec.com/spoofing-microsoft-365-like-its-1995/) — Steve Borosh, Black Hills Information Security (May 2022). The original red-team write-up that brought wider attention to the Direct Send abuse path; demonstrates how anonymous SMTP to the tenant MX smart host bypasses email gateway protections to deliver convincing internal-looking phishing.
- [How to Check Exchange Online Direct Send Email Activities](https://blog.admindroid.com/how-to-check-exchange-online-direct-send-email-activities/) — AdminDroid. A practical PowerShell-focused walkthrough of message-trace filtering for Direct Send detection, including the connector-name inspection approach that this script's deep-inspect mode implements at scale.
- [DirectSendAnalyzer (source)](https://github.com/jasonsford/directsendanalyzer) and [DirectSendAnalyzer (live tool)](https://jasonsford.github.io/directsendanalyzer) — Jason Ford. A browser-based email header analyzer that classifies individual messages as Direct Send abuse by checking nine header-level conditions (AuthAs, SPF/DKIM/DMARC/CompAuth results, SCL, spoofed From=To, directionality). Complementary to this script: when you have full email headers for a specific suspicious message, paste them there for a per-message verdict that uses signals message-trace cmdlets don't expose.
