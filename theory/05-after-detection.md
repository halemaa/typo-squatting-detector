# 5 — After detection: what do you actually do?

The detector flags `paypaI.com` as "looks like paypal.com." Now
what? The algorithm's job ends at the alert. A real SOC workflow
is just beginning.

This note walks through the response playbook — the muscle memory
that separates "I built a tool" from "I know how security teams
use tools."

## Rule zero — do NOT open the suspicious domain in a browser

The single most important rule.

If the domain is a real phishing site, visiting it in a regular
browser:
- Runs the attacker's JavaScript on your machine
- Puts your IP in their logs — they now know a defender is sniffing
- Risks downloading malware or drive-by exploits

Every step below is done from the command line or via sandboxed
third-party services. Your browser never touches the live
suspect domain.

## Step 1 — Is it alive?

```bash
nslookup paypaI.com
```

- Returns an IP → alive, hosting something
- Returns `NXDOMAIN` or similar → unregistered or not yet active

**Dead doesn't mean safe.** Attackers often register domains weeks
before activating them (called "aged" domains — they're harder for
reputation systems to flag). File the domain, monitor it, check
again next week.

**Alive means investigate now.**

## Step 2 — Who owns it, and when was it registered?

```bash
whois paypaI.com
```

Four red flags in WHOIS output:

- **Creation Date is recent** — registered in the last 7 days? Most
  phishing domains have very short lifespans. Age ≤ 30 days is
  suspicious by default.
- **Registrant is "Domains By Proxy" / "Privacy Service"** —
  legitimate businesses rarely hide WHOIS. Attackers always do.
- **Registrant country** — some countries have very slow abuse
  response. Attackers prefer them.
- **Registrar** — some registrars respond to abuse reports in
  hours (Cloudflare, Namecheap). Others respond never. Google
  "registrar name + abuse response" to check reputation.

For Kenyan domains (`.co.ke`, `.ac.ke`), WHOIS is thin — KENIC
protects most registrant data. Still worth checking the creation
date.

## Step 3 — What does the live site look like?

Open **urlscan.io** in your browser. Paste the suspect URL. Submit.
Wait ~30 seconds.

You get a full report WITHOUT visiting the site yourself:
- Screenshot of the rendered page
- All JavaScript loaded
- All redirects followed
- Phishing-kit signatures (urlscan recognises many common kits)
- Links to related infrastructure (same IP, same cert, same JS)

If the screenshot shows a login page mimicking the brand →
**confirmed phishing.** Move to Step 4.

Secondary tools for cross-reference:
- **VirusTotal** — paste URL, see how many AV vendors have flagged it
- **crt.sh** — see every TLS certificate issued for this domain
- **Shodan / Censys** — see what else is hosted on the same IP

## Step 4 — Report it (parallel, not sequential)

Send all reports at the same time. Don't wait for one to confirm
before sending the next. Each targets a different takedown path.

### 4a. The targeted brand's abuse team

The brand being impersonated has a vested interest in killing the
lookalike. They respond fastest.

| Target     | Abuse channel                              |
|------------|--------------------------------------------|
| PayPal     | `phishing@paypal.com`                      |
| Google     | `abuse@google.com`                         |
| Microsoft  | reportphishing@microsoft.com               |
| Amazon     | `stop-spoofing@amazon.com`                 |
| Apple      | `reportphishing@apple.com`                 |
| Safaricom  | `security@safaricom.co.ke`                 |
| KCB Bank   | `abuse@kcbgroup.com`                       |
| Equity Bank| `security@equitybank.co.ke`                |

Include: URL, urlscan.io link, screenshot, WHOIS output.

### 4b. Browser blocklist services

Faster user protection than waiting for takedown.

- **Google Safe Browsing** (feeds Chrome, Firefox):
  https://safebrowsing.google.com/safebrowsing/report_phish/
- **Microsoft SmartScreen** (feeds Edge, Office 365):
  https://www.microsoft.com/wdsi/filesubmission/exploitguard/report

Both are 1-minute forms. Submission → block live in browsers
within 24-48 hours.

### 4c. Community phishing databases

- **PhishTank** (phishtank.org) — community-verified, Google and
  many security vendors ingest their feed
- **APWG** (`reportphishing@apwg.org`) — Anti-Phishing Working Group,
  the industry consortium

### 4d. For Kenyan-brand attacks specifically

- **KE-CIRT** (Kenya Computer Incident Response Team):
  `incident@ke-cirt.go.ke` or form at ke-cirt.go.ke
- **KENIC** (.ke domain registry): `abuse@kenic.or.ke` — they can
  suspend `.ke` domains fast
- **CAK** (Communications Authority of Kenya): for telco-related
  cases
- **DCI Cybercrime Unit**: 0800 721 111 — for criminal prosecution
  of ongoing campaigns

### 4e. The hosting provider

Find who's hosting the attacker's content:

```bash
dig +short paypaI.com         # get IP
whois 203.0.113.42            # find the hosting provider
# look for OrgName / abuse-c
```

Email their abuse address (`abuse@provider.com`). Include evidence.
Hosting providers respond to abuse reports faster than registrars,
and shutting down the server is sometimes faster than shutting down
the domain.

## Step 5 — Block it internally (minutes)

While reports work through the system, protect your own users /
organisation NOW.

**For an enterprise SOC:**
- Add the domain to your DNS firewall blocklist (Cisco Umbrella,
  Infoblox, Palo Alto DNS Security)
- Add to email filter rules (Proofpoint, Mimecast, Microsoft 365
  Defender)
- Push to endpoint security products (CrowdStrike, SentinelOne)
- Alert the help desk ("if users report a suspicious email from this
  domain, treat as phishing")

**For personal protection on Windows:**
```
# Admin cmd
echo 0.0.0.0 paypaI.com >> C:\Windows\System32\drivers\etc\hosts
```

That `hosts` entry blocks the domain from resolving on this machine.

## Step 6 — Hunt wider

One lookalike rarely travels alone. Attackers run campaigns.

Starting from a confirmed phishing domain, pivot:

```bash
# All domains sharing the same IP address
dig +short paypaI.com
# → 203.0.113.42
# Then reverse-DNS: what other names resolve to this IP?
# Tools: Shodan, Censys, SecurityTrails (free tiers)
```

```bash
# All certs with similar subject-name patterns
# crt.sh search: %paypa%
# → shows every TLS cert ever issued containing "paypa"
```

Finding the other 15 domains in the campaign is where the real
value is. One block vs. fifteen.

## Step 7 — Write the ticket

Every incident gets documented:

```markdown
# Incident 2026-11-11-001

## Timeline
- 09:15  Detection fired (paypaI.com flagged by typosquat scan)
- 09:18  Confirmed via urlscan — phishing login page mimicking PayPal
- 09:22  Added to internal DNS blocklist
- 09:25  Reported to PayPal phishing@
- 09:27  Reported to Google Safe Browsing
- 09:30  Submitted to PhishTank
- 09:45  Hosting provider identified (Hetzner); abuse report sent
- 11:20  Site returned HTTP 503 (likely takedown in progress)

## Evidence
- urlscan: https://urlscan.io/result/abc-xyz
- WHOIS snapshot: attachments/whois.txt
- Screenshot: attachments/screenshot.png

## IOCs
- Domain: paypaI.com
- IP: 203.0.113.42
- TLS fingerprint: ...
- Phishing kit: "16Shop v2.3" (identified by urlscan)

## Related
- 12 similar lookalikes on same IP: see pivot.txt
```

This record feeds your team's threat intelligence. It's also
evidence if the case goes to law enforcement.

## Automate what you can

In a real SOC the above runs as a pipeline:

```
┌─────────────────────────────────┐
│ CT log feed / DNS registration  │
│ feed / email inbox parsing      │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│ typo-squatting-detector         │  ← you are here
│ (filter candidates by brand     │
│  similarity)                    │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│ Auto-enrichment:                │
│ whois, nslookup, urlscan,       │
│ VirusTotal, crt.sh              │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│ Risk score. High scores → queue │
│ for analyst. Low scores → log.  │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│ Analyst reviews, fills in       │
│ ticket, triggers reports.       │
└─────────────────────────────────┘
```

Your tool sits at stage 2. Everything else is composable.

## The security skill this teaches

It's not just "running an algorithm." It's **operational security
instinct**:
- Don't trust the alert — verify
- Don't visit the site — sandbox
- Don't wait — report in parallel
- Don't single-fire — hunt for related infrastructure
- Don't skip documentation — your ticket is tomorrow's threat intel

An interviewer asking "walk me through your detection, what happens
next?" wants to hear THIS, not just the algorithm.

## The one-sentence summary

> Detection is step 1. The real workflow is: verify safely → report
> in parallel to brand + Safe Browsing + registrar + host →
> block internally → hunt for related infrastructure → document.
> The algorithm is just the alarm — the response is the job.
