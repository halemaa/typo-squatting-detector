# 1 — What typo-squatting actually is

## The attack, in one sentence

An attacker registers a domain name that **looks like** a real one
(`g00gle.com`, `paypaI.com`, `safaric0m.co.ke`) and sets up a fake
site on it. When a user mistypes or misreads the URL, they land on
the attacker's site instead of the real one.

That's it. No fancy exploit. No vulnerability in your software. Just
humans reading URLs imperfectly, and attackers weaponising that.

## Why this works

Three reasons.

**1. Human eyes skim.** When you read `paypal.com`, you don't
examine each letter. Your brain sees the word "paypal" and moves on.
A lowercase `l` and a capital `I` look identical in most sans-serif
fonts. So does `0` and `O`. Your brain fills in the gap.

**2. URLs are long.** `https://www.paypal.com/myaccount/settings/`
is 40 characters. You check the beginning, maybe the end. Everything
in between gets a pass.

**3. Mobile UIs hide the full URL.** Your phone's browser often
shows only the first ~30 characters of a URL, hiding the end.
Attackers put the legitimate-looking part first and the suspicious
tail after.

## Real-world examples

These are real attack domains that have been caught in the wild:

| Legit             | Attack              | Trick                       |
|-------------------|---------------------|-----------------------------|
| `google.com`      | `g00gle.com`        | Two zeros for two o's       |
| `paypal.com`      | `paypaI.com`        | Capital I looks like lowercase l |
| `amazon.com`      | `amaz0n.com`        | Digit 0 for the o           |
| `microsoft.com`   | `rnicrosoft.com`    | `rn` looks like `m`         |
| `netflix.com`     | `netflix-renewal.com` | Added suffix (not caught by pure edit distance) |
| `safaricom.co.ke` | `safaric0m.co.ke`   | Zero for o — real attack in Kenya |
| `mpesa.com`       | `mpesa.co`          | TLD swap (`.co` instead of `.com`) |
| `kcbgroup.com`    | `kcb-group.com`     | Added hyphen                |

Phishing emails link to these. The user clicks, lands on what looks
like the real site, enters their credentials, and the attacker now
has them.

## The scale of the problem

- Attackers register thousands of new typo-squatting domains every
  day. Many large brands have dedicated teams monitoring for new
  lookalikes.
- Certificate Transparency (CT) logs, which record every TLS cert
  issued, generate millions of records a day. Many organisations
  grep their CT feeds for lookalike domains constantly.
- Average successful phishing campaign in 2024 reportedly earned
  attackers $4+ million (IBM Cost of a Data Breach report). Most
  used typo-squatting as the initial vector.

This is not a theoretical problem. It's happening right now, to
your bank, your workplace, your university.

## How this tool helps

Defensively. Your organisation has a list of brands you need to
protect — let's say `safaricom.co.ke`, `kcbgroup.com`,
`yourcompany.com`. This tool takes a list of newly-seen domains
(from DNS feeds, email logs, CT feeds) and flags any that look
suspiciously close to a brand you care about.

The flagged domains go to a human analyst for review. The analyst
decides: register it defensively, block it in the mail filter,
report it to the registrar, or ignore (false positive).

## Where this tool fits in a real workflow

Phishing defence has three stages:

1. **Discovery** — find out about the attack domain. Our tool helps
   here. Also: Certificate Transparency monitoring, domain-generation
   algorithms, threat intel feeds.
2. **Blocking** — once found, prevent your users from reaching it.
   DNS firewall (Cisco Umbrella, Pi-hole), mail filter rules, URL
   reputation services.
3. **Takedown** — get the attacker's domain removed. Report to the
   registrar, host provider, and (for Safaricom, KCB, etc.) Kenya's
   DCI or CAK.

Our tool is a **stage 1 tool**. Catch the domains that look suspicious,
then the humans do the rest.

## The security mindset shift

Most people think "security = find a bug in code." That's half the
field — application security.

The other half is **operational security**: defending systems against
human-targeting attacks like phishing, social engineering, and
credential stuffing. Operational security relies heavily on
monitoring, pattern detection, and automation on data streams.

This tool is operational security. The algorithm (DP edit distance)
is academic. The application (finding typo-squats) is purely
practical SOC work.

## The one sentence to remember

> If an attacker can register a domain that looks almost identical
> to yours, they can phish your users. Defending against this
> requires continuous monitoring for lookalike domains. The core
> detection is an edit-distance-with-homoglyphs pattern.

Next note shows how the DP algorithm gets weaponised for this.
