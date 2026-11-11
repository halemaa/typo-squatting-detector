# typo-squatting-detector

A command-line security tool that scans a list of domain names and
flags any that look suspiciously close to a list of protected brands.

Catches real-world phishing tricks:
- Pure typos (`gogle.com` for `google.com`)
- **Homoglyph attacks** (`paypaI.com` with capital-I, `g00gle.com` with zeros)
- TLD swaps (`google.co`, `paypal.net`)
- Common Kenyan-brand impersonations (`safaric0m.co.ke`, `equityb4nk.co.ke`)

Same **dynamic-programming edit-distance** algorithm as a spell
checker, but applied to defensive security instead of autocorrect.

## See it work

```bash
$ python detect.py suspicious_domains.txt
Scanned 51 domain(s). Found 23 suspicious domain(s):
--------------------------------------------------------------------------------
WARNING  gogle.com           → looks like google.com      (distance 1, 1 char edit)
WARNING  googIe.com          → looks like google.com      (distance 0, homoglyph substitution)
WARNING  amaz0n.com          → looks like amazon.com      (distance 0, homoglyph substitution)
WARNING  paypaI.com          → looks like paypal.com      (distance 0, homoglyph substitution)
WARNING  safaric0m.co.ke     → looks like safaricom.co.ke (distance 0, homoglyph substitution)
WARNING  equityb4nk.co.ke    → looks like equitybank.co.ke (distance 1, 1 char edit)
WARNING  usiu.co.ke          → looks like usiu.ac.ke      (distance 1, TLD swap)
...
```

Legitimate domains pass through quietly. Unrelated ones are ignored.

## Try it

```bash
python detect.py <file_of_domains>
python detect.py domains.txt --brands protected_brands.txt
python detect.py domains.txt --distance 1          # stricter (fewer false positives)
echo "g00gle.com" | python detect.py -             # scan a single domain from stdin
```

The shipped `brands.txt` covers ~30 well-known global and Kenyan
brands. In production, feed it the list of brands your organisation
needs to defend.

Exit code is non-zero when threats are found, so this can gate a CI
job or feed into an alerting pipeline (cron + SIEM).

## How it works

Three detection layers stacked:

### 1. Homoglyph normalisation

Before measuring edit distance, we fold visually-identical characters
to a canonical form:
- `0` → `O`, `o` → `O`
- `1` → `l`, capital `I` → `l`, `|` → `l`
- `rn` → `m` (two chars that visually look like one)
- `vv` → `w`
- `cl` → `d`

So `paypaI.com` becomes `paypal.com` *before* comparison, and the
edit distance drops to zero. Attack detected with reason "homoglyph
substitution."

### 2. Edit distance (DP)

Classical Levenshtein via dynamic programming. O(m*n) time, O(m+n)
space with the rolling-row trick. Same algorithm as spell-checker,
just applied defensively.

### 3. Domain-aware splitting

Domain names have structure. We split into base (`paypal`) and TLD
(`com` or `co.ke`), and compare parts independently. That catches
TLD-swap attacks (`google.co` for `google.com`) that would look like
a 1-char delete on the full string.

## What's in the box

```
typosquat.py                    core: homoglyph fold + edit distance + classify
detect.py                       CLI
brands.txt                      ~30 protected brands (global + Kenyan)
suspicious_domains.txt          51 sample domains (23 attacks, 28 legit/unrelated)
tests/test_typosquat.py         21 passing tests
theory/                         4 beginner-level security-flavored notes
```

## Read the theory

1. [What typo-squatting actually is](theory/01-what-is-typosquatting.md)
   — the real-world phishing tactic this defends against
2. [Edit distance applied defensively](theory/02-edit-distance-security.md)
   — the same DP algorithm from spell-checker, flipped for defense
3. [Homoglyphs — the "looks-alike" characters](theory/03-homoglyphs.md)
   — why `paypaI` looks exactly like `paypal`
4. [Where this fits in real security](theory/04-real-security-tools.md)
   — Google Safe Browsing, Microsoft Defender, Cisco Umbrella all use
   variations of this

## Extending

- **Insertion/suffix attacks** — catch `google-login.com`,
  `paypal-secure.com` by checking "does the suspicious domain contain
  the brand as a substring?"
- **Unicode homoglyphs** — modern attacks use Cyrillic `а` that looks
  identical to Latin `a`. Add a Unicode confusables table (ICU
  provides one).
- **Live DNS feeds** — plug into Certificate Transparency logs
  (crt.sh) or CZDS (ICANN zone data) for real-time monitoring of
  newly-registered lookalikes.
- **WHOIS enrichment** — on a hit, auto-fetch WHOIS info for the
  suspicious domain for attribution.
- **Scoring vs flagging** — emit a 0-10 "suspicion score" per domain
  instead of binary yes/no.

## Caveats

- A low edit distance isn't proof of an attack — it's a *signal*.
  `example.com` and `exemple.com` differ by one character, but one
  is English and one is French. Always have a human review before
  blocking.
- Homoglyph tables are never complete. New fonts and new Unicode
  blocks constantly add confusables. Keep yours updated.
- This tool compares a candidate against brands you already know.
  It won't tell you "this domain registered yesterday looks suspicious
  in general" — for that, you need volume data and reputation feeds.

## Related repos

- [`spell-checker`](https://github.com/halemaa/spell-checker) —
  same DP edit-distance algorithm, used for spell-check instead of
  typo-squatting detection
- [`cybersec-hale`](https://github.com/halemaa/cybersec-hale) —
  notes on phishing and other attack techniques
