# 2 — Edit distance, defensively

## The same tool, flipped

In the `spell-checker` project, edit distance answers:
> "User typed a weird word. Which dictionary word did they *mean*?"

Here it answers the mirror-image question:
> "An attacker registered a weird domain. Which legitimate brand are
> they *trying to look like*?"

**Same algorithm.** Same dynamic-programming grid. The input changes
(domains instead of words). The output is a security verdict instead
of a correction suggestion. That's it.

## Why edit distance fits phishing

Typo-squatting attacks are almost always 1-3 character edits away
from a real brand. More edits = less convincing to a user. Zero
edits = the attacker has to register `paypaI.com` with a capital-I
disguise rather than `paypal.com` (which someone else already owns).

So: attacks cluster at edit distance 0-3 after normalising for
homoglyphs. Anything farther is either (a) a different legitimate
site or (b) a bad attack that nobody will fall for.

The algorithm:

```
for each incoming_domain:
    for each brand_i_care_about:
        d = edit_distance(normalise(incoming), normalise(brand))
        if d <= 2:
            alert human: incoming_domain looks like brand
```

Simple. Correct. Fits on one screen.

## A tiny example

Brand we're defending: `paypal.com`.

A scan of today's new DNS registrations includes:

| Domain              | Distance (after homoglyph normalisation) | Flag? |
|---------------------|-------------------------------------------|-------|
| `paypal.com`        | 0 (identical)                             | No (legit)  |
| `paypal.co`         | 0 (base) + TLD swap                       | **Yes**     |
| `paypaI.com`        | 0 (capital I → l, then identical)         | **Yes** — homoglyph |
| `paypol.com`        | 1 (a → o)                                 | **Yes** — typo |
| `paypaI1.com`       | 1 (extra 1)                               | **Yes**     |
| `paypal-login.com`  | 6+ (lots of extra chars)                  | Not with pure edit distance — need substring match |
| `wikipedia.org`     | 10+                                       | No (unrelated) |

The DP algorithm handles the first five cases cleanly. The sixth
case is why real tools also check "does the suspicious domain
*contain* a brand as a substring?" — a separate, cheaper check.

## Tweaks for security use

The classic Levenshtein algorithm treats every edit as cost 1. In
security use, you want to weight edits by how likely a user is to
miss them:

- **Visual swap** (`o`↔`0`, `I`↔`l`) — cost 0.5 or 0 (we handle
  this via normalisation before distance)
- **Keyboard neighbour** (`a`↔`s`, `p`↔`o`) — cost 0.5 (users miss
  these when typing in a hurry)
- **Random swap** (`a`↔`z`) — cost 1 (this is a real typo, not a
  visual trick)
- **Insert / delete** — cost 1

Our implementation handles the first case via homoglyph
normalisation and treats everything else as cost 1. A production
version would layer more sophisticated weights on top — but the
principle is the same.

## Why the DP table works here

Same reason as spell-check:

- Each cell `dp[i][j]` asks: "what's the minimum cost to transform
  the first `i` chars of the suspect into the first `j` chars of
  the brand?"
- Each cell depends on three smaller cells (left, above, diagonal).
- Fill row by row. Bottom-right cell is the answer.

For a typical pair of domains (~15 characters each), the full table
is ~200 cells. Fills in microseconds. Even against a brand list of
500 names, a single suspect is checked in milliseconds.

**That's fast enough to run on every new DNS registration in
real time.** Which is what big companies actually do.

## The defender's challenge

**Attackers innovate.** New Unicode confusables get added. New TLD
registries open up. New "look-alike" tricks appear:
- `rn` for `m` (two chars pretending to be one)
- `vv` for `w`
- Cyrillic `а` for Latin `a` (different byte, identical pixels)
- IDN encoding (`xn--pypal-4ve.com` renders as `pȳpal.com` in
  the address bar)

A production tool needs its homoglyph table updated continuously.
This tool is a starting point — not a finished product.

## Tie-ins to algorithms you already know

You've seen these cousins already:

- Spell-checker (DP + dictionary) → same algorithm, different intent
- Duplicate-file-finder (hashing) → different algorithm but same
  "find similar things" pattern
- Log-anomaly-detector (sliding window) → similar operational
  security pattern

A security engineer reaches for these same algorithmic tools over
and over. The job is pattern recognition: "this problem looks like
X, which I've solved before."

## The one-paragraph summary

> Typo-squatting detection is spell-check in reverse. Same DP
> edit-distance algorithm. Same tabulation. The only addition for
> security is a homoglyph normalisation step before the compare —
> so that visually-identical characters (`0`/`O`, `I`/`l`) are
> treated as equal. Run it against your brand list, flag anything
> within 2 edits, hand to a human for review.

Simple application. Serious impact.
