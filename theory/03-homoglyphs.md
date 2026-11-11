# 3 — Homoglyphs: the "looks-alike" characters

## What a homoglyph is

A **homoglyph** is a character that looks like another character,
but isn't the same character. In your browser, in your email client,
in most text rendered on screens:

- `0` (digit zero) and `O` (capital o) look basically identical
- `1` (digit one) and `l` (lowercase L) and `I` (capital i) all look
  like the same vertical line
- `rn` (lowercase r followed by lowercase n) rendered together
  looks almost indistinguishable from `m`
- `vv` (two v's) looks like `w`

These aren't typos. The attacker typed exactly what they meant. They
chose characters that LOOK like the real ones.

## Why this works

Font design. Most sans-serif fonts (what you see on web pages) draw:

- Capital `I` and lowercase `l` as plain vertical strokes. No
  serifs. No distinguishing curves. Almost identical.
- Digit `0` and capital `O` as slightly-oval shapes. Some fonts put
  a slash through the 0 to distinguish them. Many don't.
- Digit `1` and lowercase `l` as straight vertical lines. Some fonts
  add a tiny serif to the digit. Many don't.

Browsers render URLs in these fonts. Your brain doesn't notice.

## The attack

1. Attacker picks a real brand: `paypal.com`.
2. Attacker finds a homoglyph: capital `I` for lowercase `l`.
3. Attacker registers `paypaI.com` — a completely separate domain.
   (DNS treats uppercase I and lowercase l as different characters.
   DNS is byte-exact; your eye is not.)
4. Attacker builds a fake PayPal login page at `paypaI.com`.
5. Phishing email with link to `https://paypaI.com/login`. Looks
   exactly like `https://paypal.com/login` in the email.
6. Victim clicks. Enters credentials. Attacker captures.

The DNS layer sees different domains. The user's eye sees identical
URLs. That gap is the whole attack surface.

## Normalisation — closing the gap

Our detector closes the gap by **folding** homoglyphs to a canonical
form BEFORE comparing. Think of it as "pretending the user's eye
sees it correctly":

- Every `0` becomes `O`
- Every capital `I` becomes lowercase `l`
- Every `rn` becomes `m`
- Every `vv` becomes `w`

After folding:
- `paypaI.com` → `paypal.com`
- `g00gle.com` → `google.com` (and then lowercase: `google.com`)
- `rnicrosoft.com` → `microsoft.com`

Now a byte-exact comparison finds the attack.

## The code (from `typosquat.py`)

```python
_HOMOGLYPH_CLASSES = [
    "O0o",            # all fold to canonical 'O'
    "l1I|",           # all fold to canonical 'l'
    "S5", "G6", "B8", "Z2",
]

_CHAR_FOLD = {}
for group in _HOMOGLYPH_CLASSES:
    canonical = group[0]
    for ch in group:
        _CHAR_FOLD[ch] = canonical

_MULTI_FOLD = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
]

def normalise(text):
    for src, dst in _MULTI_FOLD:
        text = text.replace(src, dst)
    text = "".join(_CHAR_FOLD.get(c, c) for c in text)
    return text.lower()
```

Three stages, in order:
1. Multi-char substitutions (`rn`→`m` must happen before any
   single-char fold touches the `r` or the `n`)
2. Single-char substitutions
3. Lowercase (so case-insensitive comparison is free)

## The subtlety — lowercase `i` is NOT a homoglyph of `l`

In most fonts:
- `l` (lowercase L) is a plain vertical stroke, no dot on top
- `i` (lowercase i) is a vertical stroke WITH a dot on top

So `i` and `l` don't actually look the same. Our fold map correctly
leaves lowercase `i` alone.

But capital `I` IS a homoglyph of lowercase `l`:
- `I` (capital i) is a plain vertical stroke, no dot
- `l` (lowercase L) is a plain vertical stroke, no dot

Both look identical. The attack `paypaI.com` (capital I) works.
A hypothetical attack `paypai.com` (lowercase i) would fail because
the `i`'s dot reveals it.

This nuance matters. It's why our fold table is explicit about
which chars fold to which — not just "all L-looking things fold
together."

## Beyond ASCII — Unicode confusables

Modern attacks use Unicode. Cyrillic `а` (U+0430) and Latin `a`
(U+0061) are different code points but look identical in every
common font. Same with Greek letters.

Our simple ASCII fold table catches the easy attacks. A production
tool would layer in the Unicode "confusables" table maintained by
the Unicode Consortium (available in Python via the `confusable_homoglyphs`
package).

The hardest attacks use IDN (Internationalised Domain Names):
`xn--pypal-4ve.com` — a punycode-encoded domain that renders as
`pȳpal.com` in your address bar. Modern browsers show punycode for
suspicious-looking IDN domains, but many detection tools still miss
them.

**This is a rolling arms race.** Homoglyph tables must be continuously
updated.

## Where attackers look next

As browsers add protections, attackers innovate:
- **Subdomain squatting:** `paypal.com.evil.com` — the attacker
  actually owns `evil.com` but puts `paypal.com` in the subdomain
  so it reads first.
- **Path squatting:** `evil.com/paypal.com/login` — same trick,
  one step deeper.
- **Punycode / Unicode ambiguity:** see above.
- **Typo-TLDs:** `paypal.cm` (Cameroon ccTLD) because users miss
  the missing `o`.

Edit distance catches some but not all. A real phishing defence
stack uses this tool PLUS substring search PLUS a reputation feed
PLUS behavioural analytics on the resulting page.

## The one-paragraph summary

> A homoglyph is a character that looks like a different character.
> Attackers exploit this to register lookalike domains. Our detector
> folds homoglyphs to a canonical form before applying edit distance,
> so a 0-character byte-level difference between `paypaI.com` and
> `paypal.com` becomes a 0-character visual-identity match — flagged.

Simple step. Enormous value.
