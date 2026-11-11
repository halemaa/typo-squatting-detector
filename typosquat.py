"""
Typo-squatting detector — flag domains that look suspiciously close
to a protected brand.

Same core algorithm as the spell-checker (edit distance / Levenshtein
via dynamic programming), but with two security-specific additions:

  1. **Homoglyph normalisation.** Before measuring edit distance, we
     replace visually confusable characters with a single canonical
     form (e.g. "0" → "O", capital "I" → lowercase "l"). This catches
     attacks like `paypaI.com` that look identical to `paypal.com`
     but would be reported as distance 2 by raw edit distance.

  2. **Domain-aware comparison.** We split a domain into its base
     name (`paypal` from `paypal.com`) and TLD (`com`), so a scan
     against legitimate `paypal.com` can also flag `paypaI.co`,
     `paypal.net`, etc.
"""

from __future__ import annotations

from dataclasses import dataclass


# Visually confusable characters. First char in each group is the
# canonical form; every other char in the group folds to it.
#
# Design note: lowercase `i` is NOT in the l-group — in most fonts it
# has a dot and doesn't look like `l`. But CAPITAL `I` does look like
# lowercase `l`, and that's a real attack vector. We list each case
# explicitly instead of auto-folding `.lower()`.
_HOMOGLYPH_CLASSES = [
    "O0o",            # capital O, digit 0, lowercase o — all fold to 'O'
    "l1I|",           # lowercase l, digit 1, capital I, pipe
    "S5",
    "G6",
    "B8",
    "Z2",
]

_CHAR_FOLD: dict[str, str] = {}
for group in _HOMOGLYPH_CLASSES:
    canonical = group[0]
    for ch in group:
        _CHAR_FOLD[ch] = canonical


# Multi-character substitutions that look like single characters.
# `rn` typed together looks almost identical to `m` in sans-serif fonts.
_MULTI_FOLD = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
]


def normalise(text: str) -> str:
    """
    Fold homoglyphs to canonical form before edit-distance comparison.

    Order: multi-char folds first, single-char folds second, lowercase
    last (so comparisons are case-insensitive).
    """
    result = text
    for src, dst in _MULTI_FOLD:
        result = result.replace(src, dst)
    result = "".join(_CHAR_FOLD.get(c, c) for c in result)
    return result.lower()


def split_domain(domain: str) -> tuple[str, str]:
    """
    Split a domain into (base, suffix).

    The BASE keeps its original case (so a capital-I attack is still
    visible to the homoglyph detector). The SUFFIX is lowercased
    because DNS treats TLDs case-insensitively.

    paypal.com      -> ("paypal", "com")
    paypaI.com      -> ("paypaI", "com")   # capital I preserved
    paypal.co.ke    -> ("paypal", "co.ke")
    sub.example.com -> ("sub.example", "com")
    """
    stripped = domain.strip()
    parts = stripped.split(".")
    if len(parts) < 2:
        return (stripped, "")

    two_part_tlds = {"co.ke", "co.uk", "com.au", "com.br", "co.za",
                     "co.nz", "com.sg", "or.ke", "ac.ke", "go.ke"}
    last_two = f"{parts[-2]}.{parts[-1]}".lower()
    if len(parts) >= 3 and last_two in two_part_tlds:
        base = ".".join(parts[:-2])
        suffix = last_two
    else:
        base = ".".join(parts[:-1])
        suffix = parts[-1].lower()

    return (base, suffix)


def edit_distance(a: str, b: str) -> int:
    """
    Edit distance via DP, rolling-row memory optimisation.

    Same algorithm as spell-checker's `edit_distance_rolling`.
    O(m*n) time, O(min(m,n)) space.
    """
    if len(b) > len(a):
        a, b = b, a
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        curr[0] = i
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(prev[j], curr[j - 1], prev[j - 1])
        prev, curr = curr, prev
    return prev[n]


@dataclass(frozen=True)
class Threat:
    """A suspicious domain and the legitimate brand it probably mimics."""
    suspicious: str
    brand: str
    distance: int
    reason: str

    def __str__(self) -> str:
        return (f"WARNING  {self.suspicious:30s}  "
                f"→ looks like {self.brand:25s}  "
                f"(distance {self.distance}, {self.reason})")


def classify_domain(domain: str, brands: list[str], max_distance: int = 2) -> Threat | None:
    """
    Compare `domain` against each legitimate brand. Return the closest
    match if it's within `max_distance` edits (after homoglyph
    normalisation), else None.

    Exact matches of a legitimate brand are NOT flagged.
    """
    dom_base, dom_tld = split_domain(domain)
    dom_base_norm = normalise(dom_base)

    best: Threat | None = None
    for brand in brands:
        brand_base, brand_tld = split_domain(brand)
        brand_base_norm = normalise(brand_base)

        # Pre-check: case-insensitive exact match → legitimate, skip.
        if dom_base.lower() == brand_base.lower() and dom_tld == brand_tld:
            return None

        d = edit_distance(dom_base_norm, brand_base_norm)

        # Detect the KIND of similarity for a human-readable reason.
        if d == 0 and dom_base.lower() != brand_base.lower():
            # Characters got folded during normalisation → homoglyph attack
            reason = "homoglyph substitution"
        elif dom_tld != brand_tld and d == 0:
            reason = "TLD swap"
        elif d <= max_distance:
            reason = f"{d} char edit" + ("s" if d != 1 else "")
        else:
            continue

        # Adjust distance score for ranking: TLD mismatch also costs.
        adjusted = d + (0 if dom_tld == brand_tld else 1)

        if best is None or adjusted < best.distance:
            best = Threat(
                suspicious=domain,
                brand=brand,
                distance=adjusted,
                reason=reason,
            )

    if best is not None and best.distance <= max_distance:
        return best
    return None


def scan_domains(domains: list[str], brands: list[str], max_distance: int = 2) -> list[Threat]:
    """Return threats for every domain that looks suspicious."""
    threats: list[Threat] = []
    for d in domains:
        d = d.strip()
        if not d or d.startswith("#"):
            continue
        t = classify_domain(d, brands, max_distance=max_distance)
        if t is not None:
            threats.append(t)
    return threats
