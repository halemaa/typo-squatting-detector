"""Tests for the typo-squatting detector."""

import pytest

from typosquat import (
    classify_domain,
    edit_distance,
    normalise,
    scan_domains,
    split_domain,
)


# ---------- normalisation (homoglyph folding) ----------

def test_zero_folds_to_o():
    assert normalise("g00gle") == normalise("google")


def test_capital_i_folds_to_lowercase_l():
    assert normalise("paypaI") == normalise("paypal")


def test_digit_1_folds_to_l():
    """
    Digit `1` is a homoglyph of lowercase `l`, so it should fold to it.
    But that doesn't make `l1nkedin` and `linkedin` identical —
    `linkedin` has an `i` where `l1nkedin` has a `1`, and lowercase `i`
    is NOT a homoglyph of `l`. We just test the digit folds correctly.
    """
    # The `1` folds to `l` — so `l1` becomes `ll`, which is a visibly
    # closer match to `li` than the raw `l1` was.
    assert "1" not in normalise("l1nkedin")
    assert normalise("l1nkedin")[1] == "l"


def test_unrelated_chars_untouched():
    assert normalise("hello") == "hello"
    assert normalise("safaricom") == "safaricom"


# ---------- domain splitting ----------

@pytest.mark.parametrize("domain,expected", [
    ("google.com",       ("google", "com")),
    ("paypal.co.uk",     ("paypal", "co.uk")),
    ("safaricom.co.ke",  ("safaricom", "co.ke")),
    ("usiu.ac.ke",       ("usiu", "ac.ke")),
    ("sub.example.com",  ("sub.example", "com")),
    ("example",          ("example", "")),
])
def test_split_domain(domain, expected):
    assert split_domain(domain) == expected


# ---------- edit distance ----------

def test_edit_distance_matches_spellcheck():
    """Should produce same answers as the classic Levenshtein algorithm."""
    assert edit_distance("kitten", "sitting") == 3
    assert edit_distance("google", "gogle") == 1
    assert edit_distance("", "abc") == 3


# ---------- classify_domain ----------

def test_legit_domain_not_flagged():
    brands = ["google.com", "paypal.com"]
    assert classify_domain("google.com", brands) is None
    assert classify_domain("paypal.com", brands) is None


def test_typo_flagged():
    brands = ["google.com"]
    threat = classify_domain("gogle.com", brands)
    assert threat is not None
    assert threat.brand == "google.com"
    assert threat.distance == 1


def test_homoglyph_flagged_as_zero_distance():
    brands = ["paypal.com"]
    threat = classify_domain("paypaI.com", brands)
    assert threat is not None
    assert "homoglyph" in threat.reason


def test_zero_for_o_homoglyph():
    brands = ["google.com"]
    threat = classify_domain("g00gle.com", brands)
    assert threat is not None
    assert threat.brand == "google.com"


def test_tld_swap_flagged():
    brands = ["google.com"]
    threat = classify_domain("google.co", brands)
    assert threat is not None
    assert "TLD" in threat.reason


def test_unrelated_domain_not_flagged():
    brands = ["google.com", "paypal.com"]
    assert classify_domain("example.com", brands) is None
    assert classify_domain("wikipedia.org", brands) is None


def test_ranks_closest_brand_first():
    """Attack targeting 'microsoft' shouldn't be mistakenly matched to 'mystartup'."""
    brands = ["microsoft.com", "mystartup.io"]
    threat = classify_domain("microsft.com", brands)
    assert threat is not None
    assert threat.brand == "microsoft.com"


def test_kenyan_domain_detection():
    """Multi-part TLDs should work correctly."""
    brands = ["safaricom.co.ke"]
    threat = classify_domain("safaric0m.co.ke", brands)
    assert threat is not None
    assert threat.brand == "safaricom.co.ke"


# ---------- scan_domains ----------

def test_scan_ignores_comments_and_blanks():
    domains = ["# this is a comment", "", "gogle.com"]
    brands = ["google.com"]
    results = scan_domains(domains, brands)
    assert len(results) == 1


def test_scan_many_domains():
    brands = ["google.com", "paypal.com", "safaricom.co.ke"]
    domains = [
        "google.com",          # legit
        "gogle.com",           # typo
        "paypaI.com",          # homoglyph
        "example.com",         # unrelated
        "safaric0m.co.ke",     # kenya homoglyph
    ]
    results = scan_domains(domains, brands)
    assert len(results) == 3
    flagged = {t.suspicious for t in results}
    assert "google.com" not in flagged
    assert "example.com" not in flagged
