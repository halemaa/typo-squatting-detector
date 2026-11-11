"""
Scan a list of domain names for ones that look suspiciously close
to protected brands.

Usage:
    python detect.py suspicious_domains.txt
    python detect.py domains.txt --brands protected_brands.txt
    python detect.py domains.txt --distance 1          # stricter
    echo "g00gle.com" | python detect.py -             # read from stdin
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from typosquat import scan_domains


DEFAULT_BRANDS = Path(__file__).parent / "brands.txt"


def load_lines(source: str) -> list[str]:
    if source == "-":
        return [ln.rstrip("\n") for ln in sys.stdin]
    path = Path(source)
    if not path.is_file():
        print(f"File not found: {source}", file=sys.stderr)
        sys.exit(2)
    return path.read_text(encoding="utf-8").splitlines()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect domains that look like typo-squats of protected brands.",
    )
    parser.add_argument(
        "domains",
        help="file of candidate domains (one per line), or '-' for stdin",
    )
    parser.add_argument(
        "--brands", type=Path, default=DEFAULT_BRANDS,
        help=f"file of protected brands (default: {DEFAULT_BRANDS.name})",
    )
    parser.add_argument(
        "--distance", type=int, default=2,
        help="maximum edit distance to flag as suspicious (default: 2)",
    )
    args = parser.parse_args()

    if not args.brands.is_file():
        print(f"Brands file not found: {args.brands}", file=sys.stderr)
        return 2

    brands = [b.strip() for b in args.brands.read_text().splitlines()
              if b.strip() and not b.startswith("#")]
    domains = load_lines(args.domains)

    threats = scan_domains(domains, brands, max_distance=args.distance)

    if not threats:
        print(f"Scanned {len(domains)} domain(s). No typo-squats detected.")
        return 0

    print(f"Scanned {len(domains)} domain(s). "
          f"Found {len(threats)} suspicious domain(s):")
    print("-" * 80)
    for t in threats:
        print(t)

    # Non-zero exit so this can gate CI or feed into alerting.
    return 1


if __name__ == "__main__":
    sys.exit(main())
