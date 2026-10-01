"""Version parsing and range comparison for CVE correlation.

Versions are compared numerically, never lexicographically (so 1.10.0 > 1.9.0).
When a reliable comparison cannot be made the result is ``UNKNOWN`` — and
``UNKNOWN`` is never downgraded to ``NOT_AFFECTED`` by callers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEMVER, MAVEN, ANDROID, GENERIC, UNKNOWN_STRATEGY = "SEMVER", "MAVEN", "ANDROID", "GENERIC", "UNKNOWN"

AFFECTED, NOT_AFFECTED, UNKNOWN = "AFFECTED", "NOT_AFFECTED", "UNKNOWN"

# Common pre-release qualifiers ordered from oldest to newest (lower = earlier).
_QUALIFIER_ORDER = {
    "dev": -6, "alpha": -5, "a": -5, "beta": -4, "b": -4, "milestone": -3, "m": -3,
    "rc": -2, "cr": -2, "snapshot": -1, "": 0, "ga": 0, "final": 0, "release": 0, "sp": 1,
}

_VERSION_RE = re.compile(r"^\s*v?(\d+(?:[.\-_+]\w+)*)\s*$")


@dataclass
class VersionRange:
    """A single affected-version constraint (OSV-style or raw operators)."""
    introduced: str | None = None       # >= (inclusive)
    fixed: str | None = None            # <  (exclusive)
    last_affected: str | None = None    # <= (inclusive)
    exact: str | None = None            # ==
    raw: str | None = None              # e.g. "< 3.14.0" or ">=1.0.0 <2.0.0"


def _tokenize(version: str) -> list | None:
    match = _VERSION_RE.match(version)
    if not match:
        return None
    core = match.group(1)
    tokens: list = []
    for part in re.split(r"[.\-_+]", core):
        if part.isdigit():
            tokens.append((0, int(part)))          # numeric segment
        else:
            num = re.match(r"(\d+)([A-Za-z].*)?", part)
            if num and num.group(1):
                tokens.append((0, int(num.group(1))))
                if num.group(2):
                    tokens.append((1, _QUALIFIER_ORDER.get(num.group(2).lower(), 2), num.group(2).lower()))
            else:
                tokens.append((1, _QUALIFIER_ORDER.get(part.lower(), 2), part.lower()))
    return tokens


def compare(a: str, b: str, strategy: str = GENERIC) -> int | None:
    """Return -1/0/1, or None when the versions cannot be reliably compared."""
    ta, tb = _tokenize(a), _tokenize(b)
    if ta is None or tb is None:
        return None
    # Pad numeric-only cores with zeros for fair comparison.
    for i in range(max(len(ta), len(tb))):
        sa = ta[i] if i < len(ta) else (0, 0)
        sb = tb[i] if i < len(tb) else (0, 0)
        if sa[0] != sb[0]:
            # numeric segment vs qualifier: a trailing qualifier (pre-release) is
            # older than the same numeric core with no qualifier.
            return 1 if sa[0] == 0 else -1
        if sa[0] == 0:  # both numeric
            if sa[1] != sb[1]:
                return -1 if sa[1] < sb[1] else 1
        else:  # both qualifiers
            if sa[1] != sb[1]:
                return -1 if sa[1] < sb[1] else 1
            # identical qualifier rank but different text: fall back to str compare
            if len(sa) > 2 and len(sb) > 2 and sa[2] != sb[2]:
                if sa[1] == 2:  # unknown qualifiers -> not reliably comparable
                    return None
                return -1 if sa[2] < sb[2] else 1
    return 0


def _cmp_or_unknown(version: str, other: str, strategy: str):
    return compare(version, other, strategy)


def in_range(version: str | None, vrange: VersionRange, strategy: str = GENERIC) -> str:
    """AFFECTED / NOT_AFFECTED / UNKNOWN for a version against one range."""
    if not version or version.upper() == "UNKNOWN":
        return UNKNOWN
    if vrange.raw:
        return _match_raw(version, vrange.raw, strategy)

    if vrange.exact is not None:
        c = compare(version, vrange.exact, strategy)
        if c is None:
            return UNKNOWN
        return AFFECTED if c == 0 else NOT_AFFECTED

    results = []
    if vrange.introduced is not None:
        c = compare(version, vrange.introduced, strategy)
        if c is None:
            return UNKNOWN
        results.append(c >= 0)
    if vrange.fixed is not None:
        c = compare(version, vrange.fixed, strategy)
        if c is None:
            return UNKNOWN
        results.append(c < 0)
    if vrange.last_affected is not None:
        c = compare(version, vrange.last_affected, strategy)
        if c is None:
            return UNKNOWN
        results.append(c <= 0)
    if not results:
        return UNKNOWN
    return AFFECTED if all(results) else NOT_AFFECTED


_OP_RE = re.compile(r"(<=|>=|<|>|==|=)\s*([\w.\-+]+)")


def _match_raw(version: str, raw: str, strategy: str) -> str:
    constraints = _OP_RE.findall(raw)
    if not constraints:
        return UNKNOWN
    ok = []
    for op, value in constraints:
        c = compare(version, value, strategy)
        if c is None:
            return UNKNOWN
        if op == "<":
            ok.append(c < 0)
        elif op == "<=":
            ok.append(c <= 0)
        elif op == ">":
            ok.append(c > 0)
        elif op == ">=":
            ok.append(c >= 0)
        else:  # == or =
            ok.append(c == 0)
    return AFFECTED if all(ok) else NOT_AFFECTED


def match_ranges(version: str | None, ranges: list[VersionRange], strategy: str = GENERIC) -> str:
    """Combine multiple ranges: AFFECTED if any matches, else NOT_AFFECTED, else UNKNOWN."""
    if not ranges:
        return UNKNOWN
    states = [in_range(version, r, strategy) for r in ranges]
    if AFFECTED in states:
        return AFFECTED
    if UNKNOWN in states:
        return UNKNOWN
    return NOT_AFFECTED
