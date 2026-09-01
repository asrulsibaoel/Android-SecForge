from app.analysis.versions import (
    AFFECTED,
    NOT_AFFECTED,
    UNKNOWN,
    VersionRange,
    compare,
    in_range,
    match_ranges,
)


def test_numeric_not_lexicographic():
    assert compare("1.10.0", "1.9.0") == 1
    assert compare("1.9.0", "1.10.0") == -1
    assert compare("2.0.0", "2.0.0") == 0


def test_prerelease_older_than_release():
    assert compare("1.0.0-alpha", "1.0.0") == -1
    assert compare("1.0.0", "1.0.0-rc1") == 1


def test_uncomparable_returns_none():
    assert compare("abc", "1.0.0") is None


def test_range_exclusive_fixed():
    assert in_range("3.12.0", VersionRange(raw="< 3.14.0")) == AFFECTED
    assert in_range("3.14.0", VersionRange(raw="< 3.14.0")) == NOT_AFFECTED
    assert in_range("3.15.0", VersionRange(raw="< 3.14.0")) == NOT_AFFECTED


def test_range_introduced_fixed():
    r = VersionRange(introduced="1.0", fixed="1.60")
    assert in_range("1.30", r) == AFFECTED
    assert in_range("1.60", r) == NOT_AFFECTED
    assert in_range("0.9", r) == NOT_AFFECTED


def test_exact_range():
    assert in_range("2.8.5", VersionRange(exact="2.8.5")) == AFFECTED
    assert in_range("2.8.6", VersionRange(exact="2.8.5")) == NOT_AFFECTED


def test_unknown_version_is_unknown_not_not_affected():
    assert in_range(None, VersionRange(raw="< 3.14.0")) == UNKNOWN
    assert in_range("UNKNOWN", VersionRange(raw="< 3.14.0")) == UNKNOWN


def test_compound_range():
    assert in_range("1.5.7", VersionRange(raw=">=1.0.0 <2.0.0")) == AFFECTED
    assert in_range("2.5.0", VersionRange(raw=">=1.0.0 <2.0.0")) == NOT_AFFECTED


def test_match_ranges_any():
    ranges = [VersionRange(raw="< 1.0.0"), VersionRange(raw=">=3.0.0 <3.14.0")]
    assert match_ranges("3.12.0", ranges) == AFFECTED
    assert match_ranges("2.0.0", ranges) == NOT_AFFECTED
