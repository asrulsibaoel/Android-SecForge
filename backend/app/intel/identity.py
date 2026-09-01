"""Deterministic identity normalization + matching (prompt 16).

Normalizes CPE 2.3, PURL, Maven coordinates, package prefixes, and native
SONAMEs, and computes an explicit identity-match confidence
(EXACT/HIGH/MEDIUM/LOW/UNKNOWN) between a dependency and a vulnerability's
identities. Two identities are never equated just because their strings look
similar — only EXACT/HIGH are eligible for confirmed correlation.
"""

from __future__ import annotations

import re

EXACT, HIGH, MEDIUM, LOW, UNKNOWN = "EXACT", "HIGH", "MEDIUM", "LOW", "UNKNOWN"
_CONF_RANK = {UNKNOWN: -1, LOW: 0, MEDIUM: 1, HIGH: 2, EXACT: 3}


def _clean(value: str | None) -> str:
    return (value or "").strip().lower()


def normalize_cpe(cpe: str | None) -> str:
    """Canonicalize a CPE 2.3 string to `cpe:2.3:a:vendor:product` (lowercased).
    A `cpe:/a:` 2.2 URI is upgraded; unparseable input is returned trimmed."""
    if not cpe:
        return ""
    c = cpe.strip()
    if c.lower().startswith("cpe:2.3:"):
        parts = c.split(":")
        if len(parts) >= 5:
            return ":".join(["cpe", "2.3", parts[2].lower(), parts[3].lower(), parts[4].lower()])
        return c.lower()
    if c.lower().startswith("cpe:/"):
        body = c[5:]
        seg = body.split(":")
        part = seg[0] if seg else "a"
        vendor = seg[1] if len(seg) > 1 else "*"
        product = seg[2] if len(seg) > 2 else "*"
        return ":".join(["cpe", "2.3", part.lower(), vendor.lower(), product.lower()])
    return c.lower()


def cpe_vendor_product(cpe: str | None) -> tuple[str, str]:
    norm = normalize_cpe(cpe)
    parts = norm.split(":")
    if len(parts) >= 5 and parts[0] == "cpe":
        return parts[3], parts[4]
    return "", ""


_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>.+?)(?:@(?P<version>[^?#]+))?(?:[?#].*)?$")


def normalize_purl(purl: str | None) -> str:
    """Canonicalize a PURL to `pkg:type/namespace/name` (version stripped)."""
    if not purl:
        return ""
    m = _PURL_RE.match(purl.strip())
    if not m:
        return purl.strip().lower()
    ptype = m.group("type").lower()
    rest = m.group("rest").strip("/").lower()
    return f"pkg:{ptype}/{rest}"


def purl_coordinate(purl: str | None) -> str:
    """Extract a `namespace/name` coordinate from a PURL (no type/version)."""
    norm = normalize_purl(purl)
    if norm.startswith("pkg:") and "/" in norm:
        return norm.split("/", 1)[1]
    return ""


def normalize_maven(package_name: str | None, product: str | None = None) -> str:
    """Return a `groupId:artifactId` coordinate. Accepts `group:artifact`, or a
    dotted group + separate artifact/product."""
    pkg = (package_name or "").strip()
    if ":" in pkg:
        group, artifact = pkg.split(":", 1)
        return f"{group.strip().lower()}:{artifact.strip().lower()}"
    if pkg and product:
        return f"{pkg.lower()}:{_clean(product)}"
    return _clean(pkg or product)


_LIB_RE = re.compile(r"^lib(.+?)(?:[.-]\d.*)?\.so(?:\.\d+)*$", re.IGNORECASE)


def normalize_soname(soname: str | None) -> str:
    """Reduce a native SONAME/filename to its stable stem (drop `lib`, `.so`, version)."""
    s = (soname or "").strip()
    if not s:
        return ""
    base = s.rsplit("/", 1)[-1]
    m = _LIB_RE.match(base)
    if m:
        return m.group(1).lower()
    return re.sub(r"\.so(\.\d+)*$", "", base, flags=re.IGNORECASE).lower()


# ---------------------------------------------------------------------------
# Dependency -> normalized identity tokens
# ---------------------------------------------------------------------------


def dependency_identities(dep) -> dict[str, set[str]]:
    """Normalized identities the dependency presents, grouped by type."""
    out: dict[str, set[str]] = {"CPE": set(), "PURL": set(), "MAVEN": set(),
                                "PACKAGE": set(), "SONAME": set(), "NAME": set()}
    if dep.name:
        out["NAME"].add(_clean(dep.name))
    if getattr(dep, "product", None):
        out["NAME"].add(_clean(dep.product))
    if getattr(dep, "cpe", None):
        out["CPE"].add(normalize_cpe(dep.cpe))
        _, product = cpe_vendor_product(dep.cpe)
        if product:
            out["NAME"].add(product)
    if dep.kind == "java":
        prefix = getattr(dep, "package_prefix", None)
        if prefix:
            out["PACKAGE"].add(_clean(prefix))
            out["MAVEN"].add(normalize_maven(prefix, dep.product or dep.name))
        # explicit group:artifact when present in artifact metadata
        if getattr(dep, "product", None):
            out["MAVEN"].add(normalize_maven(prefix or "", dep.product))
    if dep.kind == "native":
        out["SONAME"].add(normalize_soname(dep.name))
        if getattr(dep, "artifact", None):
            out["SONAME"].add(normalize_soname(dep.artifact))
    return {k: {v for v in vs if v} for k, vs in out.items()}


def identity_match(dep, vuln_identities) -> tuple[str, dict | None]:
    """Best identity-match confidence between a dependency and a vulnerability's
    persisted identities. Returns (confidence, matched-identity-dict-or-None)."""
    dep_ids = dependency_identities(dep)
    best_conf = UNKNOWN
    best_match: dict | None = None

    def consider(conf, itype, value):
        nonlocal best_conf, best_match
        if _CONF_RANK[conf] > _CONF_RANK[best_conf]:
            best_conf = conf
            best_match = {"identity_type": itype, "value": value, "confidence": conf}

    for ident in vuln_identities:
        itype = ident.identity_type
        value = ident.value or ""
        eco = ident.ecosystem
        if itype == "CPE":
            nv = normalize_cpe(value)
            if nv and nv in dep_ids["CPE"]:
                consider(EXACT, itype, value)
            else:
                _, product = cpe_vendor_product(value)
                if product and product in dep_ids["NAME"]:
                    consider(HIGH, itype, value)
        elif itype == "PURL":
            nv = normalize_purl(value)
            if nv and nv in dep_ids["PURL"]:
                consider(EXACT, itype, value)
            elif purl_coordinate(value) and purl_coordinate(value).split("/")[-1] in dep_ids["NAME"]:
                consider(HIGH, itype, value)
        elif itype == "MAVEN":
            nv = normalize_maven(value)
            if nv and nv in dep_ids["MAVEN"]:
                consider(EXACT, itype, value)
            elif ":" in nv and nv.split(":", 1)[1] in dep_ids["NAME"]:
                consider(HIGH, itype, value)
        elif itype == "SONAME":
            nv = normalize_soname(value)
            if nv and nv in dep_ids["SONAME"]:
                consider(EXACT, itype, value)
        elif itype == "PACKAGE":
            v = _clean(value)
            if v and (v in dep_ids["PACKAGE"] or any(p == v or p.startswith(v + ".") or v.startswith(p + ".")
                                                     for p in dep_ids["PACKAGE"])):
                consider(HIGH if v in dep_ids["PACKAGE"] else MEDIUM, itype, value)
            elif v and v in dep_ids["NAME"]:
                consider(MEDIUM, itype, value)
    return best_conf, best_match


def is_confirmable(confidence: str) -> bool:
    """Only EXACT/HIGH identity matches are eligible for confirmed correlation."""
    return _CONF_RANK.get(confidence, -1) >= _CONF_RANK[HIGH]


def rank(confidence: str) -> int:
    return _CONF_RANK.get(confidence, -1)
