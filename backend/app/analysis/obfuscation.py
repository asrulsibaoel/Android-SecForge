"""Obfuscation & anti-analysis intelligence (prompt 19).

A deterministic, offline projection over already-persisted evidence (code
entities, the canonical code graph, semantics, native/JNI). It identifies
transformations that make static analysis difficult — identifier/string/control-
flow obfuscation, reflection/dynamic-load indirection, native indirection — and
the analytical impact that results, plus separately-classified anti-analysis
indicators.

It is analysis intelligence, NOT an evasion/bypass engine: it never mutates
findings, CVE state, severity, risk, remediation, validation, or the canonical
graph; never asserts exploitability; never claims obfuscation == vulnerability or
anti-analysis == malicious; and preserves observed-fact vs indicator vs UNKNOWN
distinctions (UNKNOWN / UNKNOWN_NATIVE_TARGET / POSSIBLY_AFFECTED are preserved).

The obfuscation score describes ANALYSIS COMPLEXITY, a separate axis from
severity / confidence / risk / remediation priority / validation confidence.

Complexity: single-pass class/method scan with cached identifier statistics,
indexed target lookup, bounded string/method analysis, reuse of persisted
reachability paths — no N×M scans, no graph reconstruction.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from app.core.config import settings
from app.models.obfuscation import (
    AnalysisImpact, AntiAnalysisIndicator, ObfuscationObservation,
    L_CONFIRMED_STATIC, L_INDICATOR, L_SUPPORTED,
    S_EXTERNALLY_INFLUENCED, S_OBSERVED, S_RESOLVED, S_STRONG_INDICATOR, S_UNKNOWN,
    S_UNRESOLVED, S_WEAK_INDICATOR,
)

# --- finding types ---------------------------------------------------------
FT_IDENTIFIER = "ANDROID-OBFUSCATION-001"
FT_STRING = "ANDROID-OBFUSCATION-002"
FT_CONTROL_FLOW = "ANDROID-OBFUSCATION-003"
FT_DYNAMIC_RESOLUTION = "ANDROID-OBFUSCATION-004"
FT_NATIVE_INDIRECTION = "ANDROID-OBFUSCATION-005"
FT_AA_DEBUGGER = "ANDROID-ANTI-ANALYSIS-001"
FT_AA_ENVIRONMENT = "ANDROID-ANTI-ANALYSIS-002"
FT_AA_INSTRUMENTATION = "ANDROID-ANTI-ANALYSIS-003"
FT_AA_INTEGRITY = "ANDROID-ANTI-ANALYSIS-004"

# --- categories ------------------------------------------------------------
CAT_IDENTIFIER = "IDENTIFIER_OBFUSCATION"
CAT_STRING = "STRING_OBFUSCATION"
CAT_CONTROL_FLOW = "CONTROL_FLOW_OBFUSCATION"
CAT_DYNAMIC_RESOLUTION = "DYNAMIC_RESOLUTION"
CAT_NATIVE_INDIRECTION = "NATIVE_INDIRECTION"

# --- analysis-impact categories --------------------------------------------
I_REDUCED_NAME = "REDUCED_NAME_CONFIDENCE"
I_UNRESOLVED_REFLECTION = "UNRESOLVED_REFLECTION"
I_UNRESOLVED_DYNAMIC_LOAD = "UNRESOLVED_DYNAMIC_LOAD"
I_REDUCED_NATIVE = "REDUCED_NATIVE_RESOLUTION"
I_INCREASED_REACH = "INCREASED_REACHABILITY_UNCERTAINTY"
I_INCREASED_BEHAVIOR = "INCREASED_BEHAVIORAL_UNCERTAINTY"

# --- documented score weights (analysis complexity — separate axis) --------
OBFUSCATION_WEIGHTS = {
    "identifier_strong": 25,
    "identifier_weak": 12,
    "string_obfuscation": 15,
    "unresolved_reflection": 12,
    "unresolved_dynamic_load": 12,
    "native_stripped": 15,
    "native_sparse": 8,
    "control_flow": 10,
    "anti_analysis_supported": 10,
}
OBFUSCATION_PENALTIES = {
    "descriptive_identifiers": 15,
    "resolved_targets": 8,
    "symbols_available": 8,
}

# Identifier heuristics (thresholds documented; short alone is NOT obfuscation).
_MIN_CLASSES_FOR_IDENTIFIER = 8       # need enough classes to judge a ratio
_SHORT_RATIO_STRONG = 0.5
_SHORT_RATIO_WEAK = 0.25
_GENERATED_RE = re.compile(r"^(?:[a-z]{1,2}|[a-z][0-9]{1,3}|[a-z]{1,2}[0-9]{1,3})$")
_SHORT_NAME_LEN = 2

# String-obfuscation patterns (statically observable; never decrypted).
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")
_UNICODE_ESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
_RECONSTRUCT_RE = re.compile(r"(Base64\.decode|new String\(|\bxor\b|\^\s*0x|StringBuilder.*decode)", re.IGNORECASE)

# Anti-analysis keyword -> (category, finding_type). Presence is an INDICATOR only.
_AA_KEYWORDS = {
    "frida": ("INSTRUMENTATION", FT_AA_INSTRUMENTATION),
    "gum-js": ("INSTRUMENTATION", FT_AA_INSTRUMENTATION),
    "gadget": ("INSTRUMENTATION", FT_AA_INSTRUMENTATION),
    "xposed": ("ANTI_HOOKING", FT_AA_INSTRUMENTATION),
    "substrate": ("ANTI_HOOKING", FT_AA_INSTRUMENTATION),
    "ptrace": ("PTRACE", FT_AA_DEBUGGER),
    "tracerpid": ("PTRACE", FT_AA_DEBUGGER),
    "isdebuggerconnected": ("DEBUGGER", FT_AA_DEBUGGER),
    "waitingfordebugger": ("DEBUGGER", FT_AA_DEBUGGER),
    "goldfish": ("EMULATOR", FT_AA_ENVIRONMENT),
    "ranchu": ("EMULATOR", FT_AA_ENVIRONMENT),
    "sdk_gphone": ("EMULATOR", FT_AA_ENVIRONMENT),
    "qemu": ("EMULATOR", FT_AA_ENVIRONMENT),
    "generic_x86": ("EMULATOR", FT_AA_ENVIRONMENT),
    "supersu": ("ROOT", FT_AA_ENVIRONMENT),
    "superuser": ("ROOT", FT_AA_ENVIRONMENT),
    "magisk": ("ROOT", FT_AA_ENVIRONMENT),
    "rootbeer": ("ROOT", FT_AA_ENVIRONMENT),
    "test-keys": ("ROOT", FT_AA_ENVIRONMENT),
    "/system/bin/su": ("ROOT", FT_AA_ENVIRONMENT),
    "get_signatures": ("INTEGRITY", FT_AA_INTEGRITY),
    "checksignature": ("INTEGRITY", FT_AA_INTEGRITY),
    "signingcertificate": ("INTEGRITY", FT_AA_INTEGRITY),
}


def _fp(*parts) -> str:
    raw = "|".join(str(p or "").lower() for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# In-memory dataclasses
# ---------------------------------------------------------------------------


@dataclass
class OObs:
    finding_type: str
    category: str
    indicator: str
    target_type: str
    target: str | None
    state: str
    confidence: str
    source_type: str
    source_id: str | None = None
    evidence_json: dict = field(default_factory=dict)
    uncertainties: list = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return _fp(self.category, self.indicator, self.target)


@dataclass
class AAObs:
    finding_type: str
    category: str
    indicator: str
    target_type: str
    target: str | None
    evidence_level: str
    confidence: str
    source_type: str
    source_id: str | None = None
    evidence_json: dict = field(default_factory=dict)
    uncertainties: list = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return _fp("ANTI", self.category, self.indicator, self.target)


@dataclass
class AImpact:
    impact_category: str
    description: str
    affected_target: str | None
    confidence: str
    source_observation_fp: str | None = None
    evidence_json: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return _fp("IMPACT", self.impact_category, self.affected_target)


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _simple(entity) -> str:
    if entity.name:
        return entity.name
    if entity.class_name:
        return entity.class_name.rsplit(".", 1)[-1]
    return ""


def _identifier_observations(analysis) -> tuple[list[OObs], dict]:
    classes = [e for e in analysis.code_entities if e.entity_type == "class"][:settings.obfuscation_max_classes]
    methods = [e for e in analysis.code_entities if e.entity_type == "method"][:settings.obfuscation_max_methods]
    stats = {"classes": len(classes), "methods": len(methods), "available": bool(classes)}
    if len(classes) < _MIN_CLASSES_FOR_IDENTIFIER:
        stats["status"] = "UNAVAILABLE" if not classes else "INSUFFICIENT_CLASSES"
        return [], stats

    def short_or_generated(name: str) -> bool:
        n = (name or "").strip()
        return bool(n) and (len(n) <= _SHORT_NAME_LEN or _GENERATED_RE.match(n) is not None)

    short_classes = [c for c in classes if short_or_generated(_simple(c))]
    short_methods = [m for m in methods if short_or_generated(m.name or "")]
    # package flattening: single-char package segments
    pkgs = {(c.package or "") for c in classes}
    flat_pkgs = [p for p in pkgs if p and any(len(seg) <= 1 for seg in p.split("."))]
    class_ratio = len(short_classes) / len(classes)
    method_ratio = (len(short_methods) / len(methods)) if methods else 0.0
    stats.update({"short_class_ratio": round(class_ratio, 3), "short_method_ratio": round(method_ratio, 3),
                  "flattened_packages": len(flat_pkgs), "short_classes": len(short_classes)})

    obs: list[OObs] = []
    if class_ratio >= _SHORT_RATIO_STRONG or (class_ratio >= _SHORT_RATIO_WEAK and flat_pkgs):
        state = S_STRONG_INDICATOR if class_ratio >= _SHORT_RATIO_STRONG else S_WEAK_INDICATOR
        conf = "HIGH" if class_ratio >= _SHORT_RATIO_STRONG else "MEDIUM"
        sample = sorted({_simple(c) for c in short_classes})[:10]
        obs.append(OObs(FT_IDENTIFIER, CAT_IDENTIFIER,
                        f"{len(short_classes)}/{len(classes)} classes ({class_ratio:.0%}) use short/generated names",
                        "APK", None, state, conf, "JADX",
                        evidence_json={"short_class_ratio": round(class_ratio, 3),
                                       "short_method_ratio": round(method_ratio, 3),
                                       "flattened_packages": len(flat_pkgs), "sample": sample},
                        uncertainties=["short/generated names are an indicator, not proof of obfuscation"]))
    elif class_ratio >= _SHORT_RATIO_WEAK:
        obs.append(OObs(FT_IDENTIFIER, CAT_IDENTIFIER,
                        f"{len(short_classes)}/{len(classes)} classes ({class_ratio:.0%}) use short names",
                        "APK", None, S_WEAK_INDICATOR, "LOW", "JADX",
                        evidence_json={"short_class_ratio": round(class_ratio, 3)},
                        uncertainties=["short names alone do not imply obfuscation"]))
    stats["descriptive_majority"] = class_ratio < _SHORT_RATIO_WEAK
    return obs, stats


def _string_observations(analysis) -> tuple[list[OObs], dict]:
    # bounded scan of already-persisted string-bearing evidence (never decrypts)
    texts: list[tuple[str, str]] = []  # (source_id, text)
    for f in analysis.findings:
        for e in f.evidence:
            if e.detail:
                texts.append((e.location or f.rule_id, e.detail))
    for se in analysis.semantic_edges:
        if se.evidence:
            texts.append((se.src_key, se.evidence))
    for i in analysis.intents:
        if i.data_uri:
            texts.append((i.class_name or "intent", i.data_uri))
    texts = texts[:settings.obfuscation_max_strings]

    b64 = hexs = uni = recon = 0
    samples: list[str] = []
    for sid, t in texts:
        if _B64_RE.search(t):
            b64 += 1
            if len(samples) < 5:
                samples.append((_B64_RE.search(t).group(0)[:24] + "…"))
        if _HEX_RE.search(t):
            hexs += 1
        if _UNICODE_ESC_RE.search(t):
            uni += 1
        if _RECONSTRUCT_RE.search(t):
            recon += 1
    stats = {"scanned": len(texts), "base64_like": b64, "hex_like": hexs, "unicode_escaped": uni,
             "reconstruction": recon, "available": bool(texts)}
    obs: list[OObs] = []
    encoded = b64 + hexs + uni
    if encoded >= 3 and recon >= 1:
        obs.append(OObs(FT_STRING, CAT_STRING,
                        f"{encoded} encoded-string constants with {recon} runtime-reconstruction site(s)",
                        "APK", None, S_STRONG_INDICATOR, "MEDIUM", "JADX",
                        evidence_json={"base64_like": b64, "hex_like": hexs, "reconstruction": recon,
                                       "sample": samples},
                        uncertainties=["encoded constants are not decrypted; resolved target = UNKNOWN"]))
    elif encoded >= 3:
        obs.append(OObs(FT_STRING, CAT_STRING, f"{encoded} encoded-string constants observed", "APK", None,
                        S_WEAK_INDICATOR, "LOW", "JADX",
                        evidence_json={"base64_like": b64, "hex_like": hexs, "sample": samples},
                        uncertainties=["encoded constants are not decrypted; resolved target = UNKNOWN"]))
    return obs, stats


def _reachable_keys(analysis) -> set[str]:
    keys: set[str] = set()
    for p in analysis.reachability_paths:
        if p.status == "REACHABLE":
            for n in (p.nodes or []):
                if n.get("key"):
                    keys.add(n["key"])
            keys.add(p.from_key)
    return keys


def _dynamic_resolution_observations(analysis) -> tuple[list[OObs], list[AImpact], dict]:
    reachable = _reachable_keys(analysis)
    obs: list[OObs] = []
    impacts: list[AImpact] = []
    counts = {"reflection_total": 0, "reflection_unresolved": 0, "reflection_resolved": 0,
              "dynload_total": 0, "dynload_unresolved": 0, "dynload_resolved": 0}
    for se in analysis.semantic_edges:
        if se.edge_type not in ("REFLECTION_TARGET", "DYNAMIC_LOAD"):
            continue
        is_reflection = se.edge_type == "REFLECTION_TARGET"
        kind = "reflection" if is_reflection else "dynamic_load"
        ckey = "reflection" if is_reflection else "dynload"
        unresolved = se.dst_key.endswith("UNKNOWN") or se.dst_key.startswith(("reflect:UNKNOWN", "dynload:UNKNOWN"))
        externally = se.src_key in reachable
        counts[f"{ckey}_total"] += 1
        if unresolved:
            state = S_EXTERNALLY_INFLUENCED if externally else S_UNRESOLVED
            counts[f"{ckey}_unresolved"] += 1
            unc = ["target = UNKNOWN; never inferred"]
            if externally:
                unc.append("source is reachable from an entry point (externally influenced)")
            o = OObs(FT_DYNAMIC_RESOLUTION, CAT_DYNAMIC_RESOLUTION,
                     f"unresolved {kind} target", "CODE_METHOD", se.src_key, state, "MEDIUM", "SEMANTICS",
                     source_id=se.src_key, evidence_json={"edge": se.edge_type, "target": se.dst_key,
                                                          "reachable": externally}, uncertainties=unc)
            obs.append(o)
            impact_cat = I_UNRESOLVED_REFLECTION if is_reflection else I_UNRESOLVED_DYNAMIC_LOAD
            impacts.append(AImpact(impact_cat, f"{kind} target at {se.src_key} is UNKNOWN; downstream behavior "
                                   f"cannot be resolved statically", se.src_key, "MEDIUM", o.fingerprint,
                                   {"edge": se.edge_type}))
            if externally:
                impacts.append(AImpact(I_INCREASED_REACH, f"reachable {kind} with UNKNOWN target increases "
                                       f"reachability uncertainty at {se.src_key}", se.src_key, "MEDIUM",
                                       o.fingerprint, {}))
        else:
            counts[f"{ckey}_resolved"] += 1
            obs.append(OObs(FT_DYNAMIC_RESOLUTION, CAT_DYNAMIC_RESOLUTION,
                            f"constant {kind} target", "CODE_METHOD", se.src_key, S_RESOLVED, "MEDIUM", "SEMANTICS",
                            source_id=se.src_key, evidence_json={"edge": se.edge_type, "target": se.dst_key}))
    counts["available"] = (counts["reflection_total"] + counts["dynload_total"]) > 0
    return obs, impacts, counts


def _control_flow_observations(analysis) -> tuple[list[OObs], dict]:
    # fan-out per method from the canonical code graph (no re-parse); high fan-out
    # dispatcher-like methods are a WEAK indicator only, above a high threshold.
    fanout: dict[str, int] = {}
    for e in analysis.code_edges:
        if e.edge_type in ("CALLS", "INVOKES"):
            fanout[e.src_key] = fanout.get(e.src_key, 0) + 1
    high = {k: v for k, v in fanout.items() if v >= 40}
    stats = {"methods_with_edges": len(fanout), "high_fanout_methods": len(high), "available": bool(fanout)}
    obs: list[OObs] = []
    if len(high) >= 3:
        top = sorted(high.items(), key=lambda kv: -kv[1])[:5]
        obs.append(OObs(FT_CONTROL_FLOW, CAT_CONTROL_FLOW,
                        f"{len(high)} methods with dispatcher-like fan-out (>=40 calls)", "CODE", None,
                        S_WEAK_INDICATOR, "LOW", "REACHABILITY",
                        evidence_json={"high_fanout_methods": len(high), "top": [k for k, _ in top]},
                        uncertainties=["high fan-out is a weak indicator; may be normal generated dispatch"]))
    return obs, stats


def _native_observations(analysis) -> tuple[list[OObs], list[AImpact], dict]:
    obs: list[OObs] = []
    impacts: list[AImpact] = []
    stripped = sparse = 0
    for lib in analysis.native_libraries:
        if lib.status != "COMPLETE":
            continue
        exported = sum(1 for fn in lib.functions if fn.kind == "exported")
        if lib.stripped or not lib.symbols_available:
            stripped += 1
            o = OObs(FT_NATIVE_INDIRECTION, CAT_NATIVE_INDIRECTION, "stripped native symbols",
                     "NATIVE_LIBRARY", lib.filename, S_OBSERVED, "HIGH", "ELF", source_id=lib.archive_path,
                     evidence_json={"stripped": lib.stripped, "symbols_available": lib.symbols_available,
                                    "exported": exported},
                     uncertainties=["stripped symbols reduce native target resolution; UNKNOWN_NATIVE_TARGET preserved"])
            obs.append(o)
            impacts.append(AImpact(I_REDUCED_NATIVE, f"{lib.filename} is stripped; native target resolution is "
                                   f"reduced (UNKNOWN_NATIVE_TARGET preserved)", lib.filename, "HIGH", o.fingerprint,
                                   {"stripped": True}))
        elif exported <= 2 and lib.size_bytes and lib.size_bytes > 200000:
            sparse += 1
            obs.append(OObs(FT_NATIVE_INDIRECTION, CAT_NATIVE_INDIRECTION,
                            f"sparse exports ({exported}) for a large library", "NATIVE_LIBRARY", lib.filename,
                            S_WEAK_INDICATOR, "LOW", "ELF", source_id=lib.archive_path,
                            evidence_json={"exported": exported, "size_bytes": lib.size_bytes}))
    # JNI boundaries with UNKNOWN native target (preserve, never fabricate a call graph)
    for b in analysis.security_boundaries:
        if (b.boundary_type or "").upper() == "JNI":
            o = OObs(FT_NATIVE_INDIRECTION, CAT_NATIVE_INDIRECTION, "JNI boundary with UNKNOWN_NATIVE_TARGET",
                     "JNI_BINDING", b.component or b.node_key, S_UNKNOWN, "MEDIUM", "JNI", source_id=b.node_key,
                     evidence_json={"native_target": "UNKNOWN_NATIVE_TARGET"},
                     uncertainties=["native call graph is not modeled; UNKNOWN_NATIVE_TARGET preserved"])
            obs.append(o)
    stats = {"stripped_libraries": stripped, "sparse_libraries": sparse,
             "libraries": len(analysis.native_libraries), "available": bool(analysis.native_libraries)}
    return obs, impacts, stats


def _anti_analysis_indicators(analysis) -> tuple[list[AAObs], dict]:
    # bounded scan of persisted evidence for indicator keywords (presence only)
    hits: list[tuple[str, str, str, str]] = []  # (keyword, category, finding_type, source_id)
    seen: set = set()

    def scan(text: str, source_id: str, native_symbol: bool = False):
        low = (text or "").lower()
        for kw, (cat, ft) in _AA_KEYWORDS.items():
            if kw in low:
                key = (kw, source_id)
                if key in seen:
                    continue
                seen.add(key)
                hits.append((kw, cat, ft, source_id))
                if len(hits) >= settings.obfuscation_max_indicators:
                    return

    for fn in analysis.native_functions:
        scan(fn.name, f"native:{fn.name}", native_symbol=True)
    for f in analysis.findings:
        for e in f.evidence:
            scan(e.detail or "", e.location or f.rule_id)
    for se in analysis.semantic_edges:
        scan(se.evidence or "", se.src_key)
    for c in analysis.code_entities:
        scan(c.class_name or "", c.class_name or "")
    for d in analysis.dependencies:
        scan(d.name or "", d.name)

    categories = {cat for _, cat, _, _ in hits}
    distinct_cats = len(categories)
    obs: list[AAObs] = []
    for kw, cat, ft, sid in hits:
        # An indicator is only an INDICATOR by default. Multiple independent
        # categories → SUPPORTED. A native imported symbol among several → CONFIRMED_STATIC.
        level = L_INDICATOR
        if distinct_cats >= 2:
            level = L_SUPPORTED
        if distinct_cats >= 2 and sid.startswith("native:"):
            level = L_CONFIRMED_STATIC
        obs.append(AAObs(ft, cat, kw, "APK", sid.split(":", 1)[-1] if ":" in sid else None, level,
                         "MEDIUM" if level != L_INDICATOR else "LOW",
                         "ELF" if sid.startswith("native:") else "STATIC_RULE", source_id=sid,
                         evidence_json={"keyword": kw, "distinct_categories": distinct_cats},
                         uncertainties=["presence of a name/API is an indicator only, not active anti-analysis"]))
    stats = {"indicators": len(obs), "distinct_categories": distinct_cats,
             "categories": sorted(categories), "available": True}
    return obs, stats


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------


def _score(observations: list[OObs], anti: list[AAObs], stats: dict) -> dict:
    factors: list[dict] = []

    def add(name, present, reason):
        if present:
            factors.append({"name": name, "weight": OBFUSCATION_WEIGHTS[name], "reason": reason})

    ident = [o for o in observations if o.category == CAT_IDENTIFIER]
    add("identifier_strong", any(o.state == S_STRONG_INDICATOR for o in ident), "strong identifier obfuscation")
    add("identifier_weak", any(o.state == S_WEAK_INDICATOR for o in ident) and
        not any(o.state == S_STRONG_INDICATOR for o in ident), "weak identifier obfuscation")
    add("string_obfuscation", any(o.category == CAT_STRING for o in observations), "encoded strings")
    add("unresolved_reflection", any(o.category == CAT_DYNAMIC_RESOLUTION and "reflection" in o.indicator
                                     and o.state in (S_UNRESOLVED, S_EXTERNALLY_INFLUENCED) for o in observations),
        "unresolved reflection")
    add("unresolved_dynamic_load", any(o.category == CAT_DYNAMIC_RESOLUTION and "dynamic_load" in o.indicator
                                       and o.state in (S_UNRESOLVED, S_EXTERNALLY_INFLUENCED) for o in observations),
        "unresolved dynamic load")
    add("native_stripped", (stats.get("native", {}).get("stripped_libraries", 0) > 0), "stripped native symbols")
    add("native_sparse", (stats.get("native", {}).get("sparse_libraries", 0) > 0), "sparse native exports")
    add("control_flow", any(o.category == CAT_CONTROL_FLOW for o in observations), "dispatcher-like fan-out")
    add("anti_analysis_supported", any(a.evidence_level in (L_SUPPORTED, L_CONFIRMED_STATIC) for a in anti),
        "multiple independent anti-analysis indicators")

    penalties: list[dict] = []

    def pen(name, present, reason):
        if present:
            penalties.append({"name": name, "weight": OBFUSCATION_PENALTIES[name], "reason": reason})

    idstats = stats.get("identifier", {})
    pen("descriptive_identifiers", idstats.get("descriptive_majority", False) and idstats.get("available"),
        "majority of identifiers are descriptive")
    dyn = stats.get("dynamic_resolution", {})
    resolved = dyn.get("reflection_resolved", 0) + dyn.get("dynload_resolved", 0)
    unresolved = dyn.get("reflection_unresolved", 0) + dyn.get("dynload_unresolved", 0)
    pen("resolved_targets", resolved > 0 and resolved >= unresolved, "reflection/dynamic-load mostly resolved")
    natstats = stats.get("native", {})
    pen("symbols_available", natstats.get("available") and natstats.get("stripped_libraries", 0) == 0,
        "native symbols present")

    raw = sum(f["weight"] for f in factors) - sum(p["weight"] for p in penalties)
    score = max(0, min(100, raw))
    band = ("HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW" if score >= 10 else "MINIMAL")
    return {"score": score, "band": band, "factors": factors, "penalties": penalties,
            "note": "obfuscation score describes analysis complexity, NOT security severity or exploitability"}


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_intelligence(analysis) -> dict:
    """Deterministic obfuscation/anti-analysis intelligence (pure — no persistence)."""
    ident_obs, ident_stats = _identifier_observations(analysis)
    string_obs, string_stats = _string_observations(analysis)
    dyn_obs, dyn_impacts, dyn_stats = _dynamic_resolution_observations(analysis)
    cf_obs, cf_stats = _control_flow_observations(analysis)
    nat_obs, nat_impacts, nat_stats = _native_observations(analysis)
    anti_obs, anti_stats = _anti_analysis_indicators(analysis)

    observations = ident_obs + string_obs + dyn_obs + cf_obs + nat_obs
    impacts = list(dyn_impacts) + list(nat_impacts)
    if ident_obs:
        strong = any(o.state == S_STRONG_INDICATOR for o in ident_obs)
        impacts.append(AImpact(I_REDUCED_NAME, "short/generated identifiers reduce semantic naming confidence",
                               None, "HIGH" if strong else "MEDIUM", ident_obs[0].fingerprint))
    if any(a.evidence_level in (L_SUPPORTED, L_CONFIRMED_STATIC) for a in anti_obs):
        impacts.append(AImpact(I_INCREASED_BEHAVIOR, "multiple anti-analysis indicators increase behavioral "
                               "uncertainty for dynamic analysis", None, "MEDIUM"))

    # dedup by fingerprint (deterministic)
    observations = list({o.fingerprint: o for o in observations}.values())
    anti_obs = list({a.fingerprint: a for a in anti_obs}.values())
    impacts = list({i.fingerprint: i for i in impacts}.values())

    stats = {"identifier": ident_stats, "string": string_stats, "dynamic_resolution": dyn_stats,
             "control_flow": cf_stats, "native": nat_stats, "anti_analysis": anti_stats}
    score = _score(observations, anti_obs, stats)

    # sort deterministically
    observations.sort(key=lambda o: (o.category, o.fingerprint))
    anti_obs.sort(key=lambda a: (a.category, a.fingerprint))
    impacts.sort(key=lambda i: (i.impact_category, i.fingerprint))
    return {"observations": observations, "anti_analysis": anti_obs, "impacts": impacts,
            "stats": stats, "score": score}


def _availability(stats: dict) -> dict:
    return {k: ("AVAILABLE" if v.get("available") else "UNAVAILABLE") for k, v in stats.items()}


def obfuscation_view(analysis) -> dict:
    intel = build_intelligence(analysis)
    fp = hashlib.sha256("|".join(sorted(
        [o.fingerprint for o in intel["observations"]] + [a.fingerprint for a in intel["anti_analysis"]]
        + [i.fingerprint for i in intel["impacts"]] + [str(intel["score"]["score"])])).encode()).hexdigest()[:32]
    from collections import Counter
    return {
        "fingerprint": fp,
        "summary": {
            "observations": len(intel["observations"]),
            "anti_analysis_indicators": len(intel["anti_analysis"]),
            "analysis_impacts": len(intel["impacts"]),
            "by_category": dict(Counter(o.category for o in intel["observations"])),
            "by_state": dict(Counter(o.state for o in intel["observations"])),
            "anti_analysis_levels": dict(Counter(a.evidence_level for a in intel["anti_analysis"])),
            "availability": _availability(intel["stats"]),
            "statistics": intel["stats"],
        },
        "score": intel["score"],
        "observations": [_obs_dict(o) for o in intel["observations"]],
        "anti_analysis": [_aa_dict(a) for a in intel["anti_analysis"]],
        "analysis_impacts": [_impact_dict(i) for i in intel["impacts"]],
        "uncertainties": sorted({u for o in intel["observations"] for u in o.uncertainties}
                                | {u for a in intel["anti_analysis"] for u in a.uncertainties}),
        "native_deep_correlation": _native_deep_correlation(analysis),
        "recommended_review": _recommended_review(intel),
        "note": "Obfuscation intelligence describes analysis complexity, not vulnerability or exploitability. "
                "Anti-analysis indicators are not proof of malicious behavior. UNKNOWN / UNKNOWN_NATIVE_TARGET "
                "are preserved.",
    }


def _native_deep_correlation(analysis) -> dict:
    """Uncertainty-reduction note only (prompt 20). When deep-native / Ghidra
    correlation has resolved native targets, that lowers analysis uncertainty —
    but it NEVER changes the obfuscation score, any observation/indicator state,
    or any vulnerability state. Purely informational."""
    if not analysis.native_analysis_runs:
        return {"available": False, "note": "no deep-native run; obfuscation uncertainty unchanged"}
    resolved = sum(1 for j in analysis.native_deep_jni_bindings if j.state == "RESOLVED")
    unresolved = sum(1 for j in analysis.native_deep_jni_bindings if j.state == "UNKNOWN")
    return {"available": True, "resolved_native_targets": resolved,
            "unresolved_native_targets": unresolved,
            "note": ("deep-native correlation reduces native-analysis uncertainty where targets are RESOLVED; "
                     "it does not change obfuscation score or any vulnerability state; UNKNOWN_NATIVE_TARGET "
                     "is preserved")}


def _recommended_review(intel: dict) -> list[dict]:
    out = []
    cats = {i.impact_category for i in intel["impacts"]}
    if I_UNRESOLVED_REFLECTION in cats:
        out.append({"action": "REVIEW_REFLECTION", "reason": "unresolved/externally-influenced reflection targets"})
    if I_UNRESOLVED_DYNAMIC_LOAD in cats:
        out.append({"action": "REVIEW_DYNAMIC_LOADING", "reason": "unresolved dynamic-load targets"})
    if I_REDUCED_NATIVE in cats:
        out.append({"action": "REVIEW_NATIVE_INDIRECTION", "reason": "stripped/indirect native code reduces resolution"})
    return out


def _obs_dict(o: OObs) -> dict:
    return {"id": o.fingerprint, "fingerprint": o.fingerprint, "finding_type": o.finding_type,
            "category": o.category, "indicator": o.indicator, "target_type": o.target_type, "target": o.target,
            "state": o.state, "confidence": o.confidence, "source_type": o.source_type, "source_id": o.source_id,
            "evidence_json": o.evidence_json, "uncertainties": o.uncertainties}


def _aa_dict(a: AAObs) -> dict:
    return {"id": a.fingerprint, "fingerprint": a.fingerprint, "finding_type": a.finding_type,
            "category": a.category, "indicator": a.indicator, "target_type": a.target_type, "target": a.target,
            "evidence_level": a.evidence_level, "confidence": a.confidence, "source_type": a.source_type,
            "source_id": a.source_id, "evidence_json": a.evidence_json, "uncertainties": a.uncertainties}


def _impact_dict(i: AImpact) -> dict:
    return {"id": i.fingerprint, "fingerprint": i.fingerprint, "impact_category": i.impact_category,
            "description": i.description, "affected_target": i.affected_target, "confidence": i.confidence,
            "source_observation": i.source_observation_fp, "evidence_json": i.evidence_json}


# ---------------------------------------------------------------------------
# Persistence (idempotent)
# ---------------------------------------------------------------------------


def build_obfuscation(db, analysis) -> dict:
    """Build + persist obfuscation intelligence. Idempotent. Never mutates
    findings, CVE state, risk, remediation, validation, or the canonical graph."""
    for coll in (analysis.obfuscation_observations, analysis.anti_analysis_indicators, analysis.analysis_impacts):
        coll.clear()
    db.flush()
    intel = build_intelligence(analysis)
    for o in intel["observations"]:
        analysis.obfuscation_observations.append(ObfuscationObservation(
            fingerprint=o.fingerprint, finding_type=o.finding_type, category=o.category, indicator=o.indicator,
            target_type=o.target_type, target=o.target, state=o.state, confidence=o.confidence,
            source_type=o.source_type, source_id=o.source_id, evidence_json=o.evidence_json,
            uncertainties=o.uncertainties))
    for a in intel["anti_analysis"]:
        analysis.anti_analysis_indicators.append(AntiAnalysisIndicator(
            fingerprint=a.fingerprint, finding_type=a.finding_type, category=a.category, indicator=a.indicator,
            target_type=a.target_type, target=a.target, evidence_level=a.evidence_level, confidence=a.confidence,
            source_type=a.source_type, source_id=a.source_id, evidence_json=a.evidence_json,
            uncertainties=a.uncertainties))
    for i in intel["impacts"]:
        analysis.analysis_impacts.append(AnalysisImpact(
            fingerprint=i.fingerprint, impact_category=i.impact_category, description=i.description,
            affected_target=i.affected_target, confidence=i.confidence, source_observation_fp=i.source_observation_fp,
            evidence_json=i.evidence_json))
    db.flush()
    return intel


# ---------------------------------------------------------------------------
# Explanation + diff
# ---------------------------------------------------------------------------


def explain_observation(analysis, obs_dict: dict) -> dict:
    o = obs_dict
    why = [f"Observation {o['category']} ({o['finding_type']}) with indicator: {o['indicator']}.",
           f"State {o['state']} at confidence {o['confidence']}, from {o['source_type']} evidence.",
           f"Target: {o.get('target') or 'APK-wide'}."]
    if o.get("uncertainties"):
        why.append("Uncertainties: " + "; ".join(o["uncertainties"]) + ".")
    why.append("This describes analysis complexity, not a vulnerability or exploitability.")
    return {"WHY_THIS_OBSERVATION": why, "observation": o,
            "note": "Obfuscation/anti-analysis intelligence never implies vulnerability, maliciousness, or "
                    "exploitability, and never changes finding/CVE/risk state."}


def obfuscation_from_diff(comparison) -> dict:
    """A→B obfuscation diff by stable identity (observation/indicator/impact
    fingerprints). Increased obfuscation is never SECURITY_REGRESSION on its own."""
    baseline = comparison.baseline
    candidate = comparison.candidate
    va = obfuscation_view(baseline)
    vb = obfuscation_view(candidate)

    def index(view, key):
        return {x["fingerprint"]: x for x in view[key]}

    changes = []
    for key, kind in (("observations", "obfuscation"), ("anti_analysis", "anti_analysis"),
                      ("analysis_impacts", "impact")):
        a_idx, b_idx = index(va, key), index(vb, key)
        for fp in sorted(set(a_idx) - set(b_idx)):
            changes.append({"kind": kind, "change": "REMOVED", "id": fp,
                            "detail": a_idx[fp].get("indicator") or a_idx[fp].get("impact_category")})
        for fp in sorted(set(b_idx) - set(a_idx)):
            item = b_idx[fp]
            transition = ("NEW_ANTI_ANALYSIS_INDICATOR" if kind == "anti_analysis"
                          else "ANALYSIS_IMPACT_CHANGED" if kind == "impact" else "NEW_OBFUSCATION_OBSERVATION")
            changes.append({"kind": kind, "change": "ADDED", "id": fp, "transition": transition,
                            "detail": item.get("indicator") or item.get("impact_category")})

    delta = vb["score"]["score"] - va["score"]["score"]
    score_transition = ("OBFUSCATION_INCREASED" if delta > 0 else "OBFUSCATION_DECREASED" if delta < 0
                        else "OBFUSCATION_UNCHANGED")
    new_anti = any(c.get("transition") == "NEW_ANTI_ANALYSIS_INDICATOR" for c in changes)
    # increased obfuscation alone is INCONCLUSIVE, never SECURITY_REGRESSION
    security_impact = "INCONCLUSIVE" if (delta > 0 or new_anti) else "NO_MATERIAL_CHANGE"
    from collections import Counter
    return {"baseline_score": va["score"]["score"], "candidate_score": vb["score"]["score"], "score_delta": delta,
            "score_transition": score_transition, "changes": changes,
            "summary": dict(Counter(c["change"] for c in changes)), "security_impact": security_impact,
            "note": "Increased obfuscation is not a security regression on its own; it is INCONCLUSIVE unless "
                    "positive security evidence exists. Nothing is inferred exploitable."}
