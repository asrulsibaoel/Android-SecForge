"""Code/native vulnerability-signature correlation (prompt 16).

Matches provider-supplied vulnerability signatures (vulnerable class / package /
method / field / native symbol / JNI) against the EXISTING canonical code graph
and, where possible, reachability. Signatures are never invented — a signature
exists only because a provider supplied it. Confidence reflects evidence
granularity: package-level < class-level < method-level, and a reachable
method-level match is the strongest.

Signature states (per match row):
  NO_SIGNATURE         — the CVE carries no code-level signature
  SIGNATURE_NO_CODE    — signature exists but no matching code node is present
  PACKAGE_PRESENT      — vulnerable package present in code
  CLASS_PRESENT        — vulnerable class present
  METHOD_PRESENT       — vulnerable method present (not proven reachable)
  METHOD_REACHABLE     — vulnerable method present AND reachable
"""

from __future__ import annotations

_STATE_RANK = {"NO_SIGNATURE": -1, "SIGNATURE_NO_CODE": 0, "PACKAGE_PRESENT": 1,
               "CLASS_PRESENT": 2, "METHOD_PRESENT": 3, "METHOD_REACHABLE": 4}


def build_signature_index(analysis) -> dict:
    """Index the canonical graph's code/native nodes once for signature lookup."""
    methods_by_class: dict[str, list] = {}
    classes: set[str] = set()
    packages: set[str] = set()
    native_symbols: dict[str, list] = {}
    for node in analysis.code_nodes:
        if node.node_type == "JAVA_METHOD" and node.class_name:
            simple = node.class_name.rsplit(".", 1)[-1]
            classes.add(node.class_name)
            classes.add(simple)
            packages.add(node.class_name.rsplit(".", 1)[0] if "." in node.class_name else node.class_name)
            methods_by_class.setdefault(node.class_name, []).append(node)
            methods_by_class.setdefault(simple, []).append(node)
    for fn in analysis.native_functions:
        native_symbols.setdefault(fn.name, []).append(fn)
    return {"methods_by_class": methods_by_class, "classes": classes, "packages": packages,
            "native_symbols": native_symbols}


def correlate_row(row, graph, reachable, sig_index: dict) -> dict:
    """Return {state, evidence, matched:[...]} for a match row's signatures."""
    signatures = _load_signatures(row)
    if not signatures:
        return {"state": "NO_SIGNATURE", "evidence": None, "matched": []}
    if graph is None or not sig_index:
        return {"state": "SIGNATURE_NO_CODE", "evidence": "signatures present; no code graph to correlate",
                "matched": []}

    best = "SIGNATURE_NO_CODE"
    matched: list[dict] = []
    for sig in signatures:
        state, detail = _match_one(sig, graph, reachable, sig_index)
        if detail:
            matched.append(detail)
        if _STATE_RANK[state] > _STATE_RANK[best]:
            best = state
    evidence = None
    if matched:
        top = max(matched, key=lambda m: _STATE_RANK.get(m["state"], -1))
        evidence = f"{best}: {top['detail']}"
    else:
        evidence = "provider signature present but not found in decompiled/native code (SIGNATURE_NO_CODE)"
    return {"state": best, "evidence": evidence, "matched": matched}


def _match_one(sig, graph, reachable, idx) -> tuple[str, dict | None]:
    kind = sig.kind
    if kind in ("METHOD", "CLASS", "PACKAGE", "FIELD"):
        cls = sig.class_name
        if kind == "METHOD" and cls and sig.method:
            simple = cls.rsplit(".", 1)[-1]
            nodes = idx["methods_by_class"].get(cls) or idx["methods_by_class"].get(simple) or []
            for n in nodes:
                if n.method_name == sig.method:
                    if reachable is not None and n.node_key in reachable:
                        return "METHOD_REACHABLE", {"state": "METHOD_REACHABLE",
                                                    "detail": f"vulnerable method {simple}.{sig.method} is reachable",
                                                    "node": n.node_key}
                    return "METHOD_PRESENT", {"state": "METHOD_PRESENT",
                                              "detail": f"vulnerable method {simple}.{sig.method} present",
                                              "node": n.node_key}
            # method not found, fall through to class presence
        if cls and (cls in idx["classes"] or cls.rsplit(".", 1)[-1] in idx["classes"]):
            return "CLASS_PRESENT", {"state": "CLASS_PRESENT", "detail": f"vulnerable class {cls} present"}
        if sig.package and any(p == sig.package or p.startswith(sig.package + ".") for p in idx["packages"]):
            return "PACKAGE_PRESENT", {"state": "PACKAGE_PRESENT", "detail": f"vulnerable package {sig.package} present"}
        return "SIGNATURE_NO_CODE", None
    if kind in ("NATIVE_SYMBOL", "JNI") and sig.native_symbol:
        fns = idx["native_symbols"].get(sig.native_symbol)
        if fns:
            return "METHOD_PRESENT", {"state": "METHOD_PRESENT",
                                      "detail": f"vulnerable native symbol {sig.native_symbol} present"}
        return "SIGNATURE_NO_CODE", None
    return "SIGNATURE_NO_CODE", None


def _load_signatures(row):
    """Signatures for the row's vulnerability (only when a real CVE row is linked)."""
    vuln = getattr(row, "vulnerability", None)
    if vuln is not None:
        return list(vuln.signatures)
    return []
