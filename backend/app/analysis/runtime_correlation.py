"""Static ↔ runtime correlation.

Connects persisted runtime observations to the EXISTING static model. Runtime
evidence never overwrites static evidence; it can CONFIRM, SUPPORT, remain
INCONCLUSIVE, or be recorded as runtime-only. Absence of an observation is NOT
proof of absence (NOT_OBSERVED != SAFE). Confidence may increase by a bounded,
documented delta when an independent runtime observation confirms the same
static api; severity is never changed.

Correlation statuses: STATIC_ONLY, RUNTIME_OBSERVED, STATIC_RUNTIME_CONFIRMED,
RUNTIME_SUPPORTS_STATIC_PATH, RUNTIME_CONTRADICTS_HYPOTHESIS, INCONCLUSIVE.
"""

from __future__ import annotations

from app.models.correlation import RootCause  # noqa: F401 (kept for clarity)

_CONFIDENCE_BUMP = 15          # bounded, documented confidence increase on confirmation
_CONFIDENCE_CAP = 95
# Finding categories that runtime instrumentation can plausibly observe.
_OBSERVABLE_CATEGORIES = {"webview", "reflection", "crypto", "native", "reachability", "semantic"}


def _observed_java_apis(observations) -> set[str]:
    apis: set[str] = set()
    for obs in observations:
        if obs.observation_type == "JAVA" and obs.class_name and obs.method_name:
            simple = obs.class_name.rsplit(".", 1)[-1]
            apis.add(f"{simple}.{obs.method_name}")
    return apis


def _observed_native_symbols(observations) -> set[str]:
    return {obs.symbol for obs in observations if obs.observation_type == "NATIVE" and obs.symbol}


def _finding_text(finding) -> str:
    parts = [finding.title or ""]
    parts.extend(e.detail or "" for e in finding.evidence)
    return " ".join(parts)


def correlate_runtime(analysis) -> dict:
    """Correlate runtime observations with static findings. Mutates finding
    runtime_status / validation_state / runtime_evidence_count and adds
    RUNTIME_OBSERVED graph edges where a matching static node exists."""
    observations = [obs for session in analysis.runtime_sessions for obs in session.observations]
    instrumented = any(s.instrumentation_enabled for s in analysis.runtime_sessions)

    java_apis = _observed_java_apis(observations)
    native_symbols = _observed_native_symbols(observations)

    summary = {"observations": len(observations), "confirmed": 0, "supported": 0,
               "runtime_only": 0, "not_observed": 0, "inconclusive": 0}
    matched_apis: set[str] = set()

    for finding in analysis.findings:
        text = _finding_text(finding)
        confirmed_java = [api for api in java_apis if api in text]
        confirmed_native = [sym for sym in native_symbols if finding.category == "native" and sym in text]

        if confirmed_java:
            matched_apis.update(confirmed_java)
            finding.runtime_status = "STATIC_RUNTIME_CONFIRMED"
            finding.validation_state = "OBSERVED"
            finding.runtime_evidence_count = (finding.runtime_evidence_count or 0) + len(confirmed_java)
            if finding.confidence_score:
                finding.confidence_score = min(_CONFIDENCE_CAP, finding.confidence_score + _CONFIDENCE_BUMP)
            summary["confirmed"] += 1
        elif confirmed_native:
            matched_apis.update(confirmed_native)
            finding.runtime_status = "RUNTIME_SUPPORTS_STATIC_PATH"
            finding.validation_state = "OBSERVED"
            finding.runtime_evidence_count = (finding.runtime_evidence_count or 0) + len(confirmed_native)
            summary["supported"] += 1
        elif instrumented and finding.category in _OBSERVABLE_CATEGORIES:
            # Instrumentation ran but did not observe this behavior. NOT_OBSERVED != SAFE.
            finding.runtime_status = "STATIC_ONLY"
            finding.validation_state = "NOT_OBSERVED"
            summary["not_observed"] += 1
        else:
            finding.runtime_status = finding.runtime_status or "STATIC_ONLY"
            if finding.validation_state == "NOT_RUN" and instrumented:
                finding.validation_state = "INCONCLUSIVE"
                summary["inconclusive"] += 1

    # Observations that matched no static finding are runtime-only evidence.
    unmatched = [api for api in (java_apis | native_symbols) if api not in matched_apis]
    summary["runtime_only"] = len(unmatched)

    _add_runtime_edges(analysis, observations)
    return summary


def _add_runtime_edges(analysis, observations) -> None:
    """Add RUNTIME_OBSERVED edges to the EXISTING graph only where a matching
    static code node exists — never on name similarity alone across arbitrary nodes."""
    from app.models.analysis import CodeEdge, CodeNode

    method_index: dict[tuple[str, str], CodeNode] = {}
    for node in analysis.code_nodes:
        if node.node_type == "JAVA_METHOD" and node.class_name and node.method_name:
            simple = node.class_name.rsplit(".", 1)[-1]
            method_index[(simple, node.method_name)] = node

    seen: set[str] = set()
    for obs in observations:
        if obs.observation_type != "JAVA" or not (obs.class_name and obs.method_name):
            continue
        simple = obs.class_name.rsplit(".", 1)[-1]
        node = method_index.get((simple, obs.method_name))
        if node is None:
            continue  # no static node -> do not fabricate an edge
        marker = f"runtime:{simple}.{obs.method_name}"
        if marker in seen:
            continue
        seen.add(marker)
        analysis.code_nodes.append(CodeNode(node_key=marker, node_type="RUNTIME_OBSERVATION",
                                            label=f"{simple}.{obs.method_name} (observed)", confidence="MEDIUM"))
        analysis.code_edges.append(CodeEdge(
            src_key=node.node_key, dst_key=marker, edge_type="RUNTIME_OBSERVED",
            evidence=f"observed at runtime via {obs.source}", confidence="MEDIUM"))
