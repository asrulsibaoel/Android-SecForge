# Remediation testing

`tests/test_remediation.py` (unit) and `tests/test_orchestrator_remediation.py`
(end-to-end over the real pipeline). Fully offline and deterministic.

## Cases (`test_remediation.py`)

1. affected + known fixed → `UPDATE_DEPENDENCY` / `DIRECT_FIX`
2. unknown version + CVE → `VERSION_UNVERIFIED` (no AFFECTED assertion)
3. `POSSIBLY_AFFECTED` + fixed → `CONDITIONALLY_RECOMMENDED` (never confirmed)
4/5. reachable dependency outranks a present-but-not-reachable one
6. exported component + finding → `REVIEW_EXPORTED_COMPONENT`
7. WebView bridge → `REVIEW_WEBVIEW_BRIDGE`
8. JNI boundary → `REVIEW_NATIVE_JNI_BOUNDARY` (`UNKNOWN_NATIVE_TARGET` preserved)
9. Binder transaction → `REVIEW_IPC_BOUNDARY` (`target=UNKNOWN` preserved)
10. runtime OBSERVED → `RUNTIME_CORROBORATED`
11. runtime NOT_OBSERVED → static finding unchanged
12. diff finding disappears → `NO_LONGER_DETECTED` (not remediated)
13. candidate proves `NOT_AFFECTED` with version → `REMEDIATED`
14. two identical analyses → identical plan fingerprint
15. same evidence, different order → identical fingerprints
16. no findings → zero items
17. unrelated source and sink → no recommendation
18. duplicate findings → one deterministic item

Plus persistence + read-only integrity, no "exploitable" language, the
explanation engine, and `UNDETERMINED` priority for a bare unverified match.

## End-to-end (`test_orchestrator_remediation.py`)

Runs the orchestrator on the deterministic test APK, builds a plan, and asserts
every item is evidence-backed, the plan fingerprint is deterministic, source
findings/risk are unmutated, the JSON report `remediation` section is present and
free of "exploitable" language, and the KG remediation projection is opt-in
(default off, so graph snapshots / APK-diff integrity are unaffected).

## Performance

Each source is scanned once; reachability reuses persisted paths; dedup is by
fingerprint dictionary. No N×M scans. The ~18k-node Magisk plan builds in well
under a second (excluding the initial APK analysis).
