# UI security semantics

All security-state rendering flows through `src/lib/semantics.ts`. Every backend
state maps to an **accessible label** plus a visual **tone**. Tone is presentation
only; the label text always carries the meaning (never color alone), and no state
is ever collapsed into SAFE/UNSAFE. There is no “exploitable” state anywhere.

## Distinct axes (§21)

The UI keeps these axes visibly separate and never conflates them:

- **Severity** ≠ **Risk** ≠ **Priority** ≠ **Confidence** ≠ **Validation**
- Validation ≠ exploitability (which does not exist)
- Runtime observation ≠ static evidence

Severity uses its own scale (`severityMeta`), remediation priority its own
(`priorityMeta`, where HIGH priority ≠ confirmed vulnerability), and confidence is
shown separately from all of them. The `AxisLegend` component spells this out in
every workspace.

## States that must never collapse

| State | Rendered as | Never |
|-------|-------------|-------|
| `UNKNOWN` | UNKNOWN | SAFE, NOT_FOUND |
| `NOT_OBSERVED` | NOT OBSERVED (with “does not mean SAFE”) | SAFE |
| `NOT_REACHABLE` | NOT REACHABLE (with “does not mean SAFE”) | SAFE |
| `POSSIBLY_AFFECTED` | POSSIBLY AFFECTED | AFFECTED |
| `PRESENT_UNKNOWN_VERSION` | PRESENT · UNKNOWN VERSION | AFFECTED / NOT_AFFECTED |
| `NO_LONGER_DETECTED` | NO LONGER DETECTED | FIXED / REMEDIATED |
| `NO_LONGER_OBSERVED` | NO LONGER OBSERVED | FIXED |
| `MOCKED` | **MOCKED — NOT LIVE EVIDENCE** | LIVE |
| `NATIVE_API_PRESENT` | NATIVE API PRESENT | REACHED / reachable |
| `UNKNOWN_NATIVE_TARGET` | UNKNOWN NATIVE TARGET | resolved target |
| anti-analysis `INDICATOR` | INDICATOR (with “does not prove behavior”) | confirmed behavior |

## LIVE vs MOCKED

`ModeBadge` renders MOCKED with a filled-diamond marker and the permanent text
**“MOCKED — NOT LIVE EVIDENCE”** and a distinct `mocked` tone; LIVE uses a filled
circle and a distinct `live` tone. MOCKED evidence never counts as, or visually
resembles, LIVE. `UNAVAILABLE` runtime renders as an explicit “LIVE RUNTIME
UNAVAILABLE” panel — never as zero activity.

## Missing evidence

`EvidenceItem` renders any absent field as **UNKNOWN**, never a placeholder that
looks like real evidence. A finding/CVE with no evidence shows “NO EVIDENCE
AVAILABLE”, distinct from a zero/clean verdict.

## Assessment decision states (prompt 25)

The Assessment tab renders the prompt-24 decision states — `CONFIRMED`,
`STRONGLY_SUPPORTED`, `SUPPORTED`, `CONDITIONALLY_SUPPORTED`, `REQUIRES_REVIEW`,
`UNVERIFIED`, `BLOCKED`, `INCONCLUSIVE`, `NOT_APPLICABLE`, `SUPERSEDED`, plus the
assessment-level `ASSESSMENT_CONCLUSIVE` / `ASSESSMENT_INCONCLUSIVE`. These are
**evidentiary-strength** labels, never a SAFE/UNSAFE verdict and never
exploitability: `ASSESSMENT_INCONCLUSIVE` is not UNSAFE, `SUPPORTED` is not
EXPLOITABLE, and each conclusion exposes its `rule_id`, rationale, and evidence
references (to existing records). `BLOCKED` shows the missing requirement.

## Capability vs zero (prompt 25 §19)

`MetricCard` and `CapabilityBadge` render an unavailable capability as
`UNAVAILABLE` — never "0". Native `ELF_ONLY` / `FRIDA_SERVER_UNAVAILABLE` /
`NATIVE_ANALYSIS_UNAVAILABLE` are shown as capability states, not zero activity;
`NATIVE_API_PRESENT` never reads as reachability and `JNI_PRESENT` never reads as
invocation.

## Regression guarantees (tested)

`src/test/semantics.test.ts` + `src/test/components.test.tsx` assert: MOCKED never
renders as LIVE; UNKNOWN never renders as SAFE; POSSIBLY_AFFECTED never as
AFFECTED; NO_LONGER_DETECTED never as FIXED; NATIVE_API_PRESENT ≠
NATIVE_CALL_CHAIN_REACHES_API; unknown tokens are shown verbatim; and researcher
input never targets analytical-truth routes.
