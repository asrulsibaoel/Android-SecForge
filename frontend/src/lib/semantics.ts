// Security semantics for the UI (prompt 22 §21).
//
// Every backend semantic state is rendered with an accessible LABEL and a visual
// TONE. Tone is presentation only — it NEVER collapses a state into SAFE/UNSAFE,
// and the label text always carries the real meaning (never color alone). MOCKED
// is permanently distinct from LIVE; UNKNOWN is distinct from NOT_FOUND;
// NOT_OBSERVED / NOT_REACHABLE are never "safe"; POSSIBLY_AFFECTED is never
// AFFECTED; NO_LONGER_DETECTED is never FIXED. There is no "exploitable" state.

export type Tone =
  | 'neutral'
  | 'info'
  | 'attention'
  | 'concern'
  | 'affirmed'
  | 'unknown'
  | 'live'
  | 'mocked';

export interface StateMeta {
  label: string;
  tone: Tone;
  /** Longer clarification shown on hover / for screen readers. */
  note?: string;
}

// Canonical state → presentation. Unlisted states fall back to a neutral badge
// that still shows the raw token verbatim (never invented, never collapsed).
const STATES: Record<string, StateMeta> = {
  // --- generic uncertainty (never "safe", never "vulnerable") ---
  UNKNOWN: { label: 'UNKNOWN', tone: 'unknown', note: 'Not determined — not the same as NOT_FOUND or SAFE.' },
  INCONCLUSIVE: { label: 'INCONCLUSIVE', tone: 'unknown', note: 'Evidence is insufficient to conclude.' },
  UNAVAILABLE: { label: 'UNAVAILABLE', tone: 'unknown', note: 'Capability unavailable — not zero activity.' },
  NOT_FOUND: { label: 'NOT FOUND', tone: 'neutral' },
  PARTIAL: { label: 'PARTIAL', tone: 'attention' },

  // --- CVE / version states ---
  AFFECTED: { label: 'AFFECTED', tone: 'concern' },
  NOT_AFFECTED: { label: 'NOT AFFECTED', tone: 'affirmed' },
  POSSIBLY_AFFECTED: {
    label: 'POSSIBLY AFFECTED',
    tone: 'attention',
    note: 'Version unverified — this is NOT the same as AFFECTED.',
  },
  PRESENT_UNKNOWN_VERSION: {
    label: 'PRESENT · UNKNOWN VERSION',
    tone: 'unknown',
    note: 'Dependency present but installed version is unknown; affected state cannot be asserted.',
  },
  PRESENT_AFFECTED: { label: 'PRESENT · AFFECTED', tone: 'concern' },
  PRESENT_NOT_AFFECTED: { label: 'PRESENT · NOT AFFECTED', tone: 'affirmed' },
  AFFECTED_REACHABLE: { label: 'AFFECTED · REACHABLE', tone: 'concern' },
  AFFECTED_NOT_REACHABLE: { label: 'AFFECTED · NOT REACHABLE', tone: 'attention' },
  NOT_PRESENT: { label: 'NOT PRESENT', tone: 'neutral' },

  // --- reachability ---
  REACHABLE: { label: 'REACHABLE', tone: 'concern' },
  NOT_REACHABLE: {
    label: 'NOT REACHABLE',
    tone: 'attention',
    note: 'No path proven — NOT_REACHABLE does not mean SAFE.',
  },

  // --- assessment decision states (evidentiary strength; never SAFE/UNSAFE) ---
  CONFIRMED: { label: 'CONFIRMED', tone: 'attention', note: 'Evidentiarily confirmed — not an exploitability verdict.' },
  STRONGLY_SUPPORTED: { label: 'STRONGLY SUPPORTED', tone: 'attention', note: 'Multiple independent evidence families.' },
  CONDITIONALLY_SUPPORTED: { label: 'CONDITIONALLY SUPPORTED', tone: 'attention', note: 'Supported subject to a stated condition.' },
  REQUIRES_REVIEW: { label: 'REQUIRES REVIEW', tone: 'unknown', note: 'A human still needs to review this.' },
  BLOCKED: { label: 'BLOCKED', tone: 'attention', note: 'A required capability/evidence is missing.' },
  ASSESSMENT_CONCLUSIVE: { label: 'CONCLUSIVE', tone: 'affirmed', note: 'Every conclusion is evidentiarily settled.' },
  ASSESSMENT_INCONCLUSIVE: { label: 'INCONCLUSIVE', tone: 'unknown', note: 'Open items remain — not a safety verdict.' },
  SECURITY_REVIEW_REQUIRED: { label: 'REVIEW REQUIRED', tone: 'attention' },
  SECURITY_RELEVANT_EVIDENCE_PRESENT: { label: 'SECURITY-RELEVANT EVIDENCE', tone: 'attention' },

  // --- native (extra) ---
  JNI_PRESENT: { label: 'JNI PRESENT', tone: 'info', note: 'A JNI binding exists — presence is not invocation.' },
  NATIVE_ANALYSIS_UNAVAILABLE: { label: 'NATIVE ANALYSIS UNAVAILABLE', tone: 'unknown', note: 'Native call-chain analysis unavailable (Ghidra not run).' },

  // --- frida / device capability (prompt 23/24) ---
  FRIDA_HOST_AVAILABLE: { label: 'FRIDA HOST AVAILABLE', tone: 'affirmed' },
  FRIDA_UNAVAILABLE: { label: 'FRIDA UNAVAILABLE', tone: 'unknown' },
  FRIDA_SERVER_AVAILABLE: { label: 'FRIDA-SERVER AVAILABLE', tone: 'affirmed' },
  FRIDA_SERVER_UNAVAILABLE: { label: 'FRIDA-SERVER UNAVAILABLE', tone: 'unknown', note: 'frida-server is not on the device; native runtime instrumentation is unavailable.' },
  FRIDA_READY: { label: 'FRIDA READY', tone: 'affirmed' },
  UNAUTHORIZED: { label: 'UNAUTHORIZED', tone: 'attention', note: 'Accept the USB debugging prompt on the device.' },
  OFFLINE: { label: 'OFFLINE', tone: 'unknown' },
  ADB_UNAVAILABLE: { label: 'ADB UNAVAILABLE', tone: 'unknown' },

  // --- security validation ---
  UNVERIFIED: { label: 'UNVERIFIED', tone: 'unknown' },
  STATIC_SUPPORTED: { label: 'STATIC SUPPORTED', tone: 'info' },
  RUNTIME_CORROBORATED: { label: 'RUNTIME CORROBORATED', tone: 'affirmed', note: 'Corroborated by LIVE runtime evidence.' },
  MULTI_SOURCE_CORROBORATED: { label: 'MULTI-SOURCE CORROBORATED', tone: 'affirmed' },
  VALIDATION_BLOCKED: { label: 'VALIDATION BLOCKED', tone: 'attention', note: 'Evidence present but a requirement is unmet.' },
  NOT_APPLICABLE: { label: 'NOT APPLICABLE', tone: 'neutral' },
  SUPERSEDED: { label: 'SUPERSEDED', tone: 'neutral' },

  // --- runtime validation (finding axis) ---
  CONFIRMED_RUNTIME_BEHAVIOR: { label: 'CONFIRMED RUNTIME BEHAVIOR', tone: 'affirmed', note: 'Observed LIVE.' },
  NOT_OBSERVED: {
    label: 'NOT OBSERVED',
    tone: 'attention',
    note: 'Not seen at runtime — NOT_OBSERVED does not mean SAFE.',
  },
  RUNTIME_INCONCLUSIVE: { label: 'RUNTIME INCONCLUSIVE', tone: 'unknown' },
  LIVE_UNAVAILABLE: { label: 'LIVE UNAVAILABLE', tone: 'unknown', note: 'No live device — behavior not validated at runtime.' },

  // --- runtime mode (never conflate) ---
  LIVE: { label: 'LIVE', tone: 'live', note: 'Observed on a real connected device.' },
  MOCKED: { label: 'MOCKED — NOT LIVE EVIDENCE', tone: 'mocked', note: 'Offline test evidence. Never counts as LIVE.' },

  // --- diff transitions ---
  ADDED: { label: 'ADDED', tone: 'attention' },
  REMOVED: { label: 'REMOVED', tone: 'info' },
  CHANGED: { label: 'CHANGED', tone: 'attention' },
  UNCHANGED: { label: 'UNCHANGED', tone: 'neutral' },
  NO_LONGER_DETECTED: {
    label: 'NO LONGER DETECTED',
    tone: 'info',
    note: 'Absent in candidate — NOT the same as FIXED / REMEDIATED.',
  },
  NO_LONGER_OBSERVED: { label: 'NO LONGER OBSERVED', tone: 'info', note: 'Runtime behavior not seen — not FIXED.' },
  REMEDIATED: { label: 'REMEDIATED', tone: 'affirmed', note: 'Positive fix evidence (diff/state/version), not runtime alone.' },

  // --- security impact ---
  SECURITY_REGRESSION: { label: 'SECURITY REGRESSION', tone: 'concern' },
  SECURITY_IMPROVEMENT: { label: 'SECURITY IMPROVEMENT', tone: 'affirmed' },
  MIXED: { label: 'MIXED', tone: 'attention' },
  NO_MATERIAL_SECURITY_CHANGE: { label: 'NO MATERIAL SECURITY CHANGE', tone: 'neutral' },

  // --- native ---
  NATIVE_API_PRESENT: { label: 'NATIVE API PRESENT', tone: 'info', note: 'Present — presence is not reachability.' },
  NATIVE_CALL_CHAIN_REACHES_API: { label: 'CALL CHAIN REACHES API', tone: 'attention', note: 'Ghidra call chain reaches the API.' },
  REACHED: { label: 'REACHED', tone: 'attention' },
  UNKNOWN_NATIVE_TARGET: { label: 'UNKNOWN NATIVE TARGET', tone: 'unknown', note: 'Native target unresolved; never inferred.' },
  ELF_ONLY: { label: 'ELF-ONLY', tone: 'unknown', note: 'No Ghidra — native call-chain reachability is unavailable.' },
  GHIDRA_AVAILABLE: { label: 'GHIDRA', tone: 'info' },
  FIXTURE: { label: 'FIXTURE', tone: 'mocked', note: 'Clearly-marked offline Ghidra fixture data.' },

  // --- obfuscation anti-analysis evidence levels ---
  INDICATOR: { label: 'INDICATOR', tone: 'unknown', note: 'An indicator does not prove active anti-analysis behavior.' },
  SUPPORTED: { label: 'SUPPORTED', tone: 'attention' },
  CONFIRMED_STATIC: { label: 'CONFIRMED (STATIC)', tone: 'attention', note: 'Statically corroborated; not a behavior claim.' },

  // --- capabilities ---
  AVAILABLE: { label: 'AVAILABLE', tone: 'affirmed' },
  READY: { label: 'READY', tone: 'affirmed' },
  CONNECTED: { label: 'CONNECTED', tone: 'affirmed' },
  NOT_CONNECTED: { label: 'NOT CONNECTED', tone: 'unknown', note: 'No device attached.' },
  FAILED: { label: 'FAILED', tone: 'concern' },
  DEGRADED: { label: 'DEGRADED', tone: 'attention' },
  COMPLETE: { label: 'COMPLETE', tone: 'affirmed' },
  SKIPPED: { label: 'SKIPPED', tone: 'neutral' },
};

// Severity is its OWN axis — never a safety verdict, never conflated with risk,
// priority, confidence, or validation.
const SEVERITY: Record<string, StateMeta> = {
  critical: { label: 'CRITICAL', tone: 'concern' },
  high: { label: 'HIGH', tone: 'concern' },
  medium: { label: 'MEDIUM', tone: 'attention' },
  low: { label: 'LOW', tone: 'info' },
  info: { label: 'INFO', tone: 'neutral' },
};

// Remediation PRIORITY is a separate axis from severity/risk. HIGH priority does
// NOT mean a confirmed vulnerability.
const PRIORITY: Record<string, StateMeta> = {
  CRITICAL: { label: 'CRITICAL', tone: 'concern' },
  HIGH: { label: 'HIGH', tone: 'attention' },
  MEDIUM: { label: 'MEDIUM', tone: 'info' },
  LOW: { label: 'LOW', tone: 'neutral' },
  INFO: { label: 'INFO', tone: 'neutral' },
  UNDETERMINED: { label: 'UNDETERMINED', tone: 'unknown' },
};

export function stateMeta(raw: string | null | undefined): StateMeta {
  if (raw === null || raw === undefined || raw === '') {
    return { label: 'UNKNOWN', tone: 'unknown', note: 'No value reported.' };
  }
  const key = String(raw).toUpperCase();
  return STATES[key] ?? STATES[String(raw)] ?? { label: String(raw), tone: 'neutral' };
}

export function severityMeta(raw: string | null | undefined): StateMeta {
  if (!raw) return { label: 'UNKNOWN', tone: 'unknown' };
  return SEVERITY[String(raw).toLowerCase()] ?? { label: String(raw).toUpperCase(), tone: 'neutral' };
}

export function priorityMeta(raw: string | null | undefined): StateMeta {
  if (!raw) return { label: 'UNDETERMINED', tone: 'unknown' };
  return PRIORITY[String(raw).toUpperCase()] ?? { label: String(raw).toUpperCase(), tone: 'neutral' };
}

// The set of axes the UI must keep visually distinct (§21).
export const AXES = [
  ['Severity', 'How bad the issue would be — not a safety verdict.'],
  ['Risk', 'Configured scoring model — separate from severity.'],
  ['Priority', 'Remediation order — HIGH priority ≠ confirmed vulnerability.'],
  ['Confidence', 'Certainty of the finding — separate from severity.'],
  ['Validation', 'What is verified — separate from exploitability (which does not exist here).'],
] as const;
