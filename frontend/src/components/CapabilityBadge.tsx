import { stateMeta } from '../lib/semantics';

// Capability status chip for AVAILABLE / PARTIAL / UNAVAILABLE / NOT_CONNECTED /
// UNKNOWN / READY / FAILED (§1/§11/§22). Availability is shown verbatim and is
// never collapsed into a pass/fail; UNAVAILABLE is visibly not "clean".
export function CapabilityBadge({ name, availability, reason }: { name: string; availability: string; reason?: string }) {
  const meta = stateMeta(availability);
  return (
    <div className="capability" title={reason || meta.note || ''}>
      <span className="capability__name">{name}</span>
      <span className={`badge tone-${meta.tone}`} aria-label={`${name}: ${meta.label}`}>{meta.label}</span>
    </div>
  );
}
