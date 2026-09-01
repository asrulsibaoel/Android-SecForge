import { AXES } from '../lib/semantics';

// Makes the "different axes are different" rule explicit and visible (§3/§21).
export function AxisLegend() {
  return (
    <details className="axis-legend">
      <summary>Axes are distinct — Severity ≠ Risk ≠ Priority ≠ Confidence ≠ Validation</summary>
      <dl>
        {AXES.map(([name, note]) => (
          <div key={name} className="axis-legend__row">
            <dt>{name}</dt>
            <dd className="muted">{note}</dd>
          </div>
        ))}
        <div className="axis-legend__row">
          <dt>Not verdicts</dt>
          <dd className="muted">
            UNKNOWN ≠ NOT_FOUND · NOT_OBSERVED ≠ SAFE · NOT_REACHABLE ≠ SAFE · POSSIBLY_AFFECTED ≠ AFFECTED ·
            NO_LONGER_DETECTED ≠ FIXED · MOCKED ≠ LIVE · Indicator ≠ confirmed behavior. There is no “exploitable”.
          </dd>
        </div>
      </dl>
    </details>
  );
}
