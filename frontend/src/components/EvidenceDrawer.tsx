import type { Evidence } from '../api/types';
import { ModeBadge, StatusBadge } from './StatusBadge';

// Reusable global evidence panel (§17). Reused across findings / CVE / remediation
// / validation / runtime / native / investigation / graph. Every available field
// is shown; MISSING fields are shown as UNKNOWN — never filled with placeholders
// that look like real evidence (§5). LIVE/MOCKED is surfaced when present.

function Field({ label, value }: { label: string; value: unknown }) {
  const missing = value === null || value === undefined || value === '';
  return (
    <div className="ev-field">
      <span className="ev-field__label">{label}</span>
      {missing ? (
        <span className="ev-field__value muted" aria-label={`${label} unknown`}>UNKNOWN</span>
      ) : (
        <span className="ev-field__value">{String(value)}</span>
      )}
    </div>
  );
}

export function EvidenceItem({ ev }: { ev: Evidence }) {
  const mode = ev.mode ?? null;
  const uncertainty = Array.isArray(ev.uncertainty) ? ev.uncertainty : ev.uncertainty ? [ev.uncertainty] : [];
  return (
    <li className="ev-item">
      <div className="ev-item__head">
        <Field label="source_type" value={ev.source_type ?? ev.source} />
        {mode && <ModeBadge mode={mode} />}
        {ev.confidence && <StatusBadge value={ev.confidence} />}
      </div>
      <div className="ev-grid">
        <Field label="source_id" value={ev.source_id ?? ev.location} />
        <Field label="artifact" value={ev.artifact} />
        <Field label="file" value={ev.file ?? ev.artifact} />
        <Field label="class" value={ev.class} />
        <Field label="method" value={ev.method} />
        <Field label="line" value={ev.line} />
        <Field label="location" value={ev.location} />
        <Field label="timestamp" value={ev.timestamp} />
        <Field label="evidence_id" value={ev.evidence_id} />
      </div>
      {ev.detail && <p className="ev-detail">{ev.detail}</p>}
      {uncertainty.length > 0 && (
        <ul className="ev-uncertainty" aria-label="uncertainty">
          {uncertainty.map((u, i) => (
            <li key={i} className="tone-unknown">⚠ {u}</li>
          ))}
        </ul>
      )}
    </li>
  );
}

export function EvidenceDrawer({ title, evidence, onClose, children }: {
  title: string;
  evidence?: Evidence[];
  onClose: () => void;
  children?: React.ReactNode;
}) {
  return (
    <div className="drawer" role="dialog" aria-modal="true" aria-label={title}>
      <div className="drawer__backdrop" onClick={onClose} />
      <div className="drawer__panel">
        <div className="drawer__head">
          <h2>{title}</h2>
          <button className="btn" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="drawer__body">
          {children}
          {evidence && (
            <section>
              <h3>Evidence & provenance</h3>
              {evidence.length === 0 ? (
                <div className="state state--empty"><strong>NO EVIDENCE AVAILABLE</strong></div>
              ) : (
                <ul className="ev-list">{evidence.map((ev, i) => <EvidenceItem key={i} ev={ev} />)}</ul>
              )}
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
