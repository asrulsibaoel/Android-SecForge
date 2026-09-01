import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { stateMeta } from '../lib/semantics';

// Reusable visual primitives (prompt 25 §23). Presentation only — no analytical
// logic. State rendering always pairs text with tone (never color alone).

export function SectionHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="pagehead">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="muted" style={{ margin: '.2rem 0 0' }}>{subtitle}</p>}
      </div>
      {actions && <div className="tag-row">{actions}</div>}
    </div>
  );
}

// A dashboard/overview card. Distinguishes a real count from an UNAVAILABLE
// capability — never renders "0" when the capability itself is unavailable.
export function MetricCard({
  label, value, capability, to, hint, unavailable,
}: {
  label: string;
  value?: ReactNode;
  capability?: string;
  to?: string;
  hint?: string;
  unavailable?: boolean;
}) {
  const meta = capability ? stateMeta(capability) : null;
  const body = (
    <div className={`metric-card ${unavailable ? 'metric-card--unavailable' : ''}`}>
      <div className="metric-card__label">{label}</div>
      {unavailable ? (
        <div className="metric-card__value tone-unknown" style={{ fontSize: '1rem' }}>UNAVAILABLE</div>
      ) : (
        <div className="metric-card__value">{value ?? <span className="muted">—</span>}</div>
      )}
      {meta && <span className={`badge tone-${meta.tone}`} aria-label={`capability ${meta.label}`}>{meta.label}</span>}
      {hint && <div className="muted metric-card__hint">{hint}</div>}
    </div>
  );
  return to ? <Link to={to} className="metric-card__link">{body}</Link> : body;
}

export function TruncatedBanner({ detail }: { detail?: string }) {
  return (
    <div className="notice tone-attention" role="status" style={{ fontWeight: 700, marginBottom: '.8rem' }}>
      TRUNCATED{detail ? ` — ${detail}` : ''}
    </div>
  );
}

export function ProvenanceBadge({ provenance, mode }: { provenance?: string | null; mode?: string | null }) {
  return (
    <span className="tag-row" style={{ display: 'inline-flex', gap: '.3rem' }}>
      {provenance && <span className="pill">{provenance}</span>}
      {mode && <span className={`pill ${String(mode).toUpperCase() === 'MOCKED' ? 'tone-mocked' : String(mode).toUpperCase() === 'LIVE' ? 'tone-live' : ''}`}>{String(mode).toUpperCase()}</span>}
    </span>
  );
}

// Confidence is its OWN axis (never severity/risk). Rendered as text + dots.
export function ConfidenceIndicator({ confidence }: { confidence?: string | number | null }) {
  const level = String(confidence ?? '').toUpperCase();
  const filled = level === 'HIGH' || Number(confidence) >= 70 ? 3 : level === 'MEDIUM' || Number(confidence) >= 40 ? 2 : level === 'LOW' || Number(confidence) > 0 ? 1 : 0;
  return (
    <span className="confidence" title={`confidence: ${confidence ?? 'UNKNOWN'}`} aria-label={`confidence ${confidence ?? 'unknown'}`}>
      <span aria-hidden="true">{'●'.repeat(filled)}{'○'.repeat(3 - filled)}</span>
      <span className="muted" style={{ marginLeft: '.3rem', fontSize: '.72rem' }}>{confidence ?? 'UNKNOWN'}</span>
    </span>
  );
}

export function DetailPanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel">
      <h3>{title}</h3>
      {children}
    </section>
  );
}
