import { priorityMeta, severityMeta, stateMeta, type Tone } from '../lib/semantics';

// Accessible status badge. The label text always carries the meaning (never color
// alone, §21/§24). `title` exposes the clarifying note for hover + screen readers.
export function StatusBadge({ value, kind = 'state' }: { value: string | null | undefined; kind?: 'state' | 'severity' | 'priority' }) {
  const meta = kind === 'severity' ? severityMeta(value) : kind === 'priority' ? priorityMeta(value) : stateMeta(value);
  return (
    <span
      className={`badge tone-${meta.tone}`}
      data-tone={meta.tone}
      title={meta.note || meta.label}
      aria-label={meta.note ? `${meta.label}. ${meta.note}` : meta.label}
    >
      {meta.label}
    </span>
  );
}

// A prominent, permanent LIVE/MOCKED marker for runtime evidence (§11/§21).
export function ModeBadge({ mode }: { mode: string | null | undefined }) {
  const isMocked = String(mode).toUpperCase() === 'MOCKED';
  const meta = stateMeta(mode);
  return (
    <span
      className={`badge badge--mode tone-${meta.tone}`}
      data-mode={String(mode).toUpperCase()}
      title={meta.note || meta.label}
      aria-label={meta.note ? `${meta.label}. ${meta.note}` : meta.label}
    >
      {isMocked ? '◇ ' : '● '}
      {meta.label}
    </span>
  );
}

export function Tone({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return <span className={`tone-${tone}`}>{children}</span>;
}
