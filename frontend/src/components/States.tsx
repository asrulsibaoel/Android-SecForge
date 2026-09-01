import type { ReactNode } from 'react';
import type { ApiResult } from '../api/client';

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="state state--loading" role="status" aria-live="polite">
      <span className="skeleton" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ title = 'NO DATA', hint }: { title?: string; hint?: string }) {
  // An empty result is distinct from "0" and from UNKNOWN — it means the backend
  // returned no rows for this view, not that a fact is zero or safe.
  return (
    <div className="state state--empty" role="status">
      <strong>{title}</strong>
      {hint && <p className="muted">{hint}</p>}
    </div>
  );
}

export function ErrorState({ message, code }: { message?: string | null; code?: number | null }) {
  return (
    <div className="state state--error" role="alert">
      <strong>REQUEST FAILED{code ? ` · ${code}` : ''}</strong>
      {message && <p className="muted">{message}</p>}
    </div>
  );
}

export function Unavailable({ label = 'UNAVAILABLE', detail }: { label?: string; detail?: string }) {
  // UNAVAILABLE must never look like zero activity or a clean result.
  return (
    <div className="state state--unavailable" role="status">
      <strong>{label}</strong>
      {detail && <p className="muted">{detail}</p>}
    </div>
  );
}

// Renders children only on real success; otherwise shows the correct honest state.
export function ResultGate<T>({
  result,
  children,
  emptyTitle,
  emptyHint,
  loadingLabel,
}: {
  result: ApiResult<T>;
  children: (data: T) => ReactNode;
  emptyTitle?: string;
  emptyHint?: string;
  loadingLabel?: string;
}) {
  switch (result.status) {
    case 'loading':
      return <Loading label={loadingLabel} />;
    case 'not_found':
      return <EmptyState title="NOT FOUND" hint="The requested resource does not exist." />;
    case 'bad_request':
      return <ErrorState code={400} message={result.error} />;
    case 'server_error':
      return <ErrorState code={result.httpStatus} message={result.error} />;
    case 'network_error':
      return <ErrorState message={result.error ?? 'Network error — is the backend running?'} />;
    case 'unavailable':
      return <Unavailable detail={result.error ?? undefined} />;
    case 'empty':
      return <EmptyState title={emptyTitle} hint={emptyHint} />;
    case 'success':
      return <>{result.data !== null && children(result.data)}</>;
    default:
      return null;
  }
}
