// Renders a backend "explain" / evidence-chain payload (§5/§12). It never
// invents structure — it renders exactly what the API returned. Every step keeps
// its provenance/mode; UNKNOWN values stay UNKNOWN.
import { ModeBadge } from './StatusBadge';

function humanize(key: string): string {
  return key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function Step({ step }: { step: any }) {
  if (typeof step === 'string') return <li className="chain-step">{step}</li>;
  const label = step.step || step.kind || step.type;
  return (
    <li className="chain-step">
      {label && <span className="chain-step__label">{humanize(String(label))}</span>}
      <span className="chain-step__detail">{step.detail ?? step.description ?? step.text ?? JSON.stringify(step)}</span>
      <span className="chain-step__meta">
        {step.mode && <ModeBadge mode={step.mode} />}
        {step.provenance && <span className="pill">{String(step.provenance)}</span>}
        {step.source_type && <span className="pill">{String(step.source_type)}</span>}
        {step.confidence && <span className="pill">conf {String(step.confidence)}</span>}
      </span>
    </li>
  );
}

export function ExplanationView({ payload }: { payload: any }) {
  if (!payload) return <div className="state state--empty"><strong>NO EXPLANATION AVAILABLE</strong></div>;

  // A single ordered chain is the primary shape.
  const chainKey = ['chain', 'EVIDENCE_CHAIN', 'evidence_chain', 'explanation', 'steps'].find(
    (k) => Array.isArray(payload[k]),
  );

  return (
    <div className="explanation">
      {chainKey && (
        <section>
          <h4>{humanize(chainKey)}</h4>
          <ol className="chain">{payload[chainKey].map((s: any, i: number) => <Step key={i} step={s} />)}</ol>
        </section>
      )}
      {Object.entries(payload).map(([key, value]) => {
        if (key === chainKey) return null;
        if (Array.isArray(value)) {
          if (value.length === 0) return null;
          if (typeof value[0] === 'string') {
            return (
              <section key={key}>
                <h4>{humanize(key)}</h4>
                <ul className={key.toLowerCase().includes('uncertain') ? 'tone-unknown' : ''}>
                  {value.map((v, i) => <li key={i}>{v}</li>)}
                </ul>
              </section>
            );
          }
          return null;
        }
        if (typeof value === 'string' && (key === 'note' || key === 'summary' || key === 'subject' || key === 'mode')) {
          return (
            <p key={key} className="muted explanation-note">
              <strong>{humanize(key)}:</strong> {value}
            </p>
          );
        }
        return null;
      })}
    </div>
  );
}
