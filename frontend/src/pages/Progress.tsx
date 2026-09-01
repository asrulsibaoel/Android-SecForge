import { useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { cancelExecution, getAnalysisProgress, getExecution } from '../api';
import { SectionHeader } from '../components/primitives';
import { StatusBadge } from '../components/StatusBadge';
import { CapabilityBadge } from '../components/CapabilityBadge';
import { ErrorState, Loading } from '../components/States';

const TERMINAL = new Set(['COMPLETED', 'COMPLETED_WITH_LIMITATIONS', 'FAILED', 'CANCELLED']);
const POLL_MS = 1500;

// The full ordered pipeline stage list (from the backend orchestrator). We render
// this as a checklist and fill each row from the real reported stage status —
// stages not yet reported are PENDING (never fabricated as complete).
const PIPELINE_STAGES = [
  'ingest', 'manifest', 'permissions', 'components', 'dex', 'jadx', 'code_index', 'rules',
  'native', 'jni', 'ghidra', 'native_rules', 'graph', 'reachability', 'semantics',
  'dependency_fingerprint', 'vulnerability_match', 'vulnerability_reachability',
  'correlation', 'attack_surface', 'risk', 'graph_snapshot', 'validation', 'obfuscation', 'native_deep',
];

function StageRow({ name, status, current }: { name: string; status?: string; current: boolean }) {
  const icon = status === 'COMPLETE' ? '✓' : status === 'FAILED' ? '✕'
    : status === 'SKIPPED' || status === 'UNAVAILABLE' ? '⊘'
    : status === 'PARTIAL' || status === 'DEGRADED' ? '◑'
    : current ? '◉' : '○';
  return (
    <li className={`stage-row ${current ? 'stage-row--current' : ''}`}>
      <span className="stage-row__icon" aria-hidden="true">{icon}</span>
      <span className="stage-row__name">{name}</span>
      {status ? <StatusBadge value={status === 'COMPLETE' ? 'COMPLETE' : status} /> : <span className="muted">{current ? 'RUNNING' : 'PENDING'}</span>}
    </li>
  );
}

function ProgressBody({ e }: { e: any }) {
  const state = String(e.state);
  const stagesByName: Record<string, string> = {};
  for (const s of e.stages || []) stagesByName[s.name] = s.status;
  const limitations = e.capability_limitations || [];
  const pkg = e.artifact?.package || e.artifact?.filename;
  const terminal = TERMINAL.has(state);

  return (
    <div>
      <SectionHeader
        title="Analysis progress"
        subtitle={pkg ? `Artifact: ${pkg}` : undefined}
        actions={<StatusBadge value={state} />}
      />

      {state === 'FAILED' && e.error && (
        <div className="panel">
          <h3 className="tone-concern">Analysis failed</h3>
          <dl className="kv">
            <dt>code</dt><dd>{e.error.code}</dd>
            <dt>stage</dt><dd>{e.error.stage || 'UNKNOWN'}</dd>
            <dt>message</dt><dd>{e.error.message}</dd>
            <dt>retryable</dt><dd>{e.error.retryable ? 'yes' : 'no'}</dd>
          </dl>
          <p className="muted">A failed analysis is not "no findings" — it did not complete.</p>
        </div>
      )}

      {state === 'COMPLETED_WITH_LIMITATIONS' && (
        <div className="notice tone-attention" style={{ marginBottom: '1rem' }}>
          Completed with limitations — some capabilities were unavailable. Absence of a capability is not a successful
          stage.
        </div>
      )}

      <div className="panel">
        <h3>Pipeline stages</h3>
        <ul className="stage-list">
          {PIPELINE_STAGES.map((name) => (
            <StageRow key={name} name={name} status={stagesByName[name]} current={!terminal && e.current_stage === name} />
          ))}
        </ul>
      </div>

      {limitations.length > 0 && (
        <div className="panel">
          <h3>Capability limitations</h3>
          {limitations.map((l: any) => <CapabilityBadge key={l.capability} name={l.capability} availability={l.state} />)}
          <p className="muted" style={{ fontSize: '.8rem' }}>
            e.g. Ghidra unavailable → native call-chain reachability unavailable; runtime device unavailable → no LIVE
            runtime. These remain visible, never converted into success.
          </p>
        </div>
      )}

      {(state === 'COMPLETED' || state === 'COMPLETED_WITH_LIMITATIONS') && e.analysis_id && (
        <div className="panel">
          <Link className="btn btn--primary" to={`/analysis/${e.analysis_id}`}>Open Analysis Workspace →</Link>
        </div>
      )}
    </div>
  );
}

export function Progress() {
  const { executionId, analysisId } = useParams();
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cancelMsg, setCancelMsg] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let alive = true;
    async function poll() {
      const r = executionId ? await getExecution(executionId) : await getAnalysisProgress(analysisId!);
      if (!alive) return;
      if (r.status === 'success' || r.status === 'empty') {
        setResult(r.data);
        const state = r.data?.state;
        if (!TERMINAL.has(String(state))) {
          timer.current = setTimeout(poll, POLL_MS); // bounded: stops on terminal state
        }
      } else if (r.status === 'not_found') {
        setError('Execution not found (executions are in-process and ephemeral).');
      } else {
        setError(r.error || r.status);
      }
    }
    poll();
    return () => { alive = false; if (timer.current) clearTimeout(timer.current); };
  }, [executionId, analysisId]);

  async function onCancel() {
    if (!executionId) return;
    const r = await cancelExecution(executionId);
    setCancelMsg(r.data?.reason || r.data?.status || 'cancellation requested');
  }

  if (error) return <ErrorState message={error} />;
  if (!result) return <Loading label="Loading progress…" />;
  return (
    <div>
      <ProgressBody e={result} />
      {!TERMINAL.has(String(result.state)) && executionId && (
        <div className="panel">
          <button className="btn" onClick={onCancel}>Request cancel</button>
          {cancelMsg && <p className="muted" style={{ marginTop: '.5rem' }}>{cancelMsg}</p>}
        </div>
      )}
    </div>
  );
}
