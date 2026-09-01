import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { buildAssessment, explainConclusion, getAssessment } from '../api';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { DataTable, type Column } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { EvidenceDrawer } from '../components/EvidenceDrawer';
import { ExplanationView } from '../components/ExplanationView';
import { SectionHeader, MetricCard, TruncatedBanner, ProvenanceBadge } from '../components/primitives';

const OPEN = new Set(['REQUIRES_REVIEW', 'UNVERIFIED', 'BLOCKED', 'INCONCLUSIVE', 'CONDITIONALLY_SUPPORTED']);

function ConclusionDrawer({ analysisId, conc, onClose }: { analysisId: string; conc: any; onClose: () => void }) {
  const explain = useApi(() => explainConclusion(analysisId, conc.id), [analysisId, conc.id]);
  return (
    <EvidenceDrawer title={conc.conclusion_type} onClose={onClose}>
      <section>
        <div className="tag-row" style={{ marginBottom: '.6rem' }}>
          <StatusBadge value={conc.decision_state} />
          <span className="pill">confidence: {conc.confidence}</span>
          <span className="pill">rule: {conc.rule_id}</span>
        </div>
        <p>{conc.rationale}</p>
        <dl className="kv">
          <dt>subject</dt><dd>{conc.subject_type}: {conc.subject_ref}</dd>
        </dl>
        {conc.evidence?.length > 0 && (
          <>
            <h4>Evidence references (existing records — never duplicated)</h4>
            <ul className="ev-list">
              {conc.evidence.map((e: any, i: number) => (
                <li key={i} className="ev-item">
                  <div className="ev-item__head">
                    <span className="pill">{e.source_layer}</span>
                    <ProvenanceBadge provenance={e.provenance} mode={e.mode} />
                  </div>
                  <div className="ev-field"><span className="ev-field__label">evidence_ref</span>
                    <span className="ev-field__value">{e.evidence_ref}</span></div>
                  {e.detail && <p className="ev-detail">{e.detail}</p>}
                </li>
              ))}
            </ul>
          </>
        )}
        {conc.blockers?.length > 0 && (
          <>
            <h4>Blockers — what is still required</h4>
            <ul>{conc.blockers.map((b: any, i: number) => (
              <li key={i}><StatusBadge value={b.blocker} /> <span className="muted">{b.reason}</span></li>))}</ul>
          </>
        )}
        {conc.requirements?.length > 0 && (
          <ul>{conc.requirements.map((r: any, i: number) => (
            <li key={i}>{r.satisfied ? '✓' : '✗'} {r.requirement}</li>))}</ul>
        )}
      </section>
      <section>
        <h3>Decision chain</h3>
        <ResultGate result={explain.result} emptyTitle="NO EXPLANATION AVAILABLE">{(p) => <ExplanationView payload={p} />}</ResultGate>
      </section>
      <p className="muted" style={{ fontSize: '.8rem' }}>
        Decision states express evidentiary strength, not exploitability, and are never SAFE/UNSAFE.
      </p>
    </EvidenceDrawer>
  );
}

function AssessmentBody({ analysisId, view, reload }: { analysisId: string; view: any; reload: () => void }) {
  const [selected, setSelected] = useState<any | null>(null);
  const [stateFilter, setStateFilter] = useState('');
  const [busy, setBusy] = useState(false);
  const summ = view.summary || {};
  const byState = summ.by_decision_state || {};
  const conclusions: any[] = view.conclusions || [];
  const filtered = stateFilter ? conclusions.filter((c) => c.decision_state === stateFilter) : conclusions;

  const columns: Column<any>[] = [
    { key: 'state', header: 'Decision', render: (c) => <StatusBadge value={c.decision_state} />, sortValue: (c) => c.decision_state },
    { key: 'type', header: 'Conclusion', render: (c) => <strong>{c.conclusion_type}</strong>, sortValue: (c) => c.conclusion_type },
    { key: 'subject', header: 'Subject', render: (c) => <span className="muted">{c.subject_type}: {String(c.subject_ref).slice(0, 40)}</span>, sortValue: (c) => `${c.subject_type}:${c.subject_ref}` },
    { key: 'rule', header: 'Rule', render: (c) => <span className="pill">{c.rule_id}</span>, sortValue: (c) => c.rule_id },
    { key: 'conf', header: 'Confidence', render: (c) => c.confidence, sortValue: (c) => c.confidence },
  ];

  async function rebuild() {
    setBusy(true);
    await buildAssessment(analysisId);
    setBusy(false);
    reload();
  }

  const states = [...new Set(conclusions.map((c) => c.decision_state))].sort();

  return (
    <div>
      <SectionHeader
        title="Security assessment"
        subtitle="Deterministic decision synthesis over all persisted evidence. No SAFE/UNSAFE, no exploitability."
        actions={<><StatusBadge value={view.status} /><button className="btn" onClick={rebuild} disabled={busy}>{busy ? 'Rebuilding…' : 'Rebuild'}</button></>}
      />
      {summ.truncated && Object.keys(summ.truncated).length > 0 && <TruncatedBanner detail={JSON.stringify(summ.truncated)} />}
      <div className="grid grid-4">
        <MetricCard label="Conclusions" value={summ.conclusions ?? conclusions.length} />
        <MetricCard label="Open (need review)" value={summ.open ?? conclusions.filter((c) => OPEN.has(c.decision_state)).length} />
        <MetricCard label="Blockers" value={summ.blockers ?? 0} />
        <MetricCard label="Overall" value={<StatusBadge value={view.status} />} />
      </div>
      <div className="panel">
        <h3>Decision states</h3>
        <div className="tag-row">
          {Object.entries(byState).map(([s, n]) => (
            <button key={s} className="btn" onClick={() => setStateFilter(stateFilter === s ? '' : s)}
              aria-pressed={stateFilter === s}>
              <StatusBadge value={s} /> <span className="pill">{String(n)}</span>
            </button>
          ))}
        </div>
      </div>
      <div className="panel">
        <h3>Conclusion explorer {stateFilter && <span className="muted">— {stateFilter}</span>}</h3>
        <div className="filters">
          <label>decision state
            <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
              <option value="">all</option>{states.map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
        </div>
        <DataTable rows={filtered} columns={columns} rowKey={(c) => c.id} onRowClick={setSelected}
          initialSort={{ key: 'state', dir: 'asc' }} emptyLabel="NO CONCLUSIONS" />
      </div>
      {selected && <ConclusionDrawer analysisId={analysisId} conc={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

export function Assessment() {
  const { analysisId } = useParams();
  const { result, reload } = useApi(() => getAssessment(analysisId!), [analysisId]);
  return (
    <ResultGate result={result} loadingLabel="Loading assessment…"
      emptyTitle="NO ASSESSMENT YET"
      emptyHint="No assessment has been built for this analysis. Use the backend `assess build` or the Rebuild action.">
      {(v) => <AssessmentBody analysisId={analysisId!} view={v} reload={reload} />}
    </ResultGate>
  );
}
