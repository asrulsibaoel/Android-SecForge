import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getAssessmentConclusions, getCve, getFindings, getNativeFunctions, getValidationClaims } from '../api';
import { useApi } from '../hooks/useApi';
import { SectionHeader } from '../components/primitives';
import { StatusBadge } from '../components/StatusBadge';

// Bounded search SCOPED to the selected analysis (prompt 25 §18). It filters the
// already-bounded per-analysis API results — never an unbounded cross-analysis
// scan. Each result is typed and links to the appropriate workspace.
export function Search() {
  const { analysisId } = useParams();
  const findings = useApi(() => getFindings(analysisId!), [analysisId]);
  const cve = useApi(() => getCve(analysisId!), [analysisId]);
  const validation = useApi(() => getValidationClaims(analysisId!), [analysisId]);
  const native = useApi(() => getNativeFunctions(analysisId!), [analysisId]);
  const assessment = useApi(() => getAssessmentConclusions(analysisId!), [analysisId]);
  const [q, setQ] = useState('');

  const results = useMemo(() => {
    const term = q.trim().toLowerCase();
    if (!term) return [];
    const out: Array<{ type: string; label: string; to: string; badge?: string }> = [];
    const base = `/analysis/${analysisId}`;
    for (const f of (findings.result.data as any[] | null) || []) {
      if (`${f.rule_id} ${f.title} ${f.component}`.toLowerCase().includes(term))
        out.push({ type: 'Finding', label: `${f.rule_id} — ${f.title}`, to: `${base}/findings`, badge: f.severity });
    }
    for (const c of (cve.result.data as any[] | null) || []) {
      if (`${c.cve_id} ${c.dependency ?? ''}`.toLowerCase().includes(term))
        out.push({ type: 'CVE', label: `${c.cve_id}`, to: `${base}/cve`, badge: c.version_state });
    }
    for (const v of (validation.result.data as any[] | null) || []) {
      if (`${v.claim_type} ${v.target}`.toLowerCase().includes(term))
        out.push({ type: 'Validation', label: `${v.claim_type} — ${v.target}`, to: `${base}/validation`, badge: v.validation_state });
    }
    for (const n of (native.result.data as any[] | null) || []) {
      if (`${n.name} ${n.function_type ?? ''}`.toLowerCase().includes(term))
        out.push({ type: 'Native', label: n.name, to: `${base}/native`, badge: n.function_type });
    }
    for (const a of (assessment.result.data as any[] | null) || []) {
      if (`${a.conclusion_type} ${a.subject_ref}`.toLowerCase().includes(term))
        out.push({ type: 'Assessment', label: a.conclusion_type, to: `${base}/assessment`, badge: a.decision_state });
    }
    return out.slice(0, 200);
  }, [q, analysisId, findings.result, cve.result, validation.result, native.result, assessment.result]);

  return (
    <div>
      <SectionHeader title="Search" subtitle="Search is scoped to the selected analysis (bounded — no cross-analysis scan)." />
      <div className="filters">
        <label style={{ flex: 1 }}>query
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} autoFocus
            placeholder="finding / CVE / component / native function / claim / conclusion" style={{ width: '100%' }} />
        </label>
      </div>
      {!q.trim() ? (
        <div className="state state--empty"><strong>Type to search within this analysis</strong></div>
      ) : results.length === 0 ? (
        <div className="state state--empty"><strong>NO MATCHES</strong><p className="muted">No entities in this analysis match “{q}”.</p></div>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th>Type</th><th>Result</th><th>State</th></tr></thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i}><td><span className="pill">{r.type}</span></td>
                  <td><Link to={r.to}>{r.label}</Link></td>
                  <td>{r.badge ? <StatusBadge value={r.badge} /> : <span className="muted">—</span>}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
