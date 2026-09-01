import { useParams } from 'react-router-dom';
import { getObfuscationAnti, getObfuscationImpacts, getObfuscationObservations, getObfuscationSummary } from '../api';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { DataTable, type Column } from '../components/DataTable';

export function Obfuscation() {
  const { analysisId } = useParams();
  const summary = useApi(() => getObfuscationSummary(analysisId!), [analysisId]);
  const observations = useApi(() => getObfuscationObservations(analysisId!), [analysisId]);
  const anti = useApi(() => getObfuscationAnti(analysisId!), [analysisId]);
  const impacts = useApi(() => getObfuscationImpacts(analysisId!), [analysisId]);

  const obsCols: Column<any>[] = [
    { key: 'category', header: 'Category', sortValue: (r) => r.category },
    { key: 'indicator', header: 'Indicator', render: (r) => <span title={r.target || ''}>{r.indicator}</span>, sortValue: (r) => r.indicator },
    { key: 'state', header: 'State', render: (r) => <StatusBadge value={r.state} />, sortValue: (r) => r.state },
    { key: 'confidence', header: 'Confidence', render: (r) => <span className="pill">{r.confidence}</span>, sortValue: (r) => r.confidence },
  ];
  const antiCols: Column<any>[] = [
    { key: 'category', header: 'Category', sortValue: (r) => r.category },
    { key: 'indicator', header: 'Indicator', sortValue: (r) => r.indicator },
    { key: 'evidence_level', header: 'Evidence level', render: (r) => <StatusBadge value={r.evidence_level} />, sortValue: (r) => r.evidence_level },
  ];

  return (
    <div>
      <div className="pagehead"><h1>Obfuscation & anti-analysis</h1></div>
      <p className="muted">
        The obfuscation score describes analysis complexity — not vulnerability or exploitability. An anti-analysis
        indicator does not prove active anti-analysis behavior.
      </p>
      <ResultGate result={summary.result} emptyTitle="NO OBFUSCATION DATA">
        {(s: any) => (
          <div className="grid grid-4">
            <div className="stat"><div className="stat__label">Score (complexity)</div><div className="stat__value">{s.score?.score ?? '—'}/100</div></div>
            <div className="stat"><div className="stat__label">Band</div><div className="stat__value" style={{ fontSize: '1rem' }}>{s.score?.band ?? 'UNKNOWN'}</div></div>
            <div className="stat"><div className="stat__label">Observations</div><div className="stat__value">{s.summary?.observations ?? 0}</div></div>
            <div className="stat"><div className="stat__label">Anti-analysis</div><div className="stat__value">{s.summary?.anti_analysis_indicators ?? 0}</div></div>
          </div>
        )}
      </ResultGate>

      <div className="panel">
        <h3>Observations</h3>
        <ResultGate result={observations.result} emptyTitle="NO OBSERVATIONS">
          {(rows) => <DataTable rows={rows as any[]} columns={obsCols} rowKey={(r) => r.id} />}
        </ResultGate>
      </div>
      <div className="panel">
        <h3>Anti-analysis indicators</h3>
        <ResultGate result={anti.result} emptyTitle="NO ANTI-ANALYSIS INDICATORS">
          {(rows) => <DataTable rows={rows as any[]} columns={antiCols} rowKey={(r) => r.id} />}
        </ResultGate>
      </div>
      <div className="panel">
        <h3>Analysis impacts</h3>
        <ResultGate result={impacts.result} emptyTitle="NO ANALYSIS IMPACTS">
          {(rows) => (
            <ul>{(rows as any[]).map((i) => <li key={i.id}><span className="pill">{i.impact_category}</span> {i.description}</li>)}</ul>
          )}
        </ResultGate>
      </div>
    </div>
  );
}
