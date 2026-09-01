import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { getFindings } from '../api';
import type { Finding } from '../api/types';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { EvidenceItem } from '../components/EvidenceDrawer';
import { StatusBadge } from '../components/StatusBadge';

export function EvidenceTab() {
  const { analysisId } = useParams();
  const { result } = useApi(() => getFindings(analysisId!), [analysisId]);
  const [q, setQ] = useState('');
  return (
    <div>
      <div className="pagehead"><h1>Evidence</h1></div>
      <p className="muted">Every evidence object shows its provenance. Missing fields stay UNKNOWN — never filled with placeholders.</p>
      <div className="filters"><label>filter<input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="rule / source / detail" /></label></div>
      <ResultGate result={result} emptyTitle="NO EVIDENCE">
        {(rows: Finding[]) => {
          const filtered = rows.filter((f) =>
            !q || `${f.rule_id} ${f.title} ${f.evidence.map((e) => `${e.source} ${e.detail}`).join(' ')}`.toLowerCase().includes(q.toLowerCase()));
          return (
            <div>
              {filtered.map((f) => (
                <div className="panel" key={f.id}>
                  <div className="tag-row" style={{ marginBottom: '.5rem' }}>
                    <strong>{f.rule_id}</strong><StatusBadge value={f.severity} kind="severity" />
                    <span className="muted">{f.title}</span>
                  </div>
                  {f.evidence.length === 0
                    ? <div className="state state--empty"><strong>NO EVIDENCE AVAILABLE</strong></div>
                    : <ul className="ev-list">{f.evidence.map((ev, i) => <EvidenceItem key={i} ev={ev} />)}</ul>}
                </div>
              ))}
            </div>
          );
        }}
      </ResultGate>
    </div>
  );
}
