import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { createInvestigation, listInvestigations } from '../api';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';

export function InvestigationTab() {
  const { analysisId } = useParams();
  const navigate = useNavigate();
  const { result, reload } = useApi(() => listInvestigations(), []);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);

  async function create() {
    setBusy(true);
    const r = await createInvestigation(analysisId!, name || undefined);
    setBusy(false);
    const iid = r.data?.investigation_id || r.data?.id;
    if ((r.status === 'success' || r.status === 'empty') && iid) navigate(`/investigations/${iid}`);
    else reload();
  }

  return (
    <div>
      <div className="pagehead"><h1>Investigation</h1></div>
      <div className="panel">
        <h3>Create investigation for this analysis</h3>
        <div className="filters">
          <label>name<input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="optional name" /></label>
          <button className="btn btn--primary" onClick={create} disabled={busy}>{busy ? 'Creating…' : 'Create'}</button>
        </div>
        <p className="muted">A workspace collects your pins, notes, and hypotheses. Hypotheses never alter machine-derived truth.</p>
      </div>
      <div className="panel">
        <h3>Existing investigations</h3>
        <ResultGate result={result} emptyTitle="NO INVESTIGATIONS YET">
          {(rows) => (
            <ul>{(rows as any[]).filter((i) => !i.analysis_id || i.analysis_id === analysisId).map((i) => (
              <li key={i.id}><Link to={`/investigations/${i.id}`}>{i.name || i.id}</Link></li>
            ))}</ul>
          )}
        </ResultGate>
      </div>
    </div>
  );
}
