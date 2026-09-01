import { Link } from 'react-router-dom';
import { listInvestigations } from '../api';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';

export function InvestigationList() {
  const { result } = useApi(() => listInvestigations(), []);
  return (
    <div>
      <div className="pagehead"><h1>Investigations</h1></div>
      <div className="panel">
        <ResultGate result={result} emptyTitle="NO INVESTIGATIONS" emptyHint="Open an analysis and create one from its Investigation tab.">
          {(rows) => (
            <ul>{(rows as any[]).map((i) => (
              <li key={i.id}>
                <Link to={`/investigations/${i.id}`}>{i.name || i.id}</Link>
                {i.analysis_id && <span className="muted"> · analysis {String(i.analysis_id).slice(0, 8)}</span>}
              </li>
            ))}</ul>
          )}
        </ResultGate>
      </div>
    </div>
  );
}
