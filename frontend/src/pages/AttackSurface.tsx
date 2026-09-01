import { useParams } from 'react-router-dom';
import { getAttackSurface } from '../api';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { DataTable, type Column } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';

interface Node { node_key: string; type: string; name: string; exposure: string; component?: string; permission?: string | null; risk_score: number; evidence?: string }

export function AttackSurface() {
  const { analysisId } = useParams();
  const { result } = useApi(() => getAttackSurface(analysisId!), [analysisId]);
  const columns: Column<Node>[] = [
    { key: 'name', header: 'Node', render: (r) => <span title={r.node_key}>{r.name}</span>, sortValue: (r) => r.name },
    { key: 'type', header: 'Type', sortValue: (r) => r.type },
    { key: 'exposure', header: 'Exposure', render: (r) => <StatusBadge value={r.exposure} />, sortValue: (r) => r.exposure },
    { key: 'permission', header: 'Permission', render: (r) => r.permission || <span className="muted">—</span>, sortValue: (r) => r.permission ?? '' },
    { key: 'risk', header: 'Risk score', render: (r) => r.risk_score, sortValue: (r) => r.risk_score },
  ];
  return (
    <div>
      <div className="pagehead"><h1>Attack Surface</h1></div>
      <p className="muted">Exposure and risk score are attack-surface facts — not a safety verdict.</p>
      <ResultGate result={result} emptyTitle="NO ATTACK-SURFACE NODES">
        {(rows) => <DataTable rows={rows as Node[]} columns={columns} rowKey={(r) => r.node_key} initialSort={{ key: 'risk', dir: 'desc' }} />}
      </ResultGate>
    </div>
  );
}
