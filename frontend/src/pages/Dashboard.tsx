import { Link } from 'react-router-dom';
import { getDoctor, listAnalyses, listInvestigations } from '../api';
import type { AnalysisListItem, Capability, DoctorReport } from '../api/types';
import { useApi } from '../hooks/useApi';
import { CapabilityBadge } from '../components/CapabilityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { ResultGate } from '../components/States';
import { AxisLegend } from '../components/AxisLegend';

function CapabilityPanel({ doctor }: { doctor: DoctorReport }) {
  const tools = (doctor.tools ?? []).map((t) => ({ name: t.name, availability: t.capability ?? t.status, reason: t.status }));
  const runtime: Capability[] = doctor.runtime ?? [];
  const graph: Capability[] = doctor.graph ?? [];
  return (
    <div className="grid grid-3">
      <div className="panel">
        <h3>Toolchain</h3>
        {tools.map((c) => <CapabilityBadge key={c.name} name={c.name} availability={c.availability} reason={c.reason} />)}
      </div>
      <div className="panel">
        <h3>Runtime capability</h3>
        {runtime.length === 0 ? <p className="muted">No runtime capabilities reported.</p> :
          runtime.map((c) => <CapabilityBadge key={c.name} name={c.name} availability={c.availability} reason={c.reason} />)}
      </div>
      <div className="panel">
        <h3>Graph / intelligence</h3>
        {graph.map((c) => <CapabilityBadge key={c.name} name={c.name} availability={c.availability} reason={c.reason} />)}
      </div>
    </div>
  );
}

function AnalysesPanel({ rows }: { rows: AnalysisListItem[] }) {
  return (
    <div className="panel">
      <h3>Recent analyses</h3>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Package</th><th>Artifact</th><th>Type</th><th>Status</th><th>Findings</th><th>Native</th><th>Actions</th></tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id}>
                <td><Link to={`/analysis/${a.id}`}>{a.package ?? '(unknown package)'}</Link></td>
                <td className="muted">{(a as any).artifact_filename ?? '—'}</td>
                <td>{(a as any).artifact_type ? <span className="pill">{(a as any).artifact_type}</span> : <span className="muted">—</span>}</td>
                <td><StatusBadge value={a.status} /></td>
                <td>{a.finding_count}</td>
                <td>{a.native_library_count}</td>
                <td>
                  <Link className="btn" to={`/analysis/${a.id}`}>Open</Link>{' '}
                  <Link className="btn" to={`/progress/analysis/${a.id}`}>View Progress</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function Dashboard() {
  const analyses = useApi(() => listAnalyses(50), []);
  const doctor = useApi(() => getDoctor(), []);
  const investigations = useApi(() => listInvestigations(), []);

  return (
    <div>
      <div className="pagehead">
        <div>
          <h1>Dashboard</h1>
          <span className="muted">All values originate from the backend API. Capability states are shown honestly.</span>
        </div>
        <Link to="/analyses/new" className="btn btn--primary">+ New Analysis</Link>
      </div>
      <AxisLegend />

      <ResultGate result={analyses.result} emptyTitle="NO ANALYSES" emptyHint="Import and analyze an APK via the backend CLI to populate this workspace.">
        {(rows) => <AnalysesPanel rows={rows} />}
      </ResultGate>

      <ResultGate result={doctor.result} loadingLabel="Loading capabilities…">
        {(d) => <CapabilityPanel doctor={d} />}
      </ResultGate>

      <div className="panel">
        <h3>Latest investigations</h3>
        <ResultGate result={investigations.result} emptyTitle="NO INVESTIGATIONS" emptyHint="Create one from an analysis workspace.">
          {(rows) => (
            <ul>
              {(rows as any[]).slice(0, 10).map((inv) => (
                <li key={inv.id}><Link to={`/investigations/${inv.id}`}>{inv.name || inv.id}</Link></li>
              ))}
            </ul>
          )}
        </ResultGate>
      </div>
    </div>
  );
}
