import { NavLink, Outlet, useParams } from 'react-router-dom';

const TABS: Array<[string, string]> = [
  ['', 'Overview'],
  ['findings', 'Findings'],
  ['attack-surface', 'Attack Surface'],
  ['graph', 'Knowledge Graph'],
  ['cve', 'CVE Intelligence'],
  ['remediation', 'Remediation'],
  ['validation', 'Validation'],
  ['runtime', 'Runtime'],
  ['native', 'Native'],
  ['obfuscation', 'Obfuscation'],
  ['assessment', 'Assessment'],
  ['diff', 'Diff'],
  ['investigation', 'Investigation'],
  ['evidence', 'Evidence'],
  ['search', 'Search'],
];

export function AnalysisLayout() {
  const { analysisId } = useParams();
  return (
    <div className="analysis-shell">
      <nav className="subnav" aria-label="Analysis sections">
        {TABS.map(([path, label]) => (
          <NavLink
            key={path}
            to={path ? `/analysis/${analysisId}/${path}` : `/analysis/${analysisId}`}
            end={path === ''}
            className={({ isActive }) => (isActive ? 'active' : '')}
          >
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="analysis-main">
        <Outlet />
      </div>
    </div>
  );
}
