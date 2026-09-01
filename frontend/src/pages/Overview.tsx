import { useParams } from 'react-router-dom';
import { getAnalysis } from '../api';
import type { AnalysisReport } from '../api/types';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { CapabilityBadge } from '../components/CapabilityBadge';
import { AxisLegend } from '../components/AxisLegend';
import { MetricCard } from '../components/primitives';

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="stat">
      <div className="stat__label">{label}</div>
      <div className="stat__value">{value}</div>
    </div>
  );
}

function OverviewBody({ r }: { r: AnalysisReport }) {
  const apk = r.apk || ({} as any);
  const risk = r.risk?.risk || r.risk || {};
  const kg: any = r.knowledge_graph || {};
  const obf = r.obfuscation?.score || {};
  const nd = r.native_deep_analysis?.capability || {};
  const runtime = r.runtime_validation || r.runtime_summary || {};
  const caps = r.capabilities || {};
  const summary = r.summary || {};
  const assessment = r.assessment || {};
  const aid = r.analysis?.id || apk.id;
  const base = `/analysis/${aid}`;
  const cveUnavailable = Boolean(
    (Array.isArray(r.cve_matches) ? r.cve_matches.length === 0 : true) &&
    caps.cve_analysis && caps.cve_analysis !== 'COMPLETE');

  return (
    <div>
      <div className="pagehead">
        <h1>{apk.package_name || r.manifest?.package || 'Analysis'}</h1>
        <StatusBadge value={r.analysis?.status} />
      </div>
      <AxisLegend />

      <div className="grid grid-4">
        <MetricCard label="Findings" value={summary.total_findings ?? (r.findings?.length ?? '—')} to={`${base}/findings`} />
        <MetricCard label="Attack surface" value={summary.exported_components ?? '—'} hint="exported components" to={`${base}/attack-surface`} />
        <MetricCard label="CVE intelligence" unavailable={cveUnavailable} value={Array.isArray(r.cve_matches) ? r.cve_matches.length : '—'} to={`${base}/cve`} hint={cveUnavailable ? 'offline / no provider data' : undefined} />
        <MetricCard label="Remediation" value={r.remediation?.summary?.total ?? '—'} to={`${base}/remediation`} />
        <MetricCard label="Validation" capability={caps.validation} to={`${base}/validation`} value={r.validation ? (r.validation.length ?? '—') : '—'} />
        <MetricCard label="Runtime" value={<StatusBadge value={runtime.mode || 'UNAVAILABLE'} />} to={`${base}/runtime`} />
        <MetricCard label="Native" value={<StatusBadge value={nd.mode || 'UNAVAILABLE'} />} to={`${base}/native`} hint={`ghidra ${nd.ghidra || caps.ghidra_deep || 'UNAVAILABLE'}`} />
        <MetricCard label="Obfuscation" value={obf.score !== undefined ? `${obf.score}/100` : '—'} to={`${base}/obfuscation`} hint="analysis complexity" />
        <MetricCard label="Assessment" value={<StatusBadge value={assessment.status || 'ASSESSMENT_INCONCLUSIVE'} />} to={`${base}/assessment`} />
      </div>

      <div className="panel">
        <h3>APK identity</h3>
        <dl className="kv">
          <dt>package</dt><dd>{apk.package_name || r.manifest?.package || 'UNKNOWN'}</dd>
          <dt>version</dt><dd>{apk.version_name || 'UNKNOWN'} ({apk.version_code || 'UNKNOWN'})</dd>
          <dt>sha256</dt><dd>{apk.sha256}</dd>
          <dt>size</dt><dd>{apk.size_bytes ? `${apk.size_bytes} bytes` : 'UNKNOWN'}</dd>
          <dt>status</dt><dd><StatusBadge value={r.analysis?.status} /></dd>
        </dl>
      </div>

      {/* Distinct axes — never conflated */}
      <div className="grid grid-4">
        <Stat label="Findings" value={summary.total_findings ?? (r.findings?.length ?? '—')} />
        <Stat label="Risk (score)" value={risk.overall_score ?? '—'} />
        <Stat label="Risk severity" value={<StatusBadge value={risk.severity} kind="severity" />} />
        <Stat label="Risk confidence" value={<StatusBadge value={risk.confidence} />} />
        <Stat label="Native libraries" value={summary.native_libraries ?? '—'} />
        <Stat label="Obfuscation score" value={obf.score !== undefined ? `${obf.score}/100` : '—'} />
        <Stat label="Graph nodes" value={kg.node_count ?? kg.nodes ?? '—'} />
        <Stat label="Graph edges" value={kg.edge_count ?? kg.edges ?? '—'} />
      </div>

      <div className="grid grid-2">
        <div className="panel">
          <h3>Analyzer capabilities</h3>
          {Object.entries(caps).map(([k, v]) => (
            <CapabilityBadge key={k} name={k} availability={String(v)} />
          ))}
        </div>
        <div className="panel">
          <h3>Runtime · Native · Snapshot</h3>
          <dl className="kv">
            <dt>runtime mode</dt><dd><StatusBadge value={runtime.mode || 'UNAVAILABLE'} /></dd>
            <dt>native mode</dt><dd><StatusBadge value={nd.mode || 'UNAVAILABLE'} /></dd>
            <dt>ghidra</dt><dd><StatusBadge value={nd.ghidra || caps.ghidra_deep || 'UNAVAILABLE'} /></dd>
            <dt>graph digest</dt><dd>{kg.digest || 'UNKNOWN'}</dd>
            <dt>obfuscation band</dt><dd>{obf.band ? <span className="pill">{obf.band}</span> : 'UNKNOWN'}</dd>
          </dl>
          <p className="muted" style={{ fontSize: '.8rem' }}>
            The obfuscation score describes analysis complexity, not vulnerability. Risk severity is a separate axis
            from finding severity and remediation priority.
          </p>
        </div>
      </div>

      {Array.isArray(r.root_causes) && r.root_causes.length > 0 && (
        <div className="panel">
          <h3>Root causes</h3>
          <div className="tag-row">
            {r.root_causes.map((rc: any) => (
              <span key={rc.identifier} className="pill" title={rc.description}>
                {rc.category} · <StatusBadge value={rc.severity} kind="severity" />
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function Overview() {
  const { analysisId } = useParams();
  const { result } = useApi(() => getAnalysis(analysisId!), [analysisId]);
  return <ResultGate result={result} loadingLabel="Loading analysis…">{(r) => <OverviewBody r={r} />}</ResultGate>;
}
