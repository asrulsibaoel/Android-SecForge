import { useParams } from 'react-router-dom';
import { getDeviceCapability, getRuntimeValidation } from '../api';
import type { RuntimeValidationView } from '../api/types';
import { useApi } from '../hooks/useApi';
import { ResultGate, Unavailable } from '../components/States';
import { ModeBadge, StatusBadge } from '../components/StatusBadge';
import { CapabilityBadge } from '../components/CapabilityBadge';
import { DataTable, type Column } from '../components/DataTable';

// Read-only device-capability panel (prompt 23/24). It attaches to nothing; it
// only renders what the backend reported from actual ADB output. frida-server is
// never inferred from host Frida.
function DeviceCapabilityPanel() {
  const { result } = useApi(() => getDeviceCapability(), []);
  return (
    <ResultGate result={result} loadingLabel="Discovering device…" emptyTitle="DEVICE CAPABILITY UNAVAILABLE">
      {(d: any) => {
        const dev = d.device || {};
        const nativeUnavail = String(d.frida_server).toUpperCase() !== 'AVAILABLE';
        return (
          <div className="panel">
            <h3>Device capability</h3>
            <div className="grid grid-3">
              <CapabilityBadge name="adb" availability={d.adb} />
              <CapabilityBadge name="device" availability={d.device_state} />
              <CapabilityBadge name="frida host" availability={d.frida_host} reason={d.frida_host_version} />
              <CapabilityBadge name="frida-server" availability={d.frida_server} />
              <CapabilityBadge name="runtime-validation" availability={d.runtime_validation} />
              <CapabilityBadge name="native-runtime-correlation" availability={d.native_runtime_correlation} />
            </div>
            {d.device_state === 'CONNECTED' && (
              <dl className="kv" style={{ marginTop: '.7rem' }}>
                <dt>model</dt><dd>{dev.manufacturer} {dev.model} ({dev.brand})</dd>
                <dt>android</dt><dd>{dev.android_version} · API {dev.api_level} · {dev.abi}</dd>
                <dt>build</dt><dd>{dev.build_type} · {String(dev.build_fingerprint || 'UNKNOWN').slice(0, 60)}…</dd>
              </dl>
            )}
            {nativeUnavail && (
              <div className="notice tone-unknown" style={{ marginTop: '.7rem' }}>
                Native runtime instrumentation unavailable — frida-server is not available on the target device.
                This is not “0 native events”.
              </div>
            )}
          </div>
        );
      }}
    </ResultGate>
  );
}

function RuntimeBody({ v }: { v: RuntimeValidationView }) {
  const mode = String(v.mode).toUpperCase();
  const s = v.summary || {};
  const corrCols: Column<any>[] = [
    { key: 'taxonomy', header: 'Taxonomy', render: (r) => <span className="pill">{r.taxonomy || '—'}</span>, sortValue: (r) => r.taxonomy ?? '' },
    { key: 'subject', header: 'Subject', render: (r) => `${r.subject_type}: ${String(r.subject_ref).slice(0, 40)}`, sortValue: (r) => r.subject_type },
    { key: 'type', header: 'Correlation', render: (r) => <span className="pill">{r.correlation_type}</span>, sortValue: (r) => r.correlation_type },
    { key: 'mode', header: 'Evidence', render: (r) => <ModeBadge mode={r.mode} />, sortValue: (r) => r.mode },
    { key: 'provenance', header: 'Provenance', render: (r) => <span className="pill">{r.provenance}</span>, sortValue: (r) => r.provenance },
    { key: 'confidence', header: 'Confidence', sortValue: (r) => r.confidence },
  ];
  return (
    <div>
      <div className="pagehead">
        <h1>Runtime</h1>
        <ModeBadge mode={v.mode} />
      </div>
      <DeviceCapabilityPanel />
      {mode === 'UNAVAILABLE' && (
        <Unavailable label="LIVE RUNTIME UNAVAILABLE" detail="No runtime observations recorded. This is not zero activity and not a safety verdict." />
      )}
      {mode === 'MOCKED' && (
        <div className="notice tone-mocked" style={{ marginBottom: '1rem', fontWeight: 700 }}>
          MOCKED — NOT LIVE EVIDENCE. These observations come from an offline test adapter and never count as LIVE
          corroboration.
        </div>
      )}
      <div className="grid grid-4">
        <div className="stat"><div className="stat__label">Sessions</div><div className="stat__value">{s.sessions ?? 0}</div></div>
        <div className="stat"><div className="stat__label">Observations</div><div className="stat__value">{s.observations ?? 0}</div></div>
        <div className="stat"><div className="stat__label">Correlations</div><div className="stat__value">{s.correlations ?? 0}</div></div>
        <div className="stat"><div className="stat__label">LIVE claims</div><div className="stat__value">{s.live_claims ?? 0}</div></div>
      </div>

      {Array.isArray(v.blockers) && v.blockers.length > 0 && (
        <div className="panel">
          <h3>Blockers</h3>
          <ul>{v.blockers.map((b, i) => <li key={i}><StatusBadge value={b.blocker} /> <span className="muted">{b.reason}</span></li>)}</ul>
        </div>
      )}

      <div className="panel">
        <h3>Static ↔ runtime correlations</h3>
        <p className="muted">Every correlation is permanently labelled LIVE or MOCKED. A missing observation is not negative evidence.</p>
        <DataTable rows={v.correlations || []} columns={corrCols} rowKey={(r) => r.id} emptyLabel="NO CORRELATIONS" />
      </div>

      {v.uncertainties?.length > 0 && (
        <div className="panel"><h3>Uncertainty</h3><ul className="tone-unknown">{v.uncertainties.map((u, i) => <li key={i}>⚠ {u}</li>)}</ul></div>
      )}
      <p className="muted" style={{ fontSize: '.8rem' }}>{v.note}</p>
    </div>
  );
}

export function Runtime() {
  const { analysisId } = useParams();
  const { result } = useApi(() => getRuntimeValidation(analysisId!), [analysisId]);
  return <ResultGate result={result} loadingLabel="Loading runtime…">{(v) => <RuntimeBody v={v} />}</ResultGate>;
}
