import { useParams } from 'react-router-dom';
import { getNative } from '../api';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { DataTable, type Column } from '../components/DataTable';

export function Native() {
  const { analysisId } = useParams();
  const { result } = useApi(() => getNative(analysisId!), [analysisId]);

  return (
    <div>
      <div className="pagehead"><h1>Native / Deep Native</h1></div>
      <ResultGate result={result} emptyTitle="NO NATIVE ANALYSIS">
        {(nd: any) => {
          const cap = nd.capability || {};
          const s = nd.summary || {};
          const elfOnly = String(cap.mode).toUpperCase() === 'ELF_ONLY';
          const funcCols: Column<any>[] = [
            { key: 'name', header: 'Function', render: (r) => <span title={r.entry || ''}>{r.name}</span>, sortValue: (r) => r.name },
            { key: 'type', header: 'Type', render: (r) => <span className="pill">{r.function_type}</span>, sortValue: (r) => r.function_type },
            { key: 'exp', header: 'Exported', render: (r) => (r.is_exported ? 'yes' : '—'), sortValue: (r) => (r.is_exported ? 1 : 0) },
            { key: 'imp', header: 'Imported', render: (r) => (r.is_imported ? 'yes' : '—'), sortValue: (r) => (r.is_imported ? 1 : 0) },
            { key: 'source', header: 'Source', sortValue: (r) => r.source },
          ];
          const apiCols: Column<any>[] = [
            { key: 'api', header: 'API', sortValue: (r) => r.api },
            { key: 'category', header: 'Category', render: (r) => <span className="pill">{r.category}</span>, sortValue: (r) => r.category },
            { key: 'state', header: 'State', render: (r) => <StatusBadge value={r.state} />, sortValue: (r) => r.state },
          ];
          const jniCols: Column<any>[] = [
            { key: 'jc', header: 'Java', render: (r) => `${r.java_class}.${r.java_method}`, sortValue: (r) => `${r.java_class}.${r.java_method}` },
            { key: 'sym', header: 'Native target', render: (r) => r.native_symbol || <StatusBadge value="UNKNOWN_NATIVE_TARGET" />, sortValue: (r) => r.native_symbol ?? '' },
            { key: 'reg', header: 'Registration', render: (r) => <span className="pill">{r.registration_type}</span>, sortValue: (r) => r.registration_type },
            { key: 'state', header: 'State', render: (r) => <StatusBadge value={r.state} />, sortValue: (r) => r.state },
          ];
          return (
            <div>
              <div className="notice tone-unknown" style={{ marginBottom: '1rem' }}>
                Mode: <StatusBadge value={cap.mode} /> · Ghidra: <StatusBadge value={cap.ghidra || 'UNAVAILABLE'} />
                {elfOnly && ' — NATIVE CALL-GRAPH ANALYSIS UNAVAILABLE (ELF-ONLY). Reachability from Java is not modeled without Ghidra.'}
              </div>
              <div className="grid grid-4">
                <div className="stat"><div className="stat__label">Binaries</div><div className="stat__value">{s.binaries ?? 0}</div></div>
                <div className="stat"><div className="stat__label">Functions</div><div className="stat__value">{s.functions ?? 0}</div></div>
                <div className="stat"><div className="stat__label">JNI bindings</div><div className="stat__value">{s.jni_bindings ?? 0}</div></div>
                <div className="stat"><div className="stat__label">Call edges</div><div className="stat__value">{s.call_edges ?? 0}</div></div>
              </div>
              <p className="muted">
                Presence is not reachability: NATIVE_API_PRESENT ≠ NATIVE_CALL_CHAIN_REACHES_API. A native function
                existing never implies it is reachable from Java. UNKNOWN_NATIVE_TARGET is preserved.
              </p>

              <div className="panel"><h3>Binaries</h3>
                <DataTable rows={nd.binaries || []} columns={[
                  { key: 'filename', header: 'File', sortValue: (r: any) => r.filename },
                  { key: 'arch', header: 'Arch', render: (r: any) => r.architecture || r.abi, sortValue: (r: any) => r.architecture || r.abi || '' },
                  { key: 'stripped', header: 'Stripped', render: (r: any) => (r.stripped ? 'yes' : 'no'), sortValue: (r: any) => (r.stripped ? 1 : 0) },
                  { key: 'source', header: 'Source', sortValue: (r: any) => r.source },
                ]} rowKey={(r: any) => r.fingerprint} emptyLabel="NO BINARIES" />
              </div>
              <div className="panel"><h3>Security-relevant API observations</h3>
                {(nd.api_observations || []).length === 0
                  ? <div className="state state--empty"><strong>NO API OBSERVATIONS</strong></div>
                  : <DataTable rows={nd.api_observations} columns={apiCols} rowKey={(r: any) => r.id} />}
              </div>
              <div className="panel"><h3>JNI bindings</h3>
                {(nd.jni_bindings || []).length === 0
                  ? <div className="state state--empty"><strong>NO JNI BINDINGS</strong><p className="muted">This APK exposes no Java↔native bindings.</p></div>
                  : <DataTable rows={nd.jni_bindings} columns={jniCols} rowKey={(r: any) => r.id} />}
              </div>
              <div className="panel"><h3>Functions</h3>
                <DataTable rows={nd.functions || []} columns={funcCols} rowKey={(r: any) => r.id} emptyLabel="NO FUNCTIONS" pageSize={20} />
              </div>
            </div>
          );
        }}
      </ResultGate>
    </div>
  );
}
