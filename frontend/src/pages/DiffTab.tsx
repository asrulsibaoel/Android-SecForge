import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { createComparison, listAnalyses } from '../api';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';

export function DiffTab() {
  const { analysisId } = useParams();
  const navigate = useNavigate();
  const { result } = useApi(() => listAnalyses(100), []);
  const [candidate, setCandidate] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function compare() {
    if (!candidate) return;
    setBusy(true);
    setError(null);
    const r = await createComparison(analysisId!, candidate);
    setBusy(false);
    const cid = r.data?.comparison_id || r.data?.id;
    if ((r.status === 'success' || r.status === 'empty') && cid) navigate(`/diff/${cid}`);
    else setError(r.error || r.status);
  }

  return (
    <div>
      <div className="pagehead"><h1>APK Diff</h1></div>
      <div className="panel">
        <h3>Compare this analysis (baseline A) → candidate B</h3>
        <ResultGate result={result} emptyTitle="NO OTHER ANALYSES">
          {(rows) => (
            <div className="filters">
              <label>candidate (B)
                <select value={candidate} onChange={(e) => setCandidate(e.target.value)}>
                  <option value="">choose…</option>
                  {(rows as any[]).filter((a) => a.id !== analysisId).map((a) => (
                    <option key={a.id} value={a.id}>{a.package || a.id} · {a.apk_sha256?.slice(0, 10)}</option>
                  ))}
                </select>
              </label>
              <button className="btn btn--primary" onClick={compare} disabled={!candidate || busy}>{busy ? 'Comparing…' : 'Create comparison'}</button>
            </div>
          )}
        </ResultGate>
        {error && <div className="state state--error">{error}</div>}
        <p className="muted">
          Direction matters (A→B). A REMOVED finding is NO_LONGER_DETECTED — never “FIXED”. A new finding is never “EXPLOITABLE”.
        </p>
      </div>
    </div>
  );
}
