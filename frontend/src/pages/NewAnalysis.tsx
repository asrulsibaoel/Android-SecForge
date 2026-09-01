import { useCallback, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { createAnalysis, uploadArtifact } from '../api';
import { SectionHeader } from '../components/primitives';
import { StatusBadge } from '../components/StatusBadge';

// Supported artifact intake types (backend is authoritative; this is the honest
// client-side hint). We never claim every format is analyzed identically.
const EXT_TYPE: Record<string, string> = { '.apk': 'APK', '.apks': 'APK_SET', '.apkm': 'APKM', '.aab': 'APP_BUNDLE' };
const ALLOWED = Object.keys(EXT_TYPE);
const CLIENT_MAX = 512 * 1024 * 1024; // mirrors the backend default; backend re-validates

type ItemState = 'READY' | 'INVALID' | 'UPLOADING' | 'UPLOADED' | 'ERROR';
interface Item {
  key: string;
  file: File;
  type: string;
  state: ItemState;
  reason?: string;
  artifactId?: string;
  duplicate?: boolean;
}

function ext(name: string): string {
  const i = name.lastIndexOf('.');
  return i >= 0 ? name.slice(i).toLowerCase() : '';
}

function classify(file: File): Item {
  const e = ext(file.name);
  const key = `${file.name}:${file.size}:${file.lastModified}`;
  if (!ALLOWED.includes(e)) return { key, file, type: 'UNKNOWN', state: 'INVALID', reason: 'unsupported extension' };
  if (file.size === 0) return { key, file, type: EXT_TYPE[e], state: 'INVALID', reason: 'empty file' };
  if (file.size > CLIENT_MAX) return { key, file, type: EXT_TYPE[e], state: 'INVALID', reason: 'exceeds max size' };
  return { key, file, type: EXT_TYPE[e], state: 'READY' };
}

export function NewAnalysis() {
  const navigate = useNavigate();
  const [items, setItems] = useState<Item[]>([]);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const addFiles = useCallback((files: FileList | File[]) => {
    setItems((prev) => {
      const seen = new Set(prev.map((i) => i.key));
      const next = [...prev];
      for (const f of Array.from(files)) {
        const it = classify(f);
        if (!seen.has(it.key)) {
          seen.add(it.key);
          next.push(it);
        }
      }
      return next;
    });
  }, []);

  function onDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files?.length) addFiles(e.dataTransfer.files);
  }

  const valid = items.filter((i) => i.state === 'READY' || i.state === 'UPLOADED');

  async function start() {
    setBusy(true);
    let firstExec: string | null = null;
    const updated = [...items];
    for (let i = 0; i < updated.length; i++) {
      const it = updated[i];
      if (it.state !== 'READY') continue;
      updated[i] = { ...it, state: 'UPLOADING' };
      setItems([...updated]);
      const up = await uploadArtifact(it.file);
      if (up.status !== 'success' || !up.data?.id) {
        updated[i] = { ...it, state: 'ERROR', reason: up.error || up.status };
        setItems([...updated]);
        continue;
      }
      updated[i] = { ...it, state: 'UPLOADED', artifactId: up.data.id };
      setItems([...updated]);
      const created = await createAnalysis(up.data.id);
      if ((created.status === 'success' || created.status === 'empty') && created.data?.execution_id) {
        if (!firstExec) firstExec = created.data.execution_id;
      } else {
        // Never fail silently: a create failure (e.g. a stale backend returning
        // 405, or a 4xx) is surfaced on the row so the user isn't left guessing.
        updated[i] = { ...it, state: 'ERROR', artifactId: up.data.id, reason: `analysis not started (${created.error || created.status})` };
        setItems([...updated]);
      }
    }
    setBusy(false);
    if (firstExec) navigate(`/progress/execution/${firstExec}`);
  }

  return (
    <div>
      <SectionHeader title="New analysis"
        subtitle="Upload an Android artifact (APK / APKS / APKM / AAB). Backend validation is authoritative." />

      <div
        className={`dropzone ${dragging ? 'dropzone--active' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') inputRef.current?.click(); }}
        role="button"
        tabIndex={0}
        aria-label="Drop artifacts here or press Enter to choose files"
      >
        <div className="dropzone__icon" aria-hidden="true">⇪</div>
        <div><strong>Drag &amp; drop artifacts</strong> or click to choose files</div>
        <div className="muted">Supported: {ALLOWED.join(', ')} · max {Math.round(CLIENT_MAX / 1024 / 1024)} MB each</div>
        <input ref={inputRef} type="file" multiple accept={ALLOWED.join(',')} style={{ display: 'none' }}
          onChange={(e) => e.target.files && addFiles(e.target.files)} />
      </div>

      {items.length > 0 && (
        <div className="panel">
          <h3>Selected artifacts ({items.length})</h3>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Filename</th><th>Type</th><th>Size</th><th>State</th><th></th></tr></thead>
              <tbody>
                {items.map((it, idx) => (
                  <tr key={it.key}>
                    <td>{it.file.name}</td>
                    <td><span className="pill">{it.type}</span></td>
                    <td className="muted">{(it.file.size / 1024 / 1024).toFixed(2)} MB</td>
                    <td>
                      {it.state === 'INVALID' || it.state === 'ERROR'
                        ? <span className="tone-concern" title={it.reason}>{it.state} · {it.reason}</span>
                        : <StatusBadge value={it.state === 'READY' || it.state === 'UPLOADED' ? 'READY' : it.state} />}
                    </td>
                    <td>
                      <button className="btn" aria-label={`Remove ${it.file.name}`}
                        onClick={() => setItems(items.filter((_, j) => j !== idx))} disabled={busy}>×</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="filters" style={{ marginTop: '.8rem' }}>
            <button className="btn btn--primary" onClick={start} disabled={busy || valid.length === 0}>
              {busy ? 'Starting…' : `Start Analysis${valid.length > 1 ? ` (${valid.length})` : ''}`}
            </button>
            <span className="muted">Only valid artifacts are analyzed. Multiple files are independent analyses.</span>
          </div>
        </div>
      )}
    </div>
  );
}
