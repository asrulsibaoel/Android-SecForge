import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { addHypothesis, addNote, getInvestigation, getInvestigationTimeline, investigationExportUrl } from '../api';
import { useApi } from '../hooks/useApi';
import { ResultGate } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';

// Machine-generated timeline event types vs researcher-generated (§16). Researcher
// notes/hypotheses are visually separated and never alter machine truth (§15).
const RESEARCHER_EVENTS = new Set(['NOTE', 'HYPOTHESIS', 'BOOKMARK', 'INVESTIGATION_NOTE']);

const SECTIONS = ['Overview', 'Findings', 'Notes', 'Hypotheses', 'Timeline', 'Graph', 'Export'] as const;
type Section = (typeof SECTIONS)[number];

function Body({ invId }: { invId: string }) {
  const inv = useApi(() => getInvestigation(invId), [invId]);
  const timeline = useApi(() => getInvestigationTimeline(invId), [invId]);
  const [section, setSection] = useState<Section>('Overview');
  const [note, setNote] = useState('');
  const [hypo, setHypo] = useState('');

  async function submitNote() {
    if (!note.trim()) return;
    await addNote(invId, note.trim());
    setNote('');
    inv.reload();
    timeline.reload();
  }
  async function submitHypo() {
    if (!hypo.trim()) return;
    await addHypothesis(invId, hypo.trim());
    setHypo('');
    inv.reload();
    timeline.reload();
  }

  return (
    <ResultGate result={inv.result} loadingLabel="Loading investigation…">
      {(v: any) => (
        <div>
          <div className="pagehead">
            <h1>{v.name || 'Investigation'}</h1>
            {v.analysis_id && <Link className="btn" to={`/analysis/${v.analysis_id}`}>Open analysis</Link>}
          </div>
          <div className="notice" style={{ marginBottom: '1rem' }}>
            Researcher notes and hypotheses are your workspace state. They never change finding severity, confidence,
            risk, validation, CVE state, remediation priority, or graph truth.
          </div>
          <nav className="filters" aria-label="Investigation sections">
            {SECTIONS.map((s) => (
              <button key={s} className={`btn ${section === s ? 'btn--primary' : ''}`} onClick={() => setSection(s)}>{s}</button>
            ))}
          </nav>

          {section === 'Overview' && (
            <div className="grid grid-4">
              {Object.entries(v.counts || {}).map(([k, val]) => (
                <div className="stat" key={k}><div className="stat__label">{k}</div><div className="stat__value">{String(val)}</div></div>
              ))}
            </div>
          )}

          {section === 'Findings' && (
            <div className="panel"><h3>Pinned findings</h3>
              {(v.findings || []).length === 0 ? <div className="state state--empty"><strong>NO PINNED FINDINGS</strong></div> :
                <ul>{v.findings.map((f: any, i: number) => <li key={i}>{f.rule_id || f.finding_id} <span className="muted">{f.title}</span></li>)}</ul>}
            </div>
          )}

          {section === 'Notes' && (
            <div className="panel">
              <h3>Notes <span className="pill">researcher</span></h3>
              <div className="filters">
                <input type="text" value={note} onChange={(e) => setNote(e.target.value)} placeholder="add a note…" style={{ minWidth: 320 }} />
                <button className="btn btn--primary" onClick={submitNote}>Add note</button>
              </div>
              <ul>{(v.notes || []).map((n: any, i: number) => <li key={i}>{n.body || n.text} <span className="muted">— {n.author || 'researcher'}</span></li>)}</ul>
            </div>
          )}

          {section === 'Hypotheses' && (
            <div className="panel">
              <h3>Hypotheses <span className="pill">researcher</span></h3>
              <div className="filters">
                <input type="text" value={hypo} onChange={(e) => setHypo(e.target.value)} placeholder="add a hypothesis…" style={{ minWidth: 320 }} />
                <button className="btn btn--primary" onClick={submitHypo}>Add hypothesis</button>
              </div>
              <ul>{(v.hypotheses || []).map((h: any, i: number) => (
                <li key={i}>{h.statement} <StatusBadge value={h.status || h.status_value} /></li>
              ))}</ul>
              <p className="muted" style={{ fontSize: '.8rem' }}>A hypothesis is researcher state — it never promotes itself into analytical truth.</p>
            </div>
          )}

          {section === 'Timeline' && (
            <div className="panel">
              <h3>Timeline</h3>
              <ResultGate result={timeline.result} emptyTitle="NO TIMELINE EVENTS">
                {(events: any[]) => (
                  <ul className="ev-list">
                    {events.map((e, i) => {
                      const researcher = RESEARCHER_EVENTS.has(String(e.event_type).toUpperCase());
                      return (
                        <li key={i} className="ev-item">
                          <span className="pill">{researcher ? '👤 researcher' : '⚙ machine'}</span>
                          <strong> {e.event_type}</strong> <span className="muted">{e.source}</span>
                          {e.mode && <StatusBadge value={e.mode} />}
                          <div className="ev-detail">{e.detail}</div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </ResultGate>
            </div>
          )}

          {section === 'Graph' && (
            <div className="panel"><h3>Pinned nodes / edges</h3>
              <p className="muted">nodes: {(v.nodes || []).length} · edges: {(v.edges || []).length}</p>
              <ul>{(v.nodes || []).slice(0, 40).map((n: any, i: number) => <li key={i}><span className="pill">{n.node_type || n.type}</span> {n.label || n.node_ref}</li>)}</ul>
            </div>
          )}

          {section === 'Export' && (
            <div className="panel">
              <h3>Export investigation</h3>
              <p className="muted">Exports call backend endpoints — no second export format is generated in the browser.</p>
              <div className="tag-row">
                {['json', 'markdown', 'graphml', 'dot'].map((fmt) => (
                  <a key={fmt} className="btn" href={investigationExportUrl(invId, fmt)}>{fmt.toUpperCase()}</a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </ResultGate>
  );
}

export function InvestigationWorkspace() {
  const { investigationId } = useParams();
  return <Body invId={investigationId!} />;
}
