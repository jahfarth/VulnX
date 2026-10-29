import { useEffect, useMemo, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function App() {
  const [target, setTarget] = useState('http://127.0.0.1:8080');
  const [scans, setScans] = useState([]);
  const [active, setActive] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function refreshScans() {
    try {
      const res = await fetch(`${API}/api/scans`);
      if (!res.ok) throw new Error('Could not load scan history');
      setScans(await res.json());
      setError('');
    } catch (e) { setError('Backend not reachable. Start FastAPI at http://127.0.0.1:8000.'); }
  }

  useEffect(() => { refreshScans(); }, []);

  async function runScan(e) {
    e.preventDefault();
    setBusy(true); setError(''); setActive(null);
    try {
      const res = await fetch(`${API}/api/scans`, {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({target})
      });
      const data = await res.json();
      if (!res.ok) throw new Error(formatApiError(data.detail) || 'Assessment failed');
      setActive(data);
      await refreshScans();
    } catch (e) { setError(e instanceof TypeError ? 'Cannot reach FastAPI. Start the backend at http://127.0.0.1:8000 on this computer.' : (e.message || 'Assessment failed')); }
    finally { setBusy(false); }
  }

  async function openScan(id) {
    setError('');
    try {
      const res = await fetch(`${API}/api/scans/${id}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Could not open scan');
      setActive(data);
    } catch (e) { setError(e.message); }
  }

  async function loadDemo() {
    setBusy(true); setError('');
    try {
      const res = await fetch(`${API}/api/demos`, {method:'POST'});
      const data = await res.json();
      if (!res.ok) throw new Error(formatApiError(data.detail) || 'Could not load demo');
      setActive(data); await refreshScans();
    } catch(e) { setError(e.message || 'Demo failed'); }
    finally { setBusy(false); }
  }

  const simulated = active?.assessment_kind === 'simulated';
  const findings = active?.findings || [];
  const severityData = useMemo(() => {
    const counts = {Critical:0, High:0, Medium:0, Low:0, Informational:0};
    findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    return Object.entries(counts).map(([severity, count]) => ({severity, count}));
  }, [active]);

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-icon">V</span><div><strong>VulnX</strong><small>SECURITY INTELLIGENCE</small></div></div>
      <div className="nav-label">WORKSPACE</div>
      <div className="nav-item selected">▦ &nbsp; Overview</div>
      <div className="nav-item">⌕ &nbsp; Assessments</div>
      <div className="nav-item">◈ &nbsp; Risk Prioritization</div>
      <div className="nav-item">▤ &nbsp; Reports</div>
      <div className="sidebar-note"><span className="dot"></span> Local assessment mode <small>Only loopback targets are allowed</small></div>
    </aside>
    <main className="main">
      <header className="topbar"><div><span className="eyebrow">SECURITY OPERATIONS / OVERVIEW</span><h1>Vulnerability overview</h1><p>Assess local test targets and prioritize security findings.</p></div><div className="status-pill"><span className="dot"></span> Local API workspace</div></header>
      {error && <div className="alert">{error}</div>}
      <section className="notice"><strong>Academic MVP · Local-only scanner</strong><span>This prototype performs basic HTTP response-header checks and probes a fixed list of well-known exposed sensitive files. It is not a full security scan.</span></section>
      <section className="panel scan-panel">
        <div className="section-head"><div><h2>New assessment</h2><p>Enter a local target that you own or are authorized to test.</p></div><span className="tag">SAFE MODE</span></div>
        <form onSubmit={runScan} className="scan-form">
          <label htmlFor="target">Target URL</label>
          <div className="input-row"><input id="target" value={target} onChange={e=>setTarget(e.target.value)} placeholder="http://127.0.0.1:8080" required/><button disabled={busy}>{busy ? 'Assessing…' : '▶ Run assessment'}</button></div>
          <small>Allowed hosts: localhost, 127.0.0.1, and ::1.</small>
        </form>
      </section>
      <section className="notice"><strong>High/Critical training examples</strong><span>Separate synthetic data, never a real vulnerability assessment.</span><button type="button" disabled={busy} onClick={loadDemo}>Load simulated demo</button></section>
      {simulated && <div className="alert" role="status"><strong>SIMULATED DEMO - NOT REAL FINDINGS.</strong> No target was scanned. All severity, evidence and risk inputs below are invented training examples.</div>}
      <section className="metrics">
        <Metric label="ASSESSMENTS" value={scans.filter(s=>s.assessment_kind !== 'simulated').length} note="Real completed assessments only"/>
        <Metric label={simulated ? "SIMULATED FINDINGS" : "FINDINGS IN VIEW"} value={findings.length} note="Selected assessment"/>
        <Metric label={simulated ? "SIMULATED HIGH / CRITICAL" : "HIGH / CRITICAL"} value={findings.filter(f=>['High','Critical'].includes(f.severity)).length} note={simulated ? "Invented examples, not detections" : "Non-zero only when exposure evidence is observed"}/>
        <Metric label="TOP RISK SCORE" value={findings.length ? Math.max(...findings.map(f=>f.risk_score)).toFixed(1) : '—'} note="Illustrative 0–10 score"/>
      </section>
      <section className="content-grid">
        <div className="panel chart-panel"><div className="section-head"><div><h2>Severity distribution</h2><p>{simulated ? "Synthetic training examples only" : "Findings from the selected assessment"}</p></div></div>
          {findings.length ? <ResponsiveContainer width="100%" height={250}><BarChart data={severityData} margin={{top:12,right:12,left:-20,bottom:0}}><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#26344b"/><XAxis dataKey="severity" stroke="#91a0b8" tick={{fontSize:11}}/><YAxis allowDecimals={false} stroke="#91a0b8" tick={{fontSize:11}}/><Tooltip contentStyle={{background:'#111d30',border:'1px solid #2a3b55',borderRadius:8}}/><Bar dataKey="count" fill="#62d8c5" radius={[5,5,0,0]}/></BarChart></ResponsiveContainer> : <Empty>Run an assessment to populate the chart.</Empty>}
        </div>
        <div className="panel history-panel"><div className="section-head"><div><h2>Recent assessments</h2><p>Click a scan to view its findings</p></div></div>
          {scans.length ? <div className="history-list">{scans.slice(0,6).map(s=><button className={`history-item ${active?.id===s.id?'active':''}`} key={s.id} onClick={()=>openScan(s.id)}><span className="history-icon">⌁</span><span className="history-text"><strong>{s.assessment_kind === 'simulated' ? '[SIMULATED] Training examples' : s.target}</strong><small>{new Date(s.created_at).toLocaleString()}</small></span><span className="history-count">{s.total_findings}</span></button>)}</div> : <Empty>No saved assessments yet.</Empty>}
        </div>
      </section>
      <section className="panel findings-panel">
        <div className="section-head"><div><h2>{simulated ? "Simulated priorities - not real findings" : "Prioritized findings"}</h2><p>{active ? `Assessment #${active.id} · ${active.target}` : 'Run an assessment or select a saved scan'}</p></div>{active && <span className="tag">{active.status || 'Completed'}</span>}</div>
        {findings.length ? <div className="table-wrap"><table><thead><tr><th>FINDING</th><th>SEVERITY</th><th>RISK</th><th>PRIORITY</th><th>REMEDIATION</th></tr></thead><tbody>{[...findings].sort((a,b)=>b.risk_score-a.risk_score).map((f,i)=><tr key={f.id || `${f.title}-${i}`}><td><strong>{f.title}</strong><small className="description">{f.description}</small><small className="evidence">Evidence: {f.evidence}</small></td><td><span className={`severity ${f.severity.toLowerCase()}`}>{f.severity}</span></td><td><strong className="score">{Number(f.risk_score).toFixed(1)}</strong><small>/ 10</small></td><td><span className="priority">{f.priority}</span></td><td className="remediation">{f.remediation}</td></tr>)}</tbody></table></div> : <Empty>Nothing to show yet. Start an assessment against your local test server.</Empty>}
        {active?.limitations && <div className="limitations"><strong>Assessment limitations:</strong> {active.limitations}</div>}
      </section>
      <footer>VulnX · Academic prototype · Verify findings before taking remediation action.</footer>
    </main>
  </div>;
}

function Metric({label,value,note}) { return <div className="metric panel"><span>{label}</span><strong>{value}</strong><small>{note}</small></div>; }
function Empty({children}) { return <div className="empty">{children}</div>; }

function formatApiError(detail) {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map(item => item.msg || 'Invalid input').join('; ');
  return '';
}
