import React, { useEffect, useRef, useState, useCallback } from 'react';

// ---------- helpers ----------
function scoreColor(v) {
  if (v >= 85) return '#39e991';
  if (v >= 65) return '#e9c93a';
  if (v >= 45) return '#e98b3a';
  return '#ff4d5e';
}

function ScoreRing({ value, delta }) {
  const r = 74;
  const c = 2 * Math.PI * r;
  const off = c * (1 - value / 100);
  const color = scoreColor(value);
  return (
    <div className="ring-wrap">
      <svg width="180" height="180" viewBox="0 0 180 180">
        <circle cx="90" cy="90" r={r} className="ring-track" />
        <circle
          cx="90" cy="90" r={r}
          className="ring-value"
          stroke={color}
          strokeDasharray={c}
          strokeDashoffset={off}
          transform="rotate(-90 90 90)"
        />
      </svg>
      <div className="ring-center">
        <div className="ring-num" style={{ color }}>{value}</div>
        <div className="ring-label">SECURITY SCORE</div>
        {delta !== 0 && (
          <div className="ring-delta" style={{ color: delta > 0 ? '#39e991' : '#ff4d5e' }}>
            {delta > 0 ? '▲ +' : '▼ '}{delta}
          </div>
        )}
      </div>
    </div>
  );
}

function Feed({ side, title, items }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [items]);
  return (
    <div className={`console ${side}`}>
      <div className="console-head">
        <span className="dot" /> {title}
      </div>
      <div className="console-body" ref={ref}>
        {items.length === 0 && <div className="idle">// standing by…</div>}
        {items.map((it) => <FeedItem key={it.seq} it={it} side={side} />)}
      </div>
    </div>
  );
}

function FeedItem({ it, side }) {
  if (it.type === 'phase') {
    return <div className={`ln phase ${side}`}>▮ {it.text}</div>;
  }
  if (it.type === 'attack') {
    const cls = it.success ? 'attack hit' : 'attack blocked';
    return (
      <div className={`ln ${cls}`}>
        <div className="attack-title">
          {it.success ? '⛒ EXPLOIT' : '⛨ BLOCKED'} — {it.name}
          <span className="badge">HTTP {it.status}</span>
        </div>
        <div className="attack-req">{it.request}</div>
        <div className="attack-ev">{it.evidence}</div>
      </div>
    );
  }
  if (it.type === 'patch') {
    return <div className="ln patch">⟳ patch → {it.file} <span className="src">{it.source}</span></div>;
  }
  const tone = it.tone ? `tone-${it.tone}` : '';
  return <div className={`ln log ${tone}`}>{it.text}</div>;
}

function HistoryPanel({ runs, persisted }) {
  if (!persisted) {
    return (
      <div className="history empty">
        <div className="history-head">BATTLE HISTORY <span className="diff-tag">Supabase not connected — history is per-session only</span></div>
      </div>
    );
  }
  return (
    <div className="history">
      <div className="history-head">BATTLE HISTORY <span className="diff-tag">persisted in Supabase</span></div>
      <div className="history-rows">
        {runs.length === 0 && <div className="idle" style={{ padding: '10px 14px' }}>// no completed runs yet</div>}
        {runs.map((r) => (
          <div className="history-row" key={r.id}>
            <span className="history-score" style={{ color: scoreColor(r.final_score ?? r.initial_score) }}>
              {r.final_score ?? '…'}
            </span>
            <span className="history-delta">{r.initial_score} → {r.final_score ?? '?'}</span>
            <span className="history-patched">{(r.patched || []).join(', ') || 'in progress'}</span>
            <span className="history-time">{new Date(r.started_at).toLocaleTimeString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DiffPanel({ patch }) {
  if (!patch) {
    return (
      <div className="diff empty">
        <div className="diff-head">LIVE CODE REMEDIATION</div>
        <div className="diff-idle">// Blue Team patches will appear here — real code, applied to the running sandbox.</div>
      </div>
    );
  }
  return (
    <div className="diff">
      <div className="diff-head">
        LIVE CODE REMEDIATION
        <span className="diff-file">{patch.file}</span>
        <span className="diff-tag">{patch.label} · {patch.source}</span>
      </div>
      <div className="diff-cols">
        <pre className="code before"><span className="code-tag">BEFORE — vulnerable</span>{patch.before}</pre>
        <pre className="code after"><span className="code-tag">AFTER — hardened</span>{patch.after}</pre>
      </div>
    </div>
  );
}

// ---------- app ----------
export default function App() {
  const [events, setEvents] = useState([]);
  const [red, setRed] = useState([]);
  const [blue, setBlue] = useState([]);
  const [sys, setSys] = useState([]);
  const [score, setScore] = useState(100);
  const [delta, setDelta] = useState(0);
  const [running, setRunning] = useState(false);
  const [patch, setPatch] = useState(null);
  const [meta, setMeta] = useState({ llm: false, model: '', app: 'Banking API Demo', persisted: false });
  const [summary, setSummary] = useState(null);
  const [patchCount, setPatchCount] = useState(0);
  const [openVulns, setOpenVulns] = useState(0);
  const [history, setHistory] = useState([]);

  const refreshHistory = useCallback(async () => {
    try {
      const res = await fetch('/api/history');
      const data = await res.json();
      setHistory(data.runs || []);
      setMeta((m) => ({ ...m, persisted: data.persisted }));
    } catch { /* history is a nice-to-have, never block the demo on it */ }
  }, []);

  const handle = useCallback((e) => {
    setEvents((prev) => [...prev, e]);
    switch (e.type) {
      case 'run_start':
        setRed([]); setBlue([]); setSys([]); setPatch(null); setSummary(null);
        setScore(40); setDelta(0); setRunning(true); setPatchCount(0); setOpenVulns(2);
        setMeta((m) => ({ ...m, llm: e.llm, model: e.model, app: e.app || m.app }));
        break;
      case 'score':
        setScore(e.value); setDelta(e.delta);
        break;
      case 'attack':
        setRed((p) => [...p, e]);
        if (e.phase === 'retest' && !e.success) setOpenVulns((v) => Math.max(0, v - 1));
        break;
      case 'patch':
        setBlue((p) => [...p, e]); setPatch(e); setPatchCount((c) => c + 1);
        break;
      case 'run_end':
        setRunning(false); setSummary(e); setSys((p) => [...p, { ...e, type: 'phase', text: e.summary }]);
        setTimeout(refreshHistory, 400); // give the DB write a beat to land
        break;
      case 'phase':
      case 'log':
        if (e.agent === 'red') setRed((p) => [...p, e]);
        else if (e.agent === 'blue') setBlue((p) => [...p, e]);
        else setSys((p) => [...p, e]);
        break;
      default:
        break;
    }
  }, [refreshHistory]);

  useEffect(() => {
    const es = new EventSource('/api/stream');
    es.onmessage = (msg) => {
      try { handle(JSON.parse(msg.data)); } catch { /* keepalive */ }
    };
    return () => es.close();
  }, [handle]);

  useEffect(() => { refreshHistory(); }, [refreshHistory]);

  useEffect(() => {
    fetch('/api/status').then((r) => r.json()).then((s) => {
      setMeta((m) => ({ ...m, llm: s.llm, model: s.model, persisted: s.persisted }));
    }).catch(() => {});
  }, []);

  const start = async () => {
    setRunning(true);
    try { await fetch('/api/simulate/start', { method: 'POST' }); }
    catch { setRunning(false); }
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-red">RED</span>
          <span className="brand-vs">//</span>
          <span className="brand-blue">TEAM</span>
          <span className="brand-sub">Autonomous Cyber Range</span>
        </div>
        <div className="chips">
          <span className="chip">🎯 {meta.app}</span>
          <span className={`chip ${meta.llm ? 'live' : ''}`}>
            {meta.llm ? `🧠 ${meta.model}` : '🧠 fallback mode'}
          </span>
          <span className={`chip ${meta.persisted ? 'live' : ''}`}>
            {meta.persisted ? '💾 Supabase' : '💾 in-memory only'}
          </span>
          <button className="start-btn" onClick={start} disabled={running}>
            {running ? '● RUNNING…' : '▶ LAUNCH SIMULATION'}
          </button>
        </div>
      </header>

      <div className="stage">
        <Feed side="red" title="RED TEAM · OFFENSE" items={red} />

        <div className="center">
          <ScoreRing value={score} delta={delta} />
          <div className="stat-row">
            <div className="stat"><b>{openVulns}</b><span>open vulns</span></div>
            <div className="stat"><b>{patchCount}</b><span>patches</span></div>
          </div>
          {summary && (
            <div className={`verdict ${summary.patched?.length === 2 ? 'ok' : 'warn'}`}>
              {summary.patched?.length === 2 ? '✔ HARDENED' : '⚠ RESIDUAL FINDINGS'}
              <div className="verdict-sub">{summary.summary}</div>
            </div>
          )}
          <div className="sysfeed">
            {sys.length === 0 && <div className="idle center-idle">Orchestrator idle. Launch a simulation to begin the battle.</div>}
            {sys.map((s) => (
              <div key={s.seq ?? Math.random()} className={`sysln ${s.type === 'phase' ? 'sysphase' : ''}`}>{s.text}</div>
            ))}
          </div>
        </div>

        <Feed side="blue" title="BLUE TEAM · DEFENSE" items={blue} />
      </div>

      <DiffPanel patch={patch} />
      <HistoryPanel runs={history} persisted={meta.persisted} />
    </div>
  );
}
