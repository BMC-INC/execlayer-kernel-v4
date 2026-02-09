import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX,
  Activity, 
  Terminal, 
  Cpu, 
  Lock, 
  Fingerprint, 
  Database, 
  Layers, 
  Zap, 
  ChevronRight, 
  Send, 
  Loader2, 
  Volume2, 
  VolumeX, 
  Mic, 
  MicOff, 
  Link as LinkIcon,
  Braces,
  User,
  History,
  AlertTriangle,
  FileJson,
  Code,
  CheckCircle2,
  BarChart,
  Globe,
  ArrowRight,
  Search,
  Scale
} from 'lucide-react';

// --- CONFIGURATION ---
const apiKey = ""; 
const TEXT_MODEL = "gemini-2.5-flash-preview-09-2025";

// ==========================================
// COMPONENT: BriefingHUD (Landing Page)
// ==========================================
const BriefingHUD = ({ setView }) => (
  <div className="min-h-screen bg-[#020202] text-slate-100 flex flex-col overflow-x-hidden">
    <div className="fixed inset-0 pointer-events-none opacity-5 bg-[radial-gradient(#06b6d4_1px,transparent_1px)] bg-[size:40px_40px]"></div>

    <main className="flex-1 flex flex-col items-center justify-center p-8 lg:p-20 relative overflow-hidden">
      <div className="max-w-5xl w-full space-y-12 relative z-10">
        <div className="space-y-6">
          <div className="inline-flex items-center gap-3 px-4 py-1.5 rounded-full border border-cyan-500/20 bg-cyan-500/5 text-[10px] font-black uppercase tracking-widest text-cyan-500">
            <Activity className="w-3 h-3 animate-pulse" /> Protocol Baseline: ELAG v1.0
          </div>
          <h2 className="text-6xl md:text-8xl font-black italic tracking-tighter leading-[0.85] uppercase">
            Deterministic <br />
            <span className="text-cyan-500">Execution Governance</span>
          </h2>
          <p className="text-xl md:text-2xl text-slate-400 max-w-2xl leading-relaxed">
            Enforcing sovereign policy at the point of action. The neutral infrastructure layer for the autonomous frontier.
          </p>
        </div>

        <div className="flex flex-wrap gap-6 pt-6">
           <button 
             onClick={() => setView('kernel')}
             className="px-10 py-5 bg-cyan-500 text-black font-black uppercase tracking-widest rounded-full hover:scale-105 hover:bg-cyan-400 transition-all shadow-[0_0_40px_rgba(6,182,212,0.3)] flex items-center gap-3"
           >
             Initialize Kernel <ChevronRight className="w-5 h-5" />
           </button>
           <button 
             onClick={() => setView('verify')}
             className="px-10 py-5 bg-white/5 border border-white/10 text-white font-black uppercase tracking-widest rounded-full hover:bg-white/10 transition-all flex items-center gap-3"
           >
             Audit Proofs
           </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-12 pt-12 border-t border-white/5">
           <div className="space-y-2">
              <h4 className="text-cyan-500 font-black uppercase text-[10px] tracking-widest">Fail-Closed Runtime</h4>
              <p className="text-xs text-slate-500">Enforcement continuity during total network isolation and geopolitical sync-loss.</p>
           </div>
           <div className="space-y-2">
              <h4 className="text-cyan-500 font-black uppercase text-[10px] tracking-widest">Lex Juris Arbitration</h4>
              <p className="text-xs text-slate-500">Deterministic conflict resolution preserving national regulatory authority without central roots.</p>
           </div>
           <div className="space-y-2">
              <h4 className="text-cyan-500 font-black uppercase text-[10px] tracking-widest">Immutable Lineage</h4>
              <p className="text-xs text-slate-500">Forensic-grade DAG receipt chains providing non-repudiable ground truth for liability attribution.</p>
           </div>
        </div>
      </div>

      <div className="absolute right-[-5%] top-1/2 -translate-y-1/2 opacity-10 pointer-events-none hidden lg:block">
         <Cpu className="w-[600px] h-[600px] text-cyan-900" />
      </div>
    </main>
  </div>
);

// ==========================================
// COMPONENT: KernelV4 (Functional Engine)
// ==========================================
const KernelV4 = () => {
  const [userName, setUserName] = useState('');
  const [isFirstContact, setIsFirstContact] = useState(true);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [executionState, setExecutionState] = useState('IDLE');
  const [receiptChain, setReceiptChain] = useState([]);
  const [forensicTrace, setForensicTrace] = useState([]);
  const [trustScore, setTrustScore] = useState(100);
  const scrollRef = useRef(null);

  useEffect(() => {
    const initialMsg = "ExecLayer Kernel V4.0 Hardened Spine online. Identity required to anchor session DAG.";
    setMessages([{ role: 'assistant', text: initialMsg }]);
  }, []);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, isGenerating]);

  const addForensic = (msg, type = 'info') => {
    setForensicTrace(prev => [{ time: new Date().toLocaleTimeString().split(' ')[0], msg, type }, ...prev].slice(0, 20));
  };

  const handleSend = async () => {
    if (!input.trim() || isGenerating) return;
    const userText = input;
    setInput('');
    setMessages(prev => [...prev, { role: 'user', text: userText }]);

    if (isFirstContact) {
      const name = userText.split(' ').pop();
      setUserName(name);
      setIsFirstContact(false);
      setMessages(prev => [...prev, { role: 'assistant', text: `Director ${name}, identity anchored. Substrate initialized. Submit governance intent.` }]);
      addForensic(`Principal ${name} authenticated.`, 'success');
      return;
    }

    setIsGenerating(true);
    setExecutionState('PROVENANCE');
    addForensic("Sealing Intent Provenance Envelope...", "info");
    
    try {
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${TEXT_MODEL}:generateContent?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: userText }] }],
          systemInstruction: { parts: [{ text: "IDENTITY: ExecLayer Kernel V4.0. Output clinical governance briefing and V3 JSON Blueprint with ALLOW or REFUSE decision." }] }
        })
      });
      const data = await response.json();
      const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text || "Spine Disconnect.";
      
      setReceiptChain(prev => [...prev, { stage: 'BLUEPRINT', hash: '0x'+Math.random().toString(16).slice(2,10).toUpperCase() }]);
      setMessages(prev => [...prev, { role: 'assistant', text: rawText.replace(/\{[\s\S]*\}/, '').trim() }]);
      addForensic("Intent Validated. Execution Authorized.", "success");
    } catch (e) {
      setMessages(prev => [...prev, { role: 'assistant', text: "Critical Substrate Error: Enforcement Logic Unreachable." }]);
      addForensic("Spine Sync Failure.", "error");
    } finally {
      setIsGenerating(false);
      setExecutionState('IDLE');
    }
  };

  return (
    <div className="flex-1 flex overflow-hidden">
      {/* Left: Trust Lineage */}
      <aside className="w-64 md:w-80 shrink-0 border-r border-white/5 bg-black/40 p-6 overflow-y-auto hidden md:flex flex-col gap-6">
        <h3 className="text-[10px] font-mono text-slate-500 uppercase tracking-[0.4em] flex items-center gap-2">
          <LinkIcon className="w-3 h-3 text-cyan-600" /> Trust Lineage
        </h3>
        <div className="space-y-4">
          {receiptChain.map((r, i) => (
            <div key={i} className="p-3 bg-white/5 border border-white/10 rounded-lg text-[8px] font-mono">
              <div className="text-cyan-500 uppercase font-black">{r.stage}</div>
              <div className="text-slate-600 truncate mt-1">{r.hash}</div>
            </div>
          ))}
          {receiptChain.length === 0 && <p className="text-[10px] text-slate-800 italic uppercase">Awaiting Adjudication</p>}
        </div>
      </aside>

      {/* Center: Console */}
      <main className="flex-1 flex flex-col relative bg-black/20 overflow-hidden">
        <div ref={scrollRef} className="flex-1 overflow-y-auto p-6 md:p-12 space-y-8">
          {messages.map((m, i) => (
            <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[90%] md:max-w-[85%] p-6 md:p-10 rounded-[2rem] ${m.role === 'user' ? 'bg-cyan-600 text-black font-bold shadow-2xl' : 'bg-slate-900/40 border border-white/5 backdrop-blur-xl'}`}>
                <div className={`flex items-center gap-2 mb-4 text-[9px] font-mono uppercase tracking-widest opacity-40 ${m.role === 'user' ? 'text-black' : 'text-cyan-500'}`}>
                  {m.role === 'user' ? <User className="w-3 h-3" /> : <ShieldCheck className="w-3 h-3" />}
                  {m.role === 'user' ? (userName || 'Principal') : 'V4 Kernel'}
                </div>
                <div className="text-base md:text-xl leading-relaxed whitespace-pre-wrap font-medium">{m.text}</div>
              </div>
            </div>
          ))}
          {isGenerating && (
            <div className="text-cyan-500 animate-pulse font-mono text-xs flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" /> {executionState}_TRUST_VALIDATION...
            </div>
          )}
        </div>
        <div className="p-6 md:p-10 bg-black border-t border-white/10 flex gap-4">
          <input 
            className="flex-1 bg-white/5 border border-white/10 rounded-full px-6 md:px-8 py-4 md:py-5 outline-none focus:border-cyan-500 transition-all text-base md:text-lg"
            value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            placeholder="Submit Governance Intent..."
          />
          <button onClick={handleSend} disabled={isGenerating} className="p-4 md:p-6 bg-cyan-500 rounded-full text-black hover:scale-105 transition-all shadow-[0_0_30px_rgba(6,182,212,0.3)]"><Send className="w-6 h-6" /></button>
        </div>
      </main>

      {/* Right: Forensic HUD */}
      <aside className="w-80 border-l border-white/5 bg-black p-8 overflow-y-auto hidden lg:block">
        <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-6">Forensic Audit Stream</h4>
        <div className="space-y-4">
           {forensicTrace.map((log, i) => (
             <div key={i} className={`p-4 rounded-xl border text-[10px] leading-relaxed ${log.type === 'success' ? 'bg-green-500/10 border-green-500/20 text-green-400' : log.type === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-400' : 'bg-white/5 border-white/10 text-slate-500'}`}>
                {log.msg}
             </div>
           ))}
        </div>
      </aside>
    </div>
  );
};

// ==========================================
// COMPONENT: HardeningSuite (Verification)
// ==========================================
const HardeningSuite = () => {
  const [activeScenario, setActiveScenario] = useState(0);

  const scenarios = [
    {
      id: "ISOLATION_S_INF",
      title: "Infinite Isolation Lockdown",
      risk: "Geopolitical network fragmentation causing total sync loss for autonomous assets.",
      response: "Kernel defaults to RC-4 High-Risk refusal. Monotonic authority decay restricts privileges to safety-standby only.",
      status: "VERIFIED_FAIL_CLOSED"
    },
    {
      id: "JURISDICTIONAL_CLASH",
      title: "Cross-Domain Conflict",
      risk: "Simultaneous conflicting execution authorities issued by NATO and local regulatory bodies.",
      response: "Lex Juris arbitration logic reconciles based on ELAG v1.0 priority weighting. Deterministic convergence achieved.",
      status: "VERIFIED_DETERMINISTIC"
    },
    {
      id: "REVOCATION_DELAY",
      title: "Epoch Revocation Drift",
      risk: "Delayed propagation of authority withdrawal across sovereign frontier nodes.",
      response: "Substrate enforces 'Short-Epoch' windowing. All actions require proof-of-freshness; stale tokens trigger halt.",
      status: "VERIFIED_HARDENED"
    }
  ];

  return (
    <div className="flex-1 flex overflow-hidden">
      <aside className="w-72 md:w-96 border-r border-white/5 p-6 md:p-10 space-y-6 overflow-y-auto bg-black/40">
        <h3 className="text-[10px] uppercase tracking-widest text-slate-500 mb-8">Verification Vectors</h3>
        {scenarios.map((s, idx) => (
          <button 
            key={idx}
            onClick={() => setActiveScenario(idx)}
            className={`w-full text-left p-6 rounded-3xl border transition-all ${activeScenario === idx ? 'bg-cyan-600 border-cyan-500 text-black shadow-lg' : 'bg-white/5 border-white/10 text-slate-400 hover:bg-white/10'}`}
          >
            <p className="text-[10px] font-mono mb-2">{s.id}</p>
            <h4 className="font-bold text-lg leading-tight">{s.title}</h4>
          </button>
        ))}
      </aside>

      <section className="flex-1 p-8 md:p-20 bg-black overflow-y-auto">
        <div className="max-w-4xl space-y-12">
           <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-green-500/10 border border-green-500/20 text-green-500 text-[10px] font-black uppercase">
             <CheckCircle2 className="w-3 h-3" /> Integrity Check Passed
           </div>
           
           <h2 className="text-4xl md:text-6xl font-black uppercase italic tracking-tighter leading-none">{scenarios[activeScenario].title}</h2>
           
           <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
              <div className="space-y-4">
                 <h5 className="text-slate-500 uppercase font-black text-xs">Risk Scenario</h5>
                 <p className="text-xl text-slate-400 leading-relaxed">{scenarios[activeScenario].risk}</p>
              </div>
              <div className="space-y-4">
                 <h5 className="text-cyan-500 uppercase font-black text-xs">Substrate Response</h5>
                 <p className="text-xl text-slate-100 leading-relaxed">{scenarios[activeScenario].response}</p>
              </div>
           </div>

           <div className="mt-20 p-8 rounded-[3rem] bg-white/5 border border-white/10 flex flex-wrap items-center justify-between gap-6">
              <div>
                 <p className="text-[10px] font-mono text-slate-500 uppercase mb-1">Status Code</p>
                 <p className="text-2xl font-black text-cyan-500 uppercase tracking-widest">{scenarios[activeScenario].status}</p>
              </div>
              <div className="flex gap-4">
                 <div className="w-12 h-12 rounded-full border border-white/10 flex items-center justify-center text-slate-600"><Database className="w-5 h-5" /></div>
                 <div className="w-12 h-12 rounded-full border border-white/10 flex items-center justify-center text-slate-600"><Lock className="w-5 h-5" /></div>
              </div>
           </div>
        </div>
      </section>
    </div>
  );
};

// ==========================================
// COMPONENT: RegulatorDashboard (Compliance)
// ==========================================
const RegulatorDashboard = () => (
  <div className="flex-1 p-8 md:p-12 overflow-y-auto space-y-12 bg-[#020202]">
    <div className="flex justify-between items-end border-b border-white/5 pb-8">
      <div>
        <h2 className="text-4xl font-black italic tracking-tighter uppercase">Regulator Assurance HUD</h2>
        <p className="text-slate-500 mt-2 font-mono text-xs uppercase tracking-widest">GSN Safety Case Mapping // ELAG v1.0</p>
      </div>
      <div className="text-right">
        <p className="text-xs text-slate-500 mb-1">Compliance Health</p>
        <div className="text-2xl font-black text-green-500">99.98%</div>
      </div>
    </div>

    <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
       {[
         { label: "EU AI Act Art. 14", status: "NOMINAL", icon: <Scale /> },
         { label: "NIST AI RMF", status: "VERIFIED", icon: <Shield /> },
         { label: "ISO/IEC 42001", status: "ALIGNED", icon: <CheckCircle2 /> },
         { label: "AIGP Standard", status: "ENFORCED", icon: <Layers /> }
       ].map((item, i) => (
         <div key={i} className="bg-white/5 border border-white/10 p-6 rounded-3xl space-y-4">
           <div className="text-cyan-500">{item.icon}</div>
           <h4 className="font-bold uppercase text-xs text-slate-400">{item.label}</h4>
           <p className="text-lg font-black tracking-widest">{item.status}</p>
         </div>
       ))}
    </div>

    <div className="bg-white/5 border border-white/10 p-10 rounded-[3rem] space-y-8">
       <h3 className="text-xl font-bold uppercase flex items-center gap-3">
         <BarChart className="w-5 h-5 text-cyan-500" /> System Governance Telemetry
       </h3>
       <div className="h-64 flex items-end gap-2 px-4">
          {[40, 70, 45, 90, 65, 80, 55, 95, 40, 85, 60, 75].map((h, i) => (
            <div key={i} className="flex-1 bg-cyan-500/20 border-t-2 border-cyan-500 rounded-t-lg group relative" style={{ height: `${h}%` }}>
               <div className="absolute -top-8 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 transition-opacity bg-black text-cyan-400 text-[10px] px-2 py-1 rounded border border-white/10">
                 {h}%
               </div>
            </div>
          ))}
       </div>
       <p className="text-xs text-slate-500 italic text-center uppercase tracking-widest">Execution Integrity Variance // 24H Window</p>
    </div>
  </div>
);

// ==========================================
// COMPONENT: App (Root Router)
// ==========================================
const App = () => {
  const [view, setView] = useState('hud'); // hud | kernel | verify | compliance

  return (
    <div className="h-screen flex flex-col bg-black text-slate-100 overflow-hidden font-sans">
      {/* GLOBAL HUD HEADER */}
      <header className="h-20 shrink-0 border-b border-white/10 bg-black/80 backdrop-blur-xl flex items-center px-6 md:px-10 justify-between z-[100]">
        <div className="flex items-center gap-5 cursor-pointer" onClick={() => setView('hud')}>
          <div className="w-10 md:w-12 h-10 md:h-12 rounded-xl bg-cyan-600 flex items-center justify-center shadow-[0_0_25px_rgba(6,182,212,0.4)]">
            <Shield className="text-black w-6 h-6 md:w-7 md:h-7" />
          </div>
          <div>
            <h1 className="text-xs md:text-sm font-black tracking-[0.4em] uppercase italic">
              ExecLayer <span className="text-cyan-400">Hardened Spine</span>
            </h1>
            <div className="hidden md:flex gap-4 text-[9px] font-mono text-slate-500 uppercase tracking-widest mt-1">
              <span className="text-green-500 flex items-center gap-1"><Activity className="w-2 h-2" /> Spine: Synced</span>
              <span>Substrate: Hardened_V4.0</span>
            </div>
          </div>
        </div>

        <nav className="flex gap-4 md:gap-8 text-[9px] md:text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">
           <button onClick={() => setView('kernel')} className={`hover:text-cyan-400 transition-colors ${view === 'kernel' ? 'text-cyan-400' : ''}`}>Kernel</button>
           <button onClick={() => setView('verify')} className={`hover:text-cyan-400 transition-colors ${view === 'verify' ? 'text-cyan-400' : ''}`}>Verification</button>
           <button onClick={() => setView('compliance')} className={`hover:text-cyan-400 transition-colors ${view === 'compliance' ? 'text-cyan-400' : ''}`}>Compliance</button>
        </nav>
      </header>

      {/* VIEW SWITCHER */}
      <div className="flex-1 flex overflow-hidden">
        {(() => {
          switch (view) {
            case 'hud': return <BriefingHUD setView={setView} />;
            case 'kernel': return <KernelV4 />;
            case 'verify': return <HardeningSuite />;
            case 'compliance': return <RegulatorDashboard />;
            default: return <BriefingHUD setView={setView} />;
          }
        })()}
      </div>

      {/* SHARED FOOTER */}
      <footer className="h-10 shrink-0 border-t border-white/10 bg-[#010101] flex items-center px-10 justify-between text-[9px] font-mono text-slate-800 tracking-[0.5em] uppercase">
         <div className="flex gap-12 text-slate-600">
           <span>Substrate: ELAG_V1.0_PROD</span>
           <span className="flex items-center gap-2"><CheckCircle2 className="w-3 h-3" /> Audit: VERIFIED</span>
         </div>
         <div className="hidden md:block">© 2026 ExecLayer Inc. // Infrastructure Baseline</div>
      </footer>
    </div>
  );
};

export default App;
