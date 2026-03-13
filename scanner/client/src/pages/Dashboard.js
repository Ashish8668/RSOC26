import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
const SEV_ORDER = {critical:0,high:1,medium:2,low:3,info:4};
const SEV_COLOR = {critical:'#ff4757',high:'#ff6b35',medium:'#ffa502',low:'#2ed573',info:'#1e90ff'};

export default function Dashboard() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const intervalRef = useRef(null);
  const feedRef = useRef(null);

  const fetchScan = async () => {
    try {
      const { data } = await axios.get(`${API_URL}/api/scan/${scanId}`);
      setScan(data);
      const sorted = (data.findings||[]).sort((a,b)=>(SEV_ORDER[a.severity]||5)-(SEV_ORDER[b.severity]||5));
      setFindings(sorted);
      setLoading(false);
      if (sorted.length > 0 && !selected) setSelected(sorted[0]);
      if (data.status==='completed'||data.status==='error') clearInterval(intervalRef.current);
    } catch(e){ setLoading(false); }
  };

  useEffect(()=>{ fetchScan(); intervalRef.current=setInterval(fetchScan,2000); return ()=>clearInterval(intervalRef.current); },[scanId]);
  useEffect(()=>{ if(feedRef.current) feedRef.current.scrollTop=feedRef.current.scrollHeight; },[findings.length]);

  const vulnerabilityTypes = ['all', ...Array.from(new Set(findings.map(f => f.type).filter(Boolean))).sort()];
  const filtered = findings.filter(f => (filter === 'all' || f.severity === filter) && (typeFilter === 'all' || f.type === typeFilter));
  const risk = scan?.summary ? Math.min(100,(scan.summary.critical||0)*10+(scan.summary.high||0)*7+(scan.summary.medium||0)*4+(scan.summary.low||0)*2) : 0;

  if (loading) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'calc(100vh - 60px)'}}><div style={{textAlign:'center'}}><div style={{fontSize:48,marginBottom:12}}>🔍</div><div style={{color:'#8b9bb8'}}>Loading scan...</div></div></div>;

  return (
    <div style={{height:'calc(100vh - 60px)',display:'flex',flexDirection:'column',overflow:'hidden'}}>
      {/* Top bar */}
      <div style={{padding:'14px 24px',borderBottom:'1px solid #2a3347',display:'flex',alignItems:'center',gap:14,flexShrink:0,background:'rgba(13,17,23,0.8)',backdropFilter:'blur(8px)'}}>
        <div style={{flex:1}}>
          <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4}}>
            <StatusPill status={scan?.status}/>
            <span style={{fontSize:12,fontFamily:'var(--font-mono)',color:'#8b9bb8'}}>{scan?.targetUrl}</span>
          </div>
          <ProgressBar progress={scan?.progress||0} module={scan?.currentModule} status={scan?.status}/>
          <div style={{fontSize:10,color:'#4a5568',marginTop:3,fontFamily:'var(--font-mono)'}}>
            {(scan?.summary?.critical||0)} Critical · {(scan?.summary?.high||0)} High · {(scan?.summary?.medium||0)} Medium
          </div>
        </div>
        <div style={{display:'flex',gap:6}}>
          {['critical','high','medium','low'].map(s=>(
            <div key={s} className={`badge badge-${s}`} style={{cursor:'pointer'}} onClick={()=>setFilter(filter===s?'all':s)}>
              {scan?.summary?.[s]||0} {s}
            </div>
          ))}
        </div>
        <div style={{padding:'8px 14px',borderRadius:10,background:risk>=70?'rgba(255,71,87,0.1)':risk>=40?'rgba(255,107,53,0.1)':'rgba(46,213,115,0.1)',border:`1px solid ${risk>=70?'rgba(255,71,87,0.3)':risk>=40?'rgba(255,107,53,0.3)':'rgba(46,213,115,0.3)'}`,textAlign:'center'}}>
          <div style={{fontSize:22,fontWeight:800,fontFamily:'var(--font-display)',color:risk>=70?'#ff4757':risk>=40?'#ff6b35':'#2ed573'}}>{risk}</div>
          <div style={{fontSize:9,color:'#8b9bb8',textTransform:'uppercase',letterSpacing:1}}>Risk</div>
        </div>
        {scan?.status==='completed'&&<button onClick={()=>navigate(`/report/${scanId}`)} style={{padding:'8px 18px',background:'#4f8ef7',border:'none',borderRadius:8,color:'white',cursor:'pointer',fontSize:13,fontWeight:600,fontFamily:'var(--font-body)'}}>View Report →</button>}
      </div>

      {/* Panels */}
      <div style={{flex:1,display:'grid',gridTemplateColumns:'340px 1fr',overflow:'hidden'}}>
        {/* Left: findings list */}
        <div style={{borderRight:'1px solid #2a3347',display:'flex',flexDirection:'column',overflow:'hidden'}}>
          <div style={{padding:'10px 12px',borderBottom:'1px solid #2a3347',display:'flex',gap:4,flexWrap:'wrap'}}>
            {['all','critical','high','medium','low'].map(f=>(
              <button key={f} onClick={()=>setFilter(f)} style={{padding:'3px 9px',borderRadius:6,border:'1px solid',cursor:'pointer',fontSize:10,fontWeight:600,fontFamily:'var(--font-mono)',textTransform:'uppercase',
                borderColor:filter===f?(SEV_COLOR[f]||'#4f8ef7'):'#2a3347',background:filter===f?`${(SEV_COLOR[f]||'#4f8ef7')}15`:'transparent',color:filter===f?(SEV_COLOR[f]||'#4f8ef7'):'#4a5568'}}>
                {f==='all'?`All (${findings.length})`:f}
              </button>
            ))}
            <select value={typeFilter} onChange={e=>setTypeFilter(e.target.value)} style={{marginLeft:'auto',background:'#0f1523',border:'1px solid #2a3347',borderRadius:6,color:'#8b9bb8',fontSize:11,padding:'2px 6px'}}>
              {vulnerabilityTypes.map(t => <option key={t} value={t}>{t === 'all' ? 'Type: All' : t}</option>)}
            </select>
          </div>
          <div style={{padding:'8px 10px',borderBottom:'1px solid #2a3347',maxHeight:140,overflowY:'auto'}}>
            <div style={{fontSize:10,color:'#4a5568',fontFamily:'var(--font-mono)',textTransform:'uppercase',letterSpacing:1,marginBottom:6}}>Live Feed</div>
            {(scan?.activity||[]).slice(-8).map((a, i) => (
              <div key={i} style={{fontSize:10,color:a.level==='error'?'#ff4757':a.level==='finding'?'#ffa502':'#8b9bb8',marginBottom:4,fontFamily:'var(--font-mono)'}}>
                [{new Date(a.at).toLocaleTimeString()}] {a.message}
              </div>
            ))}
          </div>
          <div ref={feedRef} style={{flex:1,overflowY:'auto',padding:6}}>
            {filtered.length===0&&<div style={{padding:20,textAlign:'center',color:'#4a5568',fontSize:13}}>{scan?.status==='running'?<><div style={{fontSize:20,marginBottom:6}}>⏳</div>Scanning {scan?.currentModule||'endpoints'}...</>:'No findings'}</div>}
            {filtered.map((f,i)=><FindingRow key={i} finding={f} isSelected={selected===f} onClick={()=>setSelected(f)}/>)}
            {scan?.status==='running'&&<div style={{margin:'6px',padding:'8px 10px',borderRadius:7,background:'rgba(79,142,247,0.05)',border:'1px solid rgba(79,142,247,0.2)',display:'flex',alignItems:'center',gap:7,fontSize:11,color:'#4f8ef7'}}>
              <div style={{width:5,height:5,borderRadius:'50%',background:'#4f8ef7',animation:'pulse-dot 1s ease-in-out infinite'}}/>Scanning {scan?.currentModule||'...'}
            </div>}
          </div>
        </div>
        {/* Right: detail */}
        <div style={{overflowY:'auto',padding:20}}>
          {selected?<FindingDetail finding={selected}/>:<div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'100%',color:'#4a5568',textAlign:'center'}}><div><div style={{fontSize:40,marginBottom:10}}>👈</div>Select a finding</div></div>}
        </div>
      </div>
    </div>
  );
}

function StatusPill({status}){
  const c={running:{color:'#4f8ef7',label:'SCANNING',pulse:true},discovering:{color:'#ffa502',label:'DISCOVERING',pulse:true},completed:{color:'#2ed573',label:'COMPLETED',pulse:false},error:{color:'#ff4757',label:'ERROR',pulse:false}}[status]||{color:'#8b9bb8',label:(status||'').toUpperCase(),pulse:false};
  return <div style={{display:'flex',alignItems:'center',gap:5,padding:'2px 9px',borderRadius:20,background:`${c.color}15`,border:`1px solid ${c.color}40`,fontSize:10,fontFamily:'var(--font-mono)',color:c.color,fontWeight:600}}>
    <div style={{width:5,height:5,borderRadius:'50%',background:c.color,animation:c.pulse?'pulse-dot 1.5s ease-in-out infinite':'none'}}/>{c.label}
  </div>;
}

function ProgressBar({progress,status,module}){
  const done=status==='completed';
  return <div><div style={{height:3,background:'#1e2535',borderRadius:2,overflow:'hidden'}}><div style={{height:'100%',width:`${progress||0}%`,background:done?'#2ed573':'linear-gradient(90deg,#4f8ef7,#7c3aed)',borderRadius:2,transition:'width 0.5s ease'}}/></div>
    <div style={{fontSize:10,color:'#4a5568',marginTop:2,fontFamily:'var(--font-mono)'}}>{progress}%{module?` · ${module}`:''}</div></div>;
}

function FindingRow({finding,isSelected,onClick}){
  const c=SEV_COLOR[finding.severity]||'#8b9bb8';
  return <div onClick={onClick} style={{padding:'9px 10px',borderRadius:7,marginBottom:3,cursor:'pointer',background:isSelected?'#1e2535':'transparent',border:`1px solid ${isSelected?c+'40':'transparent'}`}}
    onMouseEnter={e=>!isSelected&&(e.currentTarget.style.background='#161b27')} onMouseLeave={e=>!isSelected&&(e.currentTarget.style.background='transparent')}>
    <div style={{display:'flex',gap:7}}>
      <div style={{width:3,borderRadius:2,background:c,flexShrink:0}}/>
      <div style={{flex:1,minWidth:0}}>
        <div style={{fontSize:12,fontWeight:600,color:'#e8edf5',marginBottom:2,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{finding.title}</div>
        <div style={{fontSize:10,color:'#4a5568',fontFamily:'var(--font-mono)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{finding.method} {(finding.endpoint||'').replace(/^https?:\/\/[^/]+/,'')}</div>
        <div style={{display:'flex',alignItems:'center',gap:5,marginTop:3}}><span className={`badge badge-${finding.severity}`} style={{fontSize:9}}>{finding.severity}</span><span style={{fontSize:10,color:'#4a5568'}}>CVSS {finding.cvss_score}</span><span style={{fontSize:10,color:'#4a5568'}}>{finding.confidence||'Possible'}</span></div>
      </div>
    </div>
  </div>;
}

function FindingDetail({finding}){
  const c=SEV_COLOR[finding.severity]||'#8b9bb8';
  const [tab,setTab]=useState('overview');
  return <div style={{animation:'fadeInUp 0.2s ease'}}>
    <div style={{padding:18,background:'var(--bg-2)',borderRadius:11,border:`1px solid ${c}30`,marginBottom:14,borderLeft:`3px solid ${c}`}}>
      <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:7}}>
        <span className={`badge badge-${finding.severity}`}>{finding.severity}</span>
        <span style={{fontSize:10,color:'#4a5568',fontFamily:'var(--font-mono)'}}>CVSS {finding.cvss_score} · {finding.type} · {finding.confidence||'Possible'}</span>
      </div>
      <h2 style={{fontSize:17,fontWeight:700,color:'#e8edf5',marginBottom:5}}>{finding.title}</h2>
      <div style={{fontFamily:'var(--font-mono)',fontSize:11,color:'#4a5568'}}><span style={{color:'#4f8ef7'}}>{finding.method}</span> {finding.endpoint}</div>
    </div>
    <div style={{display:'flex',gap:4,marginBottom:14}}>
      {['overview','evidence','diff','remediation'].map(t=>(
        <button key={t} onClick={()=>setTab(t)} style={{padding:'5px 14px',borderRadius:7,border:'1px solid',cursor:'pointer',fontSize:12,fontWeight:500,fontFamily:'var(--font-body)',textTransform:'capitalize',
          borderColor:tab===t?'rgba(79,142,247,0.5)':'#2a3347',background:tab===t?'rgba(79,142,247,0.1)':'transparent',color:tab===t?'#4f8ef7':'#8b9bb8'}}>{t}</button>
      ))}
    </div>
    {tab==='overview'&&<div className="card">
      <p style={{fontSize:13,color:'#e8edf5',lineHeight:1.7,marginBottom:16}}>{finding.description}</p>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
        {[['Type',finding.type],['OWASP',finding.owasp||'API8:2023'],['CVSS Score',`${finding.cvss_score} / 10.0`],['Severity',(finding.severity||'').toUpperCase()]].map(([l,v])=>(
          <div key={l} style={{background:'var(--bg-3)',borderRadius:7,padding:'9px 12px'}}>
            <div style={{fontSize:10,color:'#4a5568',marginBottom:3,textTransform:'uppercase',letterSpacing:.5}}>{l}</div>
            <div style={{fontSize:12,fontWeight:600,color:'#e8edf5',fontFamily:'var(--font-mono)'}}>{v}</div>
          </div>
        ))}
      </div>
    </div>}
    {tab==='evidence'&&<div className="card">
      <pre style={{background:'var(--bg-3)',border:'1px solid var(--border)',borderRadius:7,padding:14,fontSize:11,fontFamily:'var(--font-mono)',color:'#e8edf5',overflow:'auto',lineHeight:1.6,whiteSpace:'pre-wrap',wordBreak:'break-all'}}>
        {JSON.stringify(finding.evidence||{},null,2)}
      </pre>
    </div>}
    {tab==='diff'&&<div className="card">
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
        <div>
          <div style={{fontSize:11,color:'#ff6b35',marginBottom:6,fontFamily:'var(--font-mono)'}}>Insecure / Actual</div>
          <pre style={{background:'var(--bg-3)',border:'1px solid rgba(255,107,53,0.2)',borderRadius:7,padding:10,fontSize:11,fontFamily:'var(--font-mono)',color:'#e8edf5',whiteSpace:'pre-wrap',wordBreak:'break-all'}}>
            {JSON.stringify(finding.replay?.insecure_response || finding.evidence || {}, null, 2)}
          </pre>
        </div>
        <div>
          <div style={{fontSize:11,color:'#2ed573',marginBottom:6,fontFamily:'var(--font-mono)'}}>Expected Secure</div>
          <pre style={{background:'var(--bg-3)',border:'1px solid rgba(46,213,115,0.2)',borderRadius:7,padding:10,fontSize:11,fontFamily:'var(--font-mono)',color:'#e8edf5',whiteSpace:'pre-wrap',wordBreak:'break-all'}}>
            {JSON.stringify(finding.replay?.expected_secure_response || { status: '401/403/validated' }, null, 2)}
          </pre>
        </div>
      </div>
      <div style={{marginTop:10}}>
        <div style={{fontSize:11,color:'#4f8ef7',marginBottom:6,fontFamily:'var(--font-mono)'}}>Triggered Request</div>
        <pre style={{background:'var(--bg-3)',border:'1px solid rgba(79,142,247,0.2)',borderRadius:7,padding:10,fontSize:11,fontFamily:'var(--font-mono)',color:'#e8edf5',whiteSpace:'pre-wrap',wordBreak:'break-all'}}>
          {JSON.stringify(finding.replay?.request || { method: finding.method, url: finding.endpoint }, null, 2)}
        </pre>
      </div>
    </div>}
    {tab==='remediation'&&<div className="card">
      {finding.aiRemediation&&finding.aiRemediation!==finding.remediation&&<div style={{fontSize:11,color:'#4f8ef7',marginBottom:8,fontFamily:'var(--font-mono)'}}>🤖 AI-Powered Fix</div>}
      <pre style={{background:'var(--bg-3)',border:'1px solid rgba(46,213,115,0.2)',borderRadius:7,padding:14,fontSize:12,fontFamily:'var(--font-mono)',color:'#e8edf5',lineHeight:1.7,whiteSpace:'pre-wrap'}}>
        {finding.aiRemediation||finding.remediation}
      </pre>
    </div>}
  </div>;
}
