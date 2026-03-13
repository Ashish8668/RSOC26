import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
const SC = {critical:'#ff4757',high:'#ff6b35',medium:'#ffa502',low:'#2ed573',info:'#1e90ff'};

export default function Report() {
  const {scanId}=useParams(), navigate=useNavigate();
  const [report,setReport]=useState(null), [loading,setLoading]=useState(true);
  useEffect(()=>{ axios.get(`${API_URL}/api/report/${scanId}`).then(r=>{setReport(r.data);setLoading(false);}).catch(()=>setLoading(false)); },[scanId]);

  if (loading) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'80vh',color:'#8b9bb8'}}>Generating report...</div>;
  if (!report) return <div style={{padding:40,color:'#ff4757'}}>Report not found</div>;

  const {meta,executive_summary:es,findings,recommendations}=report;
  const pieData=['critical','high','medium','low','info'].map(s=>({name:s,value:es[s]||0,color:SC[s]})).filter(d=>d.value>0);
  const owaspData=Object.entries(findings.reduce((a,f)=>{a[f.type]=(a[f.type]||0)+1;return a;},{})).map(([name,count])=>({name,count})).sort((a,b)=>b.count-a.count).slice(0,8);
  const risk=es.risk_score||0;

  return (
    <div style={{maxWidth:960,margin:'0 auto',padding:'28px 20px'}}>
      <div style={{display:'flex',gap:10,marginBottom:28}}>
        <button onClick={()=>navigate(`/scan/${scanId}`)} style={{padding:'7px 14px',background:'transparent',border:'1px solid #2a3347',borderRadius:7,color:'#8b9bb8',cursor:'pointer',fontSize:13,fontFamily:'var(--font-body)'}}>← Dashboard</button>
        <button onClick={()=>window.print()} style={{padding:'7px 18px',background:'#4f8ef7',border:'none',borderRadius:7,color:'white',cursor:'pointer',fontSize:13,fontFamily:'var(--font-body)',fontWeight:600}}>🖨️ Print / Save PDF</button>
      </div>

      {/* Header */}
      <div style={{background:'linear-gradient(135deg,#0d1117,#161b27)',border:'1px solid #2a3347',borderRadius:14,padding:28,marginBottom:20,borderTop:`4px solid ${risk>=70?'#ff4757':risk>=40?'#ff6b35':'#ffa502'}`}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
          <div>
            <div style={{fontSize:10,color:'#4a5568',fontFamily:'var(--font-mono)',marginBottom:6,letterSpacing:2,textTransform:'uppercase'}}>API Security Assessment Report</div>
            <h1 style={{fontFamily:'var(--font-display)',fontSize:26,fontWeight:800,marginBottom:6,color:'#e8edf5'}}>{meta.target}</h1>
            <div style={{fontSize:12,color:'#8b9bb8',fontFamily:'var(--font-mono)'}}>Generated: {new Date(meta.generatedAt).toLocaleString()}</div>
          </div>
          <div style={{textAlign:'center'}}>
            <div style={{width:72,height:72,borderRadius:'50%',background:`${risk>=70?'rgba(255,71,87,0.15)':risk>=40?'rgba(255,107,53,0.15)':'rgba(46,213,115,0.15)'}`,border:`2px solid ${risk>=70?'#ff4757':risk>=40?'#ff6b35':'#2ed573'}`,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center'}}>
              <div style={{fontSize:22,fontWeight:800,fontFamily:'var(--font-display)',color:risk>=70?'#ff4757':risk>=40?'#ff6b35':'#2ed573'}}>{risk}</div>
            </div>
            <div style={{marginTop:6,fontSize:11,fontWeight:700,color:risk>=70?'#ff4757':risk>=40?'#ff6b35':'#2ed573'}}>{es.risk_level}</div>
          </div>
        </div>
      </div>

      {/* Summary cards */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(5,1fr)',gap:10,marginBottom:20}}>
        {['critical','high','medium','low','info'].map(s=>(
          <div key={s} style={{background:'var(--bg-2)',border:`1px solid ${SC[s]}25`,borderRadius:10,padding:'14px 10px',textAlign:'center',borderTop:`3px solid ${SC[s]}`}}>
            <div style={{fontSize:26,fontWeight:800,fontFamily:'var(--font-display)',color:SC[s]}}>{es[s]||0}</div>
            <div style={{fontSize:10,color:'#8b9bb8',textTransform:'uppercase',letterSpacing:1,marginTop:2}}>{s}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14,marginBottom:20}}>
        <div className="card">
          <h3 style={{fontSize:12,color:'#8b9bb8',fontWeight:600,marginBottom:14,textTransform:'uppercase',letterSpacing:1}}>Finding Distribution</h3>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart><Pie data={pieData} cx="50%" cy="50%" innerRadius={44} outerRadius={72} dataKey="value" paddingAngle={3}>
              {pieData.map((e,i)=><Cell key={i} fill={e.color}/>)}
            </Pie><Tooltip contentStyle={{background:'#1e2535',border:'1px solid #2a3347',borderRadius:7,fontSize:11}}/></PieChart>
          </ResponsiveContainer>
          <div style={{display:'flex',gap:8,flexWrap:'wrap',justifyContent:'center'}}>
            {pieData.map(d=><div key={d.name} style={{display:'flex',alignItems:'center',gap:4,fontSize:11}}>
              <div style={{width:7,height:7,borderRadius:2,background:d.color}}/><span style={{color:'#8b9bb8'}}>{d.name} ({d.value})</span>
            </div>)}
          </div>
        </div>
        <div className="card">
          <h3 style={{fontSize:12,color:'#8b9bb8',fontWeight:600,marginBottom:14,textTransform:'uppercase',letterSpacing:1}}>By Vulnerability Type</h3>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={owaspData} layout="vertical">
              <XAxis type="number" tick={{fill:'#4a5568',fontSize:10}}/>
              <YAxis type="category" dataKey="name" width={80} tick={{fill:'#8b9bb8',fontSize:10}}/>
              <Tooltip contentStyle={{background:'#1e2535',border:'1px solid #2a3347',borderRadius:7,fontSize:11}}/>
              <Bar dataKey="count" fill="#4f8ef7" radius={[0,4,4,0]}/>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Findings */}
      <div className="card" style={{marginBottom:20}}>
        <h2 style={{fontSize:15,fontWeight:700,marginBottom:16,color:'#e8edf5'}}>Detailed Findings ({findings.length})</h2>
        <div style={{display:'flex',flexDirection:'column',gap:10}}>
          {findings.map((f,i)=>(
            <div key={i} style={{background:'var(--bg-3)',borderRadius:9,padding:14,borderLeft:`3px solid ${SC[f.severity]||'#8b9bb8'}`}}>
              <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:7}}>
                <div><div style={{display:'flex',alignItems:'center',gap:7,marginBottom:3}}><span className={`badge badge-${f.severity}`}>{f.severity}</span><span style={{fontSize:10,color:'#4a5568'}}>CVSS {f.cvss_score}</span></div>
                  <h3 style={{fontSize:14,fontWeight:600,color:'#e8edf5'}}>{f.title}</h3></div>
                <div style={{fontSize:10,color:'#4a5568',fontFamily:'var(--font-mono)',textAlign:'right'}}><div style={{color:'#4f8ef7'}}>{f.method}</div><div>{(f.endpoint||'').replace(/^https?:\/\/[^/]+/,'').slice(0,35)}</div></div>
              </div>
              <p style={{fontSize:12,color:'#8b9bb8',marginBottom:10,lineHeight:1.6}}>{f.description}</p>
              <pre style={{background:'var(--bg-4)',borderRadius:7,padding:'9px 12px',fontSize:11,fontFamily:'var(--font-mono)',color:'#2ed573',lineHeight:1.6,whiteSpace:'pre-wrap',overflow:'hidden'}}>
                {'//'} Remediation{'\n'}{(f.aiRemediation||f.remediation||'').slice(0,300)}
              </pre>
            </div>
          ))}
        </div>
      </div>

      {/* Recommendations */}
      {recommendations?.length>0&&<div className="card">
        <h2 style={{fontSize:15,fontWeight:700,marginBottom:14,color:'#e8edf5'}}>Strategic Recommendations</h2>
        <div style={{display:'flex',flexDirection:'column',gap:8}}>
          {recommendations.map((r,i)=>(
            <div key={i} style={{background:'var(--bg-3)',borderRadius:9,padding:14,display:'flex',gap:12,alignItems:'flex-start',border:`1px solid ${r.priority==='critical'?'rgba(255,71,87,0.2)':'#2a3347'}`}}>
              <div style={{fontSize:18}}>{r.priority==='critical'?'🚨':r.priority==='high'?'⚠️':'💡'}</div>
              <div><div style={{fontSize:13,fontWeight:600,color:'#e8edf5',marginBottom:3}}>{r.title}</div>
                <div style={{fontSize:12,color:'#8b9bb8',lineHeight:1.6}}>{r.description}</div></div>
            </div>
          ))}
        </div>
      </div>}
    </div>
  );
}
