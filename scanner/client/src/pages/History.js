import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
const SC = {critical:'#ff4757',high:'#ff6b35',medium:'#ffa502',low:'#2ed573',info:'#1e90ff'};

export default function History() {
  const navigate=useNavigate();
  const [scans,setScans]=useState([]), [loading,setLoading]=useState(true);
  useEffect(()=>{ axios.get(`${API_URL}/api/scan`).then(r=>{setScans(r.data);setLoading(false);}).catch(()=>setLoading(false)); },[]);

  if(loading) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'80vh',color:'#8b9bb8'}}>Loading history...</div>;

  return (
    <div style={{maxWidth:860,margin:'0 auto',padding:'36px 20px'}}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:28}}>
        <div>
          <h1 style={{fontFamily:'var(--font-display)',fontSize:26,fontWeight:800,color:'#e8edf5'}}>Scan History</h1>
          <p style={{color:'#8b9bb8',marginTop:3,fontSize:13}}>{scans.length} scans recorded</p>
        </div>
        <button onClick={()=>navigate('/')} style={{padding:'9px 18px',background:'#4f8ef7',border:'none',borderRadius:8,color:'white',cursor:'pointer',fontSize:13,fontFamily:'var(--font-body)',fontWeight:600}}>+ New Scan</button>
      </div>

      {scans.length===0?(
        <div style={{textAlign:'center',padding:'72px 0',color:'#4a5568'}}>
          <div style={{fontSize:44,marginBottom:14}}>🔍</div>
          <div>No scans yet — start your first one!</div>
        </div>
      ):(
        <div style={{display:'flex',flexDirection:'column',gap:9}}>
          {scans.map((scan,i)=>{
            const risk=Math.min(100,((scan.summary?.critical||0)*10+(scan.summary?.high||0)*7+(scan.summary?.medium||0)*4+(scan.summary?.low||0)*2));
            const total=Object.values(scan.summary||{}).reduce((a,b)=>a+b,0);
            return (
              <div key={scan.scanId||i} style={{background:'var(--bg-2)',border:'1px solid var(--border)',borderRadius:11,padding:'14px 18px',display:'flex',alignItems:'center',gap:14,cursor:'pointer',transition:'all .15s',animation:`fadeInUp .3s ease ${i*.04}s both`}}
                onClick={()=>navigate(scan.status==='completed'?`/report/${scan.scanId}`:`/scan/${scan.scanId}`)}
                onMouseEnter={e=>{e.currentTarget.style.borderColor='#344060';e.currentTarget.style.transform='translateX(3px)';}}
                onMouseLeave={e=>{e.currentTarget.style.borderColor='#2a3347';e.currentTarget.style.transform='none';}}>
                <div style={{width:9,height:9,borderRadius:'50%',flexShrink:0,background:scan.status==='completed'?'#2ed573':scan.status==='running'?'#4f8ef7':'#ff4757',animation:scan.status==='running'?'pulse-dot 1.5s ease-in-out infinite':'none'}}/>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:13,fontWeight:600,color:'#e8edf5',marginBottom:2,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{scan.targetUrl}</div>
                  <div style={{fontSize:11,color:'#4a5568',fontFamily:'var(--font-mono)'}}>{new Date(scan.createdAt).toLocaleString()} · {scan.scanType} · {scan.scannedEndpoints||0} endpoints</div>
                </div>
                <div style={{display:'flex',gap:5}}>
                  {['critical','high','medium'].map(s=>{ const c=scan.summary?.[s]||0; return c?<div key={s} className={`badge badge-${s}`} style={{fontSize:10}}>{c}</div>:null; })}
                  {total===0&&<div className="badge badge-low" style={{fontSize:10}}>Clean</div>}
                </div>
                <div style={{textAlign:'center',minWidth:44}}>
                  <div style={{fontSize:18,fontWeight:800,fontFamily:'var(--font-display)',color:risk>=70?'#ff4757':risk>=40?'#ff6b35':'#2ed573'}}>{risk}</div>
                  <div style={{fontSize:9,color:'#4a5568',textTransform:'uppercase',letterSpacing:1}}>risk</div>
                </div>
                <div style={{color:'#4a5568'}}>→</div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
