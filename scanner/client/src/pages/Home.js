import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import toast from 'react-hot-toast';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
const SCAN_TYPES = [
  {id:'quick',  label:'Quick Scan',    desc:'~2 min · Core checks', icon:'⚡'},
  {id:'standard',label:'Standard Scan',desc:'~8 min · All modules', icon:'🔍'},
  {id:'deep',   label:'Deep Scan',     desc:'~20 min · Full OWASP', icon:'🛡️'},
];
const VULN_TYPES = [
  {icon:'🔐',label:'BOLA / IDOR'},{icon:'🚫',label:'Auth Bypass'},{icon:'🌊',label:'Rate Limiting'},
  {icon:'📡',label:'Data Exposure'},{icon:'💉',label:'SQL Injection'},{icon:'⚙️',label:'Misconfig'},
  {icon:'🔑',label:'JWT Security'},{icon:'🎯',label:'XSS / SSRF'},
];

export default function Home() {
  const navigate = useNavigate();
  const fileRef = useRef();
  const [url, setUrl] = useState('');
  const [token, setToken] = useState('');
  const [scanType, setScanType] = useState('standard');
  const [file, setFile] = useState(null);
  const [rawCurl, setRawCurl] = useState('');
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState('url');

  const submit = async (e) => {
    e.preventDefault();
    if (!url && !file && !rawCurl.trim()) return toast.error('Enter a target URL, upload a spec file, or paste curl commands');
    setLoading(true);
    const tid = toast.loading('Starting scan...');
    try {
      const fd = new FormData();
      if (url)   fd.append('targetUrl', url);
      if (token) fd.append('authToken', token);
      if (rawCurl.trim()) fd.append('rawCurl', rawCurl.trim());
      fd.append('scanType', scanType);
      if (file)  fd.append('file', file);
      const { data } = await axios.post(`${API_URL}/api/scan/start`, fd, { headers: {'Content-Type':'multipart/form-data'} });
      toast.success('Scan started!', {id:tid});
      navigate(`/scan/${data.scanId}`);
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to start scan', {id:tid});
      setLoading(false);
    }
  };

  return (
    <div style={{minHeight:'calc(100vh - 60px)',padding:'48px 24px',maxWidth:1000,margin:'0 auto'}}>
      {/* Hero */}
      <div style={{textAlign:'center',marginBottom:48,animation:'fadeInUp 0.5s ease'}}>
        <div style={{display:'inline-flex',alignItems:'center',gap:8,background:'rgba(79,142,247,0.1)',border:'1px solid rgba(79,142,247,0.25)',borderRadius:20,padding:'6px 16px',marginBottom:20,fontSize:13,color:'#4f8ef7',fontFamily:'var(--font-mono)'}}>
          ● OWASP API Security Top 10 · 2023
        </div>
        <h1 style={{fontFamily:'var(--font-display)',fontSize:'clamp(32px,5vw,64px)',fontWeight:800,lineHeight:1.05,letterSpacing:'-2px',marginBottom:16,background:'linear-gradient(135deg,#e8edf5 0%,#8b9bb8 100%)',WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent'}}>
          Find API Vulnerabilities<br/>Before Attackers Do
        </h1>
        <p style={{fontSize:17,color:'#8b9bb8',maxWidth:520,margin:'0 auto'}}>
          Automated scanner that tests your API against OWASP Top 10 and generates AI-powered fix suggestions.
        </p>
      </div>

      {/* Form */}
      <div style={{background:'var(--bg-2)',border:'1px solid var(--border)',borderRadius:16,padding:32,marginBottom:28,animation:'fadeInUp 0.5s ease 0.1s both'}}>
        <div style={{display:'flex',gap:8,marginBottom:24}}>
          {[{id:'url',label:'🌐 Target URL'},{id:'file',label:'📁 Upload Spec'},{id:'curl',label:'🧵 Raw curl'}].map(t=>(
            <button key={t.id} onClick={()=>setTab(t.id)} style={{padding:'7px 18px',borderRadius:8,border:'1px solid',cursor:'pointer',fontSize:13,fontWeight:500,fontFamily:'var(--font-body)',
              borderColor:tab===t.id?'rgba(79,142,247,0.5)':'var(--border)',background:tab===t.id?'rgba(79,142,247,0.1)':'transparent',color:tab===t.id?'#4f8ef7':'#8b9bb8'}}>{t.label}</button>
          ))}
        </div>
        <form onSubmit={submit}>
          {tab==='url' && (
            <div style={{marginBottom:16}}>
              <label style={{display:'block',fontSize:13,color:'#8b9bb8',marginBottom:6,fontWeight:500}}>Target API Base URL</label>
              <input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://api.example.com  or  http://localhost:3001"
                style={{width:'100%',padding:'11px 14px',background:'var(--bg-3)',border:'1px solid var(--border)',borderRadius:9,color:'var(--text-primary)',fontSize:14,fontFamily:'var(--font-mono)',outline:'none'}}
                onFocus={e=>e.target.style.borderColor='#4f8ef7'} onBlur={e=>e.target.style.borderColor='#2a3347'}/>
              <p style={{fontSize:12,color:'#4a5568',marginTop:5}}>💡 Try: http://localhost:3001 to scan the included vulnerable demo API</p>
            </div>
          )}
          {tab==='file' && (
            <div style={{marginBottom:16}}>
              <div onClick={()=>fileRef.current.click()} style={{border:`2px dashed ${file?'#4f8ef7':'var(--border)'}`,borderRadius:10,padding:'28px 20px',textAlign:'center',cursor:'pointer',background:file?'rgba(79,142,247,0.05)':'var(--bg-3)'}}>
                <div style={{fontSize:28,marginBottom:6}}>{file?'✅':'📂'}</div>
                <div style={{color:file?'#4f8ef7':'#8b9bb8',fontSize:13}}>{file?file.name:'Click to upload Postman .json or OpenAPI .yaml'}</div>
              </div>
              <input ref={fileRef} type="file" accept=".json,.yaml,.yml" style={{display:'none'}} onChange={e=>setFile(e.target.files[0])}/>
            </div>
          )}
          {tab==='curl' && (
            <div style={{marginBottom:16}}>
              <label style={{display:'block',fontSize:13,color:'#8b9bb8',marginBottom:6,fontWeight:500}}>Paste raw curl command(s)</label>
              <textarea
                value={rawCurl}
                onChange={e=>setRawCurl(e.target.value)}
                placeholder={`curl -X GET http://localhost:3001/api/users/1\ncurl -X POST http://localhost:3001/api/auth/login -H "Content-Type: application/json" -d '{"email":"alice@example.com","password":"password123"}'`}
                rows={7}
                style={{width:'100%',padding:'11px 14px',background:'var(--bg-3)',border:'1px solid var(--border)',borderRadius:9,color:'var(--text-primary)',fontSize:13,fontFamily:'var(--font-mono)',outline:'none',resize:'vertical'}}
                onFocus={e=>e.target.style.borderColor='#4f8ef7'} onBlur={e=>e.target.style.borderColor='#2a3347'}
              />
              <p style={{fontSize:12,color:'#4a5568',marginTop:5}}>You can paste multiple curl commands on separate lines.</p>
            </div>
          )}
          <div style={{marginBottom:20}}>
            <label style={{display:'block',fontSize:13,color:'#8b9bb8',marginBottom:6,fontWeight:500}}>Bearer Token <span style={{color:'#4a5568',fontWeight:400}}>(optional)</span></label>
            <input value={token} onChange={e=>setToken(e.target.value)} placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
              style={{width:'100%',padding:'10px 14px',background:'var(--bg-3)',border:'1px solid var(--border)',borderRadius:8,color:'var(--text-primary)',fontSize:13,fontFamily:'var(--font-mono)',outline:'none'}}
              onFocus={e=>e.target.style.borderColor='#4f8ef7'} onBlur={e=>e.target.style.borderColor='#2a3347'}/>
          </div>
          <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10,marginBottom:24}}>
            {SCAN_TYPES.map(t=>(
              <button key={t.id} type="button" onClick={()=>setScanType(t.id)} style={{padding:'13px 10px',borderRadius:10,border:'1px solid',cursor:'pointer',textAlign:'left',fontFamily:'var(--font-body)',
                borderColor:scanType===t.id?'rgba(79,142,247,0.6)':'var(--border)',background:scanType===t.id?'rgba(79,142,247,0.08)':'var(--bg-3)'}}>
                <div style={{fontSize:18,marginBottom:4}}>{t.icon}</div>
                <div style={{fontSize:13,fontWeight:600,color:scanType===t.id?'#4f8ef7':'#e8edf5'}}>{t.label}</div>
                <div style={{fontSize:11,color:'#8b9bb8',marginTop:2}}>{t.desc}</div>
              </button>
            ))}
          </div>
          <button type="submit" disabled={loading} style={{width:'100%',padding:'13px',background:loading?'#252d3d':'linear-gradient(135deg,#4f8ef7,#7c3aed)',border:'none',borderRadius:10,cursor:loading?'not-allowed':'pointer',color:'white',fontSize:16,fontWeight:700,fontFamily:'var(--font-body)'}}>
            {loading?'⏳ Starting scan...':'🚀 Start Security Scan'}
          </button>
        </form>
      </div>
      {/* Coverage grid */}
      <h2 style={{fontSize:12,fontWeight:600,color:'#4a5568',letterSpacing:2,textTransform:'uppercase',marginBottom:12}}>Vulnerability Coverage</h2>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(180px,1fr))',gap:8}}>
        {VULN_TYPES.map((v,i)=>(
          <div key={i} style={{background:'var(--bg-2)',border:'1px solid var(--border)',borderRadius:10,padding:'12px 14px',display:'flex',alignItems:'center',gap:10,animation:`fadeInUp 0.4s ease ${0.2+i*0.04}s both`}}>
            <span style={{fontSize:18}}>{v.icon}</span>
            <span style={{fontSize:13,fontWeight:600,color:'#e8edf5'}}>{v.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
