import React from 'react';
import { Link, useLocation } from 'react-router-dom';

export default function Navbar() {
  const location = useLocation();
  const active = (p) => location.pathname === p;

  return (
    <nav
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 100,
        background: 'rgba(8,11,20,0.9)',
        backdropFilter: 'blur(16px)',
        borderBottom: '1px solid #2a3347',
        padding: '0 32px',
        display: 'flex',
        alignItems: 'center',
        gap: '32px',
        height: '64px',
      }}
    >
      <Link to="/" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div
          style={{
            width: 38,
            height: 38,
            borderRadius: 10,
            background: 'linear-gradient(135deg,#4f8ef7,#7c3aed)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}
        >
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M12 3L4 6v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V6l-8-3z" fill="white" fillOpacity="0.94" />
            <path d="M9.8 12.7l1.7 1.7 2.8-3" stroke="#4f8ef7" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
        <span
          style={{
            fontFamily: 'var(--font-display)',
            fontWeight: 800,
            fontSize: 19,
            color: '#e8edf5',
            letterSpacing: '-0.4px',
            lineHeight: 1.15,
          }}
        >
          APIGuard
        </span>
      </Link>

      <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
        {[{ to: '/', label: 'New Scan' }, { to: '/history', label: 'History' }].map(({ to, label }) => (
          <Link
            key={to}
            to={to}
            style={{
              textDecoration: 'none',
              padding: '6px 14px',
              borderRadius: 8,
              fontSize: 14,
              fontWeight: 500,
              color: active(to) ? '#4f8ef7' : '#8b9bb8',
              background: active(to) ? 'rgba(79,142,247,0.1)' : 'transparent',
              border: `1px solid ${active(to) ? 'rgba(79,142,247,0.3)' : 'transparent'}`,
            }}
          >
            {label}
          </Link>
        ))}
      </div>

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '4px 12px',
          borderRadius: 20,
          background: 'rgba(46,213,115,0.1)',
          border: '1px solid rgba(46,213,115,0.25)',
          fontSize: 12,
          color: '#2ed573',
          fontFamily: 'var(--font-mono)',
        }}
      >
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#2ed573', animation: 'pulse-dot 2s ease-in-out infinite' }} />
        Scanner Online
      </div>
    </nav>
  );
}
