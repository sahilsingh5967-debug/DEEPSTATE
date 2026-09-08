import React from 'react';
import { Shield, Activity, Server, AlertCircle } from 'lucide-react';

export default function Header({ backendHealth, loading }) {
  const isHealthy = backendHealth?.status === 'ok';

  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '16px 24px',
      backgroundColor: '#0f172a',
      borderBottom: '1px solid #1e293b'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{
          padding: '8px',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          borderRadius: '8px',
          border: '1px solid rgba(59, 130, 246, 0.2)'
        }}>
          <Shield style={{ width: '24px', height: '24px', color: '#60a5fa' }} />
        </div>
        <div>
          <h1 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: '#f8fafc' }}>
            IPsec VPN Analyzer & Security Framework
          </h1>
          <span style={{ fontSize: '12px', color: '#94a3b8' }}>
            Smart India Hackathon (SIH) Project Architecture
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 12px',
          borderRadius: '20px',
          fontSize: '13px',
          fontWeight: '500',
          backgroundColor: isHealthy ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${isHealthy ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
          color: isHealthy ? '#4ade80' : '#f87171'
        }}>
          <Server style={{ width: '14px', height: '14px' }} />
          <span>
            Backend: {loading ? 'Connecting...' : isHealthy ? `Operational (v${backendHealth.version})` : 'Offline'}
          </span>
        </div>
      </div>
    </header>
  );
}
