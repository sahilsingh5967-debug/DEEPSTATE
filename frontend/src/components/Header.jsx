import React from 'react';
import { Shield, Server, Activity, Cpu } from 'lucide-react';

export default function Header({ backendHealth, loading, pipelineStatus = 'idle' }) {
  const isHealthy = backendHealth?.status === 'ok';

  const getPipelineBadge = () => {
    switch (pipelineStatus) {
      case 'analyzing':
        return { label: 'Pipeline: Analyzing', bg: 'rgba(56, 189, 248, 0.12)', border: 'rgba(56, 189, 248, 0.3)', color: '#38bdf8' };
      case 'completed':
        return { label: 'Pipeline: Completed', bg: 'rgba(34, 197, 94, 0.12)', border: 'rgba(34, 197, 94, 0.3)', color: '#4ade80' };
      case 'failed':
        return { label: 'Pipeline: Failed', bg: 'rgba(239, 68, 68, 0.12)', border: 'rgba(239, 68, 68, 0.3)', color: '#f87171' };
      default:
        return { label: 'Pipeline: Idle', bg: 'rgba(148, 163, 184, 0.12)', border: 'rgba(148, 163, 184, 0.3)', color: '#94a3b8' };
    }
  };

  const pipeBadge = getPipelineBadge();

  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '16px 28px',
      backgroundColor: '#070a12',
      borderBottom: '1px solid #1e293b'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          padding: '10px',
          backgroundColor: 'rgba(14, 165, 233, 0.1)',
          borderRadius: '10px',
          border: '1px solid rgba(14, 165, 233, 0.25)'
        }}>
          <Shield style={{ width: '26px', height: '26px', color: '#0ea5e9' }} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ margin: 0, fontSize: '20px', fontWeight: '800', color: '#f8fafc', letterSpacing: '0.04em' }}>
              DEEPSTATE
            </h1>
            <span style={{
              fontSize: '10px',
              fontWeight: '700',
              padding: '2px 8px',
              borderRadius: '4px',
              backgroundColor: 'rgba(14, 165, 233, 0.15)',
              color: '#38bdf8',
              border: '1px solid rgba(14, 165, 233, 0.3)',
              letterSpacing: '0.05em'
            }}>
              SOC v0.1.0
            </span>
          </div>
          <span style={{ fontSize: '12px', color: '#94a3b8', fontWeight: '500' }}>
            IPsec Security Intelligence Platform
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {/* Backend Status Indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 14px',
          borderRadius: '20px',
          fontSize: '12px',
          fontWeight: '600',
          backgroundColor: isHealthy ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${isHealthy ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
          color: isHealthy ? '#4ade80' : '#f87171'
        }}>
          <Server style={{ width: '13px', height: '13px' }} />
          <span>
            Backend: {loading ? 'Connecting...' : isHealthy ? `Operational (v${backendHealth.version})` : 'Offline'}
          </span>
        </div>

        {/* Pipeline Status Indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 14px',
          borderRadius: '20px',
          fontSize: '12px',
          fontWeight: '600',
          backgroundColor: pipeBadge.bg,
          border: `1px solid ${pipeBadge.border}`,
          color: pipeBadge.color
        }}>
          <Activity style={{ width: '13px', height: '13px' }} />
          <span>{pipeBadge.label}</span>
        </div>
      </div>
    </header>
  );
}
