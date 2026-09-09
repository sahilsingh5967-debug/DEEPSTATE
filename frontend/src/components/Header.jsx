import React from 'react';
import { Shield, FlaskConical, Play, HardDrive, LayoutDashboard } from 'lucide-react';

export default function Header({ backendHealth, loading, activeTab, setActiveTab }) {
  const backendOk = backendHealth?.status === 'ok' || backendHealth?.status === 'healthy';

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'analyze', label: 'Analyze PCAP', icon: Play },
    { id: 'lab', label: 'Demonstration Lab', icon: FlaskConical },
    { id: 'library', label: 'PCAP Library', icon: HardDrive },
  ];

  return (
    <header style={{
      height: '72px',
      backgroundColor: '#FFFDF8',
      borderBottom: '1px solid #D8D4C8',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 32px',
      boxSizing: 'border-box',
      position: 'sticky',
      top: 0,
      zIndex: 100
    }}>
      {/* Left Branding */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{
          width: '38px',
          height: '38px',
          borderRadius: '8px',
          backgroundColor: '#F4E7B8',
          border: '1px solid #D6A928',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#9A7618'
        }}>
          <Shield style={{ width: '20px', height: '20px' }} />
        </div>
        <div>
          <h1 style={{ margin: 0, fontSize: '20px', fontWeight: '700', color: '#252525', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
            DEEPSTATE
          </h1>
          <span style={{ fontSize: '11px', fontWeight: '500', color: '#77736A' }}>
            IPsec Security Intelligence Platform
          </span>
        </div>
      </div>

      {/* Center Navigation Links */}
      <nav style={{ display: 'flex', gap: '6px', backgroundColor: '#EDEAE1', padding: '4px', borderRadius: '9px', border: '1px solid #D8D4C8' }}>
        {navItems.map(item => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '7px',
                height: '36px',
                padding: '0 14px',
                borderRadius: '7px',
                fontSize: '13px',
                fontWeight: isActive ? '700' : '500',
                cursor: 'pointer',
                border: isActive ? '1px solid #D6A928' : 'none',
                backgroundColor: isActive ? '#F4E7B8' : 'transparent',
                color: isActive ? '#9A7618' : '#66645D',
                transition: 'all 0.15s ease'
              }}
            >
              <Icon style={{ width: '15px', height: '15px', color: isActive ? '#9A7618' : '#8A877E' }} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Right Operational Status Pills */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        {/* Backend Status Pill */}
        <div style={{
          height: '32px',
          padding: '0 12px',
          borderRadius: '16px',
          backgroundColor: backendOk ? '#E3EEE7' : '#F3E2E0',
          color: backendOk ? '#3F7654' : '#A94B43',
          border: `1px solid ${backendOk ? '#C5DEC9' : '#E2B9B5'}`,
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '12px',
          fontWeight: '600'
        }}>
          <span style={{
            width: '7px',
            height: '7px',
            borderRadius: '50%',
            backgroundColor: backendOk ? '#3F7654' : '#A94B43'
          }} />
          <span>{loading ? 'Connecting...' : backendOk ? 'Backend Operational' : 'Backend Offline'}</span>
        </div>

        {/* Pipeline Status Pill */}
        <div style={{
          height: '32px',
          padding: '0 12px',
          borderRadius: '16px',
          backgroundColor: '#F4E7B8',
          color: '#9A7618',
          border: '1px solid #E6D3A7',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '12px',
          fontWeight: '600'
        }}>
          <span style={{ width: '7px', height: '7px', borderRadius: '50%', backgroundColor: '#D6A928' }} />
          <span>Analysis Pipeline Ready</span>
        </div>
      </div>
    </header>
  );
}
