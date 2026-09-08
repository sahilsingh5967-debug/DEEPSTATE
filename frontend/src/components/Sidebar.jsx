import React from 'react';
import { LayoutDashboard, Radio, Network, ShieldAlert, Cpu, FileText, Settings } from 'lucide-react';

const NAV_ITEMS = [
  { id: 'overview', label: 'Architecture Overview', icon: LayoutDashboard, phase: 'Phase 1 Active', active: true },
  { id: 'testbed', label: 'IPsec Testbed', icon: Radio, phase: 'Phase 2 Planned', active: false },
  { id: 'pcap', label: 'PCAP Analyzer', icon: Network, phase: 'Phase 3 Planned', active: false },
  { id: 'security', label: 'Security Assessment', icon: ShieldAlert, phase: 'Phase 4 Planned', active: false },
  { id: 'ml', label: 'ML Classification', icon: Cpu, phase: 'Phase 5 Planned', active: false },
  { id: 'reports', label: 'Reports & Dashboard', icon: FileText, phase: 'Phase 7 Planned', active: false },
];

export default function Sidebar() {
  return (
    <aside style={{
      width: '260px',
      backgroundColor: '#090d16',
      borderRight: '1px solid #1e293b',
      padding: '20px 12px',
      display: 'flex',
      flexDirection: 'column',
      gap: '8px'
    }}>
      <div style={{ padding: '0 12px 12px', fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', color: '#64748b', letterSpacing: '0.05em' }}>
        System Modules
      </div>
      {NAV_ITEMS.map((item) => {
        const Icon = item.icon;
        return (
          <div
            key={item.id}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '10px 12px',
              borderRadius: '8px',
              backgroundColor: item.active ? 'rgba(59, 130, 246, 0.12)' : 'transparent',
              border: item.active ? '1px solid rgba(59, 130, 246, 0.3)' : '1px solid transparent',
              color: item.active ? '#60a5fa' : '#94a3b8',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Icon style={{ width: '18px', height: '18px' }} />
              <span style={{ fontSize: '14px', fontWeight: item.active ? '600' : '400' }}>{item.label}</span>
            </div>
            <span style={{
              fontSize: '10px',
              padding: '2px 6px',
              borderRadius: '4px',
              backgroundColor: item.active ? 'rgba(34, 197, 94, 0.2)' : '#1e293b',
              color: item.active ? '#4ade80' : '#64748b'
            }}>
              {item.phase}
            </span>
          </div>
        );
      })}
    </aside>
  );
}
