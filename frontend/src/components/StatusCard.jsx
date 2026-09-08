import React from 'react';

export default function StatusCard({ title, status, badge, description, icon: Icon }) {
  return (
    <div style={{
      backgroundColor: '#0f172a',
      borderRadius: '12px',
      border: '1px solid #1e293b',
      padding: '20px',
      display: 'flex',
      flexDirection: 'column',
      gap: '12px'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {Icon && (
            <div style={{
              padding: '8px',
              borderRadius: '8px',
              backgroundColor: '#1e293b',
              color: '#60a5fa'
            }}>
              <Icon style={{ width: '20px', height: '20px' }} />
            </div>
          )}
          <h3 style={{ margin: 0, fontSize: '15px', fontWeight: '600', color: '#f1f5f9' }}>{title}</h3>
        </div>
        <span style={{
          fontSize: '11px',
          padding: '3px 8px',
          borderRadius: '12px',
          backgroundColor: badge === 'Active' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(148, 163, 184, 0.15)',
          color: badge === 'Active' ? '#4ade80' : '#94a3b8',
          border: `1px solid ${badge === 'Active' ? 'rgba(34, 197, 94, 0.3)' : 'rgba(148, 163, 184, 0.3)'}`
        }}>
          {badge}
        </span>
      </div>
      <div style={{ fontSize: '18px', fontWeight: '700', color: '#38bdf8' }}>
        {status}
      </div>
      <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8', lineHeight: '1.5' }}>
        {description}
      </p>
    </div>
  );
}
