import React from 'react';
import { ShieldAlert, Activity, FileText, Cpu } from 'lucide-react';

export function KpiCard({ label, value, subtext, highlight, badge, icon: Icon }) {
  return (
    <div style={{
      backgroundColor: '#FFFFFF',
      borderRadius: '10px',
      border: '1px solid #D8D4C8',
      padding: '20px 22px',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
      position: 'relative',
      overflow: 'hidden',
      boxShadow: '0 2px 8px rgba(30, 30, 20, 0.05)',
      height: '135px',
      boxSizing: 'border-box'
    }}>
      {/* Top indicator bar for highlighted card */}
      {highlight && (
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '4px',
          backgroundColor: '#D6A928'
        }} />
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '11px', fontWeight: '700', color: '#8A877E', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {label}
        </span>
        {Icon && (
          <div style={{ padding: '6px', borderRadius: '6px', backgroundColor: '#EDEAE1', color: '#596F7D' }}>
            <Icon style={{ width: '16px', height: '16px' }} />
          </div>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
        <span style={{ fontSize: '28px', fontWeight: '700', color: '#252525', lineHeight: 1 }}>
          {value}
        </span>
        {badge && (
          <span style={{
            fontSize: '11px',
            fontWeight: '600',
            padding: '2px 8px',
            borderRadius: '5px',
            backgroundColor: badge.bg || '#EDEAE1',
            color: badge.color || '#252525',
            border: `1px solid ${badge.border || '#D8D4C8'}`
          }}>
            {badge.text}
          </span>
        )}
      </div>

      {subtext && (
        <span style={{ fontSize: '12px', color: '#66645D' }}>
          {subtext}
        </span>
      )}
    </div>
  );
}

export default function StatusCard({ result }) {
  if (!result) return null;

  const secScore = result?.security_assessment?.security_score ?? 100.0;
  const riskLevel = result?.security_assessment?.risk_level || result?.security_assessment?.overall_status || 'SECURE';
  const packetCount = result?.pcap_metadata?.packet_count ?? (result?.esp?.packet_count || 0);
  const mlClass = result?.traffic_classification?.dominant_class || 'N/A';
  const mlConf = result?.traffic_classification?.confidence ? `${(result.traffic_classification.confidence * (result.traffic_classification.confidence <= 1 ? 100 : 1)).toFixed(1)}%` : 'N/A';

  const riskBadge = riskLevel.includes('SECURE') || riskLevel === 'LOW'
    ? { text: 'LOW RISK', bg: '#E3EEE7', color: '#3F7654', border: '#BFD7C7' }
    : riskLevel.includes('MEDIUM')
    ? { text: 'MEDIUM RISK', bg: '#F5EBD5', color: '#B57B22', border: '#E3D08C' }
    : { text: 'HIGH RISK', bg: '#F3E2E0', color: '#A94B43', border: '#E8C4C1' };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
      <KpiCard
        label="Security Score"
        value={`${secScore} / 100`}
        subtext="Evaluated by Security Policy Engine"
        highlight={true}
        icon={ShieldAlert}
      />
      <KpiCard
        label="Risk Posture"
        value={riskLevel}
        badge={riskBadge}
        subtext="Phase 4 Policy Assessment"
        icon={Activity}
      />
      <KpiCard
        label="Packets Analyzed"
        value={packetCount}
        subtext="PCAP Capture Volume"
        icon={FileText}
      />
      <KpiCard
        label="ML Classification"
        value={mlClass}
        subtext={`Confidence: ${mlConf}`}
        icon={Cpu}
      />
    </div>
  );
}
