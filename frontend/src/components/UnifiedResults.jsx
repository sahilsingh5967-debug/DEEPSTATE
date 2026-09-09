import React from 'react';
import {
  ShieldCheck,
  Cpu,
  Lock,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Info,
  Layers,
  FileCheck,
  ShieldAlert,
  Radio,
  Download
} from 'lucide-react';
import StatusCard from './StatusCard';

export default function UnifiedResults({ result }) {
  if (!result) return null;

  const {
    analysis_id,
    pcap_metadata,
    protocol_identification,
    ike,
    esp,
    mode_inference,
    security_assessment,
    traffic_classification,
    analysis_warnings,
    errors
  } = result;

  const handleExportJson = () => {
    const jsonStr = JSON.stringify(result, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const downloadAnchor = document.createElement('a');
    downloadAnchor.href = url;
    downloadAnchor.download = `DEEPSTATE_Report_${analysis_id || 'result'}.json`;
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    URL.revokeObjectURL(url);
  };

  const getRiskColor = (risk) => {
    switch (risk?.toUpperCase()) {
      case 'CRITICAL': return '#ef4444';
      case 'HIGH': return '#f97316';
      case 'MEDIUM': return '#f59e0b';
      case 'LOW': return '#84cc16';
      case 'SECURE': return '#22c55e';
      default: return '#94a3b8';
    }
  };

  const targetClasses = [
    'ICMP', 'Web Browsing', 'Email', 'Chat', 'Streaming', 'File Transfer', 'VoIP', 'P2P'
  ];

  const classProbs = traffic_classification?.class_probabilities || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Overview Metadata Header */}
      <div style={{
        backgroundColor: '#0f172a',
        borderRadius: '12px',
        border: '1px solid #1e293b',
        padding: '20px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ padding: '10px', backgroundColor: 'rgba(56, 189, 248, 0.1)', borderRadius: '8px', border: '1px solid rgba(56, 189, 248, 0.2)' }}>
            <FileCheck style={{ width: '24px', height: '24px', color: '#38bdf8' }} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: '#f8fafc' }}>
              DEEPSTATE Threat & Traffic Intelligence Report
            </h3>
            <span style={{ fontSize: '12px', color: '#94a3b8', fontFamily: 'monospace' }}>
              Analysis Session ID: {analysis_id}
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '13px', color: '#cbd5e1' }}>
          <div>File: <strong style={{ color: '#f8fafc' }}>{pcap_metadata?.file_name || 'N/A'}</strong></div>
          <div>Packets: <strong style={{ color: '#f8fafc' }}>{pcap_metadata?.packet_count || 0}</strong></div>
          <div>Duration: <strong style={{ color: '#f8fafc' }}>{pcap_metadata?.duration_seconds ? `${pcap_metadata.duration_seconds}s` : 'N/A'}</strong></div>
          <div>Size: <strong style={{ color: '#f8fafc' }}>{pcap_metadata?.file_size_bytes ? `${pcap_metadata.file_size_bytes} B` : 'N/A'}</strong></div>

          <button
            type="button"
            onClick={handleExportJson}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer',
              border: '1px solid rgba(56, 189, 248, 0.4)',
              backgroundColor: 'rgba(56, 189, 248, 0.12)',
              color: '#38bdf8',
              transition: 'background-color 0.2s'
            }}
          >
            <Download style={{ width: '14px', height: '14px' }} />
            <span>Export Report (JSON)</span>
          </button>
        </div>
      </div>

      {/* 4-KPI SOC Executive Summary Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
        <StatusCard
          title="Security Risk Score"
          status={security_assessment ? `${security_assessment.security_score.toFixed(1)} / 100` : 'N/A'}
          badge={security_assessment?.risk_level || 'Active'}
          description={`Overall Posture: ${security_assessment?.overall_status || 'Evaluated'}`}
          icon={ShieldAlert}
        />
        <StatusCard
          title="IKE Negotiation"
          status={ike?.detected ? `Detected (${ike.version || 'IKE'})` : 'None Observed'}
          badge="Observed Fact"
          description={ike?.detected ? `${ike.exchange_types?.length || 0} exchange type(s) identified` : 'No IKE handshakes found'}
          icon={Lock}
        />
        <StatusCard
          title="ESP Encapsulation"
          status={esp?.detected ? `${esp.encapsulation || 'ESP Payload'}` : 'None Observed'}
          badge="Observed Fact"
          description={esp?.detected ? `${esp.packet_count} packets processed` : 'No ESP frames present'}
          icon={Activity}
        />
        <StatusCard
          title="ML Traffic Class"
          status={traffic_classification ? `${traffic_classification.dominant_class} (${((traffic_classification.confidence || 0) * 100).toFixed(0)}%)` : 'N/A'}
          badge="ML Inference"
          description="Probabilistic inference from encrypted flow statistics"
          icon={Cpu}
        />
      </div>

      {errors && errors.length > 0 && (
        <div style={{ padding: '16px', backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '8px', color: '#f87171' }}>
          <strong>Analysis Errors:</strong>
          <ul style={{ margin: '8px 0 0', paddingLeft: '20px' }}>
            {errors.map((err, i) => <li key={i}>{err}</li>)}
          </ul>
        </div>
      )}

      {/* TIER A: PROTOCOL OBSERVATIONS */}
      <div style={{
        backgroundColor: '#0f172a',
        borderRadius: '12px',
        border: '1px solid #1e293b',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Lock style={{ width: '20px', height: '20px', color: '#60a5fa' }} />
            <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '600', color: '#f1f5f9' }}>
              Tier A: Deterministic Protocol Observations (Phase 3)
            </h4>
          </div>
          <span style={{
            fontSize: '11px',
            fontWeight: '700',
            padding: '4px 10px',
            borderRadius: '12px',
            backgroundColor: 'rgba(96, 165, 250, 0.1)',
            border: '1px solid rgba(96, 165, 250, 0.3)',
            color: '#60a5fa',
            textTransform: 'uppercase',
            letterSpacing: '0.5px'
          }}>
            OBSERVED / DETERMINISTIC FACTS
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
          {/* Protocol Identification */}
          <div style={{ backgroundColor: '#1e293b', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
            <div style={{ fontSize: '13px', fontWeight: '600', color: '#94a3b8', marginBottom: '8px' }}>
              Protocols Detected
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {protocol_identification?.protocols_detected?.map((p) => (
                <span key={p} style={{ fontSize: '12px', fontWeight: '600', padding: '3px 8px', borderRadius: '4px', backgroundColor: '#0f172a', border: '1px solid #334155', color: '#38bdf8' }}>
                  {p}
                </span>
              )) || <span style={{ fontSize: '12px', color: '#64748b' }}>None</span>}
            </div>
            <div style={{ marginTop: '10px', fontSize: '12px', color: '#cbd5e1' }}>
              IP Versions: {protocol_identification?.ip_versions?.join(', ') || 'N/A'}
            </div>
          </div>

          {/* IKE Details */}
          <div style={{ backgroundColor: '#1e293b', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
            <div style={{ fontSize: '13px', fontWeight: '600', color: '#94a3b8', marginBottom: '8px' }}>
              IKE Negotiation
            </div>
            <div style={{ fontSize: '13px', color: '#f8fafc' }}>
              Detected: <strong style={{ color: ike?.detected ? '#4ade80' : '#94a3b8' }}>{ike?.detected ? `Yes (${ike.version || 'Unknown'})` : 'No'}</strong>
            </div>
            {ike?.detected && (
              <div style={{ marginTop: '6px', fontSize: '12px', color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div>Exchanges: {ike.exchange_types?.join(', ') || 'None'}</div>
                <div>Initiator SPI: <code style={{ color: '#38bdf8' }}>{ike.initiator_spi || 'N/A'}</code></div>
                <div>Encryption: {ike.encryption_algorithms?.join(', ') || 'Unobservable / Encrypted'}</div>
                <div>DH Groups: {ike.dh_groups?.join(', ') || 'Unobservable / Encrypted'}</div>
              </div>
            )}
          </div>

          {/* ESP Details */}
          <div style={{ backgroundColor: '#1e293b', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
            <div style={{ fontSize: '13px', fontWeight: '600', color: '#94a3b8', marginBottom: '8px' }}>
              ESP Payload Analysis
            </div>
            <div style={{ fontSize: '13px', color: '#f8fafc' }}>
              Detected: <strong style={{ color: esp?.detected ? '#4ade80' : '#94a3b8' }}>{esp?.detected ? `Yes (${esp.packet_count} packets)` : 'No'}</strong>
            </div>
            {esp?.detected && (
              <div style={{ marginTop: '6px', fontSize: '12px', color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div>Encapsulation: <strong style={{ color: '#f8fafc' }}>{esp.encapsulation}</strong></div>
                <div>Observed SPIs: {esp.spis?.map(s => <code key={s} style={{ color: '#38bdf8', marginRight: '6px' }}>{s}</code>) || 'None'}</div>
              </div>
            )}
          </div>

          {/* Inferred Mode */}
          <div style={{ backgroundColor: '#1e293b', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
            <div style={{ fontSize: '13px', fontWeight: '600', color: '#94a3b8', marginBottom: '8px' }}>
              Mode Inference
            </div>
            <div style={{ fontSize: '14px', fontWeight: '700', color: '#38bdf8' }}>
              Inferred Mode: {mode_inference?.inferred_mode?.value || 'Unknown'}
            </div>
            <div style={{ fontSize: '12px', color: '#cbd5e1', marginTop: '4px' }}>
              Confidence: {((mode_inference?.inferred_mode?.confidence || 0) * 100).toFixed(0)}%
            </div>
            {mode_inference?.inferred_mode?.evidence?.map((ev, i) => (
              <div key={i} style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>• {ev}</div>
            ))}
          </div>
        </div>
      </div>

      {/* TIER B: SECURITY ASSESSMENT ENGINE */}
      {security_assessment && (
        <div style={{
          backgroundColor: '#0f172a',
          borderRadius: '12px',
          border: '1px solid #1e293b',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldCheck style={{ width: '20px', height: '20px', color: getRiskColor(security_assessment.risk_level) }} />
              <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '600', color: '#f1f5f9' }}>
                Tier B: Security Assessment Engine (Phase 4)
              </h4>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{
                fontSize: '11px',
                fontWeight: '700',
                padding: '4px 10px',
                borderRadius: '12px',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                color: '#4ade80',
                textTransform: 'uppercase',
                letterSpacing: '0.5px'
              }}>
                POLICY-BASED SECURITY ASSESSMENT
              </span>
              <span style={{
                fontSize: '12px',
                fontWeight: '700',
                padding: '4px 12px',
                borderRadius: '12px',
                backgroundColor: `${getRiskColor(security_assessment.risk_level)}20`,
                border: `1px solid ${getRiskColor(security_assessment.risk_level)}40`,
                color: getRiskColor(security_assessment.risk_level)
              }}>
                {security_assessment.overall_status} (Risk: {security_assessment.risk_level})
              </span>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
            <div style={{ backgroundColor: '#1e293b', padding: '16px', borderRadius: '8px', textAlign: 'center' }}>
              <div style={{ fontSize: '12px', color: '#94a3b8' }}>Security Score</div>
              <div style={{ fontSize: '32px', fontWeight: '800', color: getRiskColor(security_assessment.risk_level), marginTop: '4px' }}>
                {security_assessment.security_score.toFixed(1)} <span style={{ fontSize: '16px', color: '#64748b' }}>/ 100</span>
              </div>
            </div>
            <div style={{ backgroundColor: '#1e293b', padding: '16px', borderRadius: '8px', display: 'flex', justifyContent: 'space-around', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '12px', color: '#4ade80', display: 'flex', alignItems: 'center', gap: '4px' }}><CheckCircle2 style={{ width: '14px' }} /> Passed</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#f8fafc' }}>{security_assessment.passed_checks}</div>
              </div>
              <div>
                <div style={{ fontSize: '12px', color: '#f87171', display: 'flex', alignItems: 'center', gap: '4px' }}><XCircle style={{ width: '14px' }} /> Failed</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#f8fafc' }}>{security_assessment.failed_checks}</div>
              </div>
              <div>
                <div style={{ fontSize: '12px', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '4px' }}><HelpCircle style={{ width: '14px' }} /> Unknown</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#f8fafc' }}>{security_assessment.unknown_checks}</div>
              </div>
            </div>
          </div>

          {/* Findings List */}
          {security_assessment.findings && security_assessment.findings.length > 0 && (
            <div style={{ marginTop: '8px' }}>
              <div style={{ fontSize: '14px', fontWeight: '600', color: '#f1f5f9', marginBottom: '12px' }}>
                Security Policy Checks & Findings
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {security_assessment.findings.map((f, i) => (
                  <div key={i} style={{
                    backgroundColor: '#1e293b',
                    borderRadius: '8px',
                    padding: '12px 16px',
                    borderLeft: `4px solid ${f.status === 'PASS' ? '#22c55e' : f.status === 'FAIL' ? '#ef4444' : f.status === 'WARNING' ? '#f59e0b' : '#64748b'}`
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ fontSize: '13px', fontWeight: '600', color: '#f8fafc' }}>
                        {f.title}
                      </span>
                      <span style={{ fontSize: '11px', fontWeight: '700', color: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? '#f87171' : '#94a3b8' }}>
                        [{f.severity}] {f.status}
                      </span>
                    </div>
                    <p style={{ margin: '0 0 6px', fontSize: '12px', color: '#cbd5e1' }}>
                      {f.description}
                    </p>
                    {f.recommendation && (
                      <div style={{ fontSize: '11px', color: '#38bdf8', backgroundColor: 'rgba(56,189,248,0.08)', padding: '6px 10px', borderRadius: '4px' }}>
                        💡 <strong>Recommendation:</strong> {f.recommendation}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TIER C: ML TRAFFIC CLASSIFICATION INFERENCE */}
      <div style={{
        backgroundColor: '#0f172a',
        borderRadius: '12px',
        border: '1px solid #1e293b',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Cpu style={{ width: '20px', height: '20px', color: '#a855f7' }} />
            <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '600', color: '#f1f5f9' }}>
              Tier C: ML Traffic Classification Inference (Phase 5)
            </h4>
          </div>
          <span style={{
            fontSize: '11px',
            fontWeight: '700',
            padding: '4px 10px',
            borderRadius: '12px',
            backgroundColor: 'rgba(168, 85, 247, 0.1)',
            border: '1px solid rgba(168, 85, 247, 0.3)',
            color: '#c084fc',
            textTransform: 'uppercase',
            letterSpacing: '0.5px'
          }}>
            ML Probabilistic Inference
          </span>
        </div>

        {/* Mandatory ML Disclaimer Notice Box */}
        <div style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '10px',
          padding: '12px 16px',
          backgroundColor: 'rgba(168, 85, 247, 0.08)',
          border: '1px solid rgba(168, 85, 247, 0.25)',
          borderRadius: '8px',
          color: '#e9d5ff',
          fontSize: '12px',
          lineHeight: '1.5'
        }}>
          <Info style={{ width: '18px', height: '18px', color: '#c084fc', flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>ML Inference Policy Notice:</strong>{' '}
            {traffic_classification?.disclaimer || "This classification is an ML model inference based on encrypted flow statistics and is NOT an observed protocol fact."}
          </div>
        </div>

        {traffic_classification ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Top metrics summary */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
              <div style={{ backgroundColor: '#1e293b', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>Inferred Dominant Class</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#c084fc', marginTop: '2px' }}>
                  {traffic_classification.dominant_class}
                </div>
              </div>
              <div style={{ backgroundColor: '#1e293b', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>Model Confidence</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#38bdf8', marginTop: '2px' }}>
                  {(traffic_classification.confidence * 100).toFixed(2)}%
                </div>
              </div>
              <div style={{ backgroundColor: '#1e293b', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>Flows Evaluated</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#f8fafc', marginTop: '2px' }}>
                  {traffic_classification.flow_count}
                </div>
              </div>
              <div style={{ backgroundColor: '#1e293b', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>ML Model Used</div>
                <div style={{ fontSize: '16px', fontWeight: '600', color: '#f8fafc', marginTop: '4px' }}>
                  {traffic_classification.model_used || 'Random Forest'}
                </div>
              </div>
            </div>

            {/* Probability distribution chart */}
            <div>
              <div style={{ fontSize: '13px', fontWeight: '600', color: '#f1f5f9', marginBottom: '10px' }}>
                Class Probability Distribution across Target Classes (Sums ≈ 1.0)
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {targetClasses.map((cname) => {
                  const prob = classProbs[cname] || 0.0;
                  const pct = (prob * 100).toFixed(2);
                  const isDominant = cname === traffic_classification.dominant_class;
                  return (
                    <div key={cname} style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '12px' }}>
                      <div style={{ width: '110px', color: isDominant ? '#c084fc' : '#94a3b8', fontWeight: isDominant ? '700' : '500' }}>
                        {cname} {isDominant && '★'}
                      </div>
                      <div style={{ flex: 1, backgroundColor: '#1e293b', borderRadius: '4px', height: '14px', overflow: 'hidden' }}>
                        <div style={{
                          width: `${pct}%`,
                          height: '100%',
                          backgroundColor: isDominant ? '#a855f7' : '#38bdf8',
                          transition: 'width 0.3s'
                        }} />
                      </div>
                      <div style={{ width: '50px', textAlign: 'right', color: '#cbd5e1', fontFamily: 'monospace' }}>
                        {prob.toFixed(4)}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        ) : (
          <div style={{ color: '#94a3b8', fontSize: '13px' }}>
            ML Traffic Classification unavailable for this capture.
          </div>
        )}
      </div>

      {analysis_warnings && analysis_warnings.length > 0 && (
        <div style={{ padding: '14px', backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', fontSize: '12px', color: '#94a3b8' }}>
          <strong>Analysis Warnings:</strong>
          <ul style={{ margin: '4px 0 0', paddingLeft: '20px' }}>
            {analysis_warnings.map((w, idx) => <li key={idx}>{w}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}
