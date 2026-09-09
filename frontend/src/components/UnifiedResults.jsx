import React, { useState } from 'react';
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
  Download,
  X,
  ExternalLink,
  ChevronRight,
  Sliders,
  Maximize2
} from 'lucide-react';
import StatusCard from './StatusCard';

export default function UnifiedResults({ result }) {
  const [activeModal, setActiveModal] = useState(null);

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

  const getRiskBadgeStyle = (risk) => {
    switch (risk?.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return { bg: '#F3E2E0', text: '#7D2822', border: '#E2B9B5', indicator: '#A94B43' };
      case 'MEDIUM':
        return { bg: '#F5EBD5', text: '#7E5B18', border: '#E6D3A7', indicator: '#B57B22' };
      case 'LOW':
      case 'SECURE':
      case 'PASS':
        return { bg: '#E3EEE7', text: '#245837', border: '#B6D7C2', indicator: '#3F7654' };
      default:
        return { bg: '#EDEAE1', text: '#555555', border: '#D8D4C8', indicator: '#596F7D' };
    }
  };

  const targetClasses = [
    'ICMP', 'Web Browsing', 'Email', 'Chat', 'Streaming', 'File Transfer', 'VoIP', 'P2P'
  ];

  const classProbs = traffic_classification?.class_probabilities || {};
  const riskStyle = getRiskBadgeStyle(security_assessment?.risk_level);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Overview Metadata Header */}
      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: '12px',
        border: '1px solid #D8D4C8',
        padding: '20px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px',
        boxShadow: '0 1px 3px rgba(0,0,0,0.03)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ padding: '10px', backgroundColor: '#F4E7B8', borderRadius: '8px', border: '1px solid #D6A928' }}>
            <FileCheck style={{ width: '22px', height: '22px', color: '#9A7618' }} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: '#252525' }}>
              DEEPSTATE Threat & Traffic Intelligence Report
            </h3>
            <span style={{ fontSize: '12px', color: '#666666', fontFamily: 'monospace' }}>
              Analysis Session ID: {analysis_id || 'N/A'}
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '13px', color: '#555555' }}>
          <div>File: <strong style={{ color: '#252525' }}>{pcap_metadata?.file_name || 'N/A'}</strong></div>
          <div>Packets: <strong style={{ color: '#252525' }}>{pcap_metadata?.packet_count || 0}</strong></div>
          <div>Duration: <strong style={{ color: '#252525' }}>{pcap_metadata?.duration_seconds ? `${pcap_metadata.duration_seconds}s` : 'N/A'}</strong></div>
          <div>Size: <strong style={{ color: '#252525' }}>{pcap_metadata?.file_size_bytes ? `${pcap_metadata.file_size_bytes} B` : 'N/A'}</strong></div>

          <button
            type="button"
            onClick={handleExportJson}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '6px',
              fontSize: '13px',
              fontWeight: '600',
              cursor: 'pointer',
              border: '1px solid #D8D4C8',
              backgroundColor: '#FFFFFF',
              color: '#252525',
              transition: 'all 0.15s ease'
            }}
            onMouseOver={(e) => e.currentTarget.style.backgroundColor = '#EDEAE1'}
            onMouseOut={(e) => e.currentTarget.style.backgroundColor = '#FFFFFF'}
          >
            <Download style={{ width: '14px', height: '14px', color: '#D6A928' }} />
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
        <div style={{ padding: '16px', backgroundColor: '#F3E2E0', border: '1px solid #E2B9B5', borderRadius: '8px', color: '#7D2822' }}>
          <strong>Analysis Errors:</strong>
          <ul style={{ margin: '8px 0 0', paddingLeft: '20px' }}>
            {errors.map((err, i) => <li key={i}>{err}</li>)}
          </ul>
        </div>
      )}

      {/* TIER A: PROTOCOL OBSERVATIONS */}
      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: '12px',
        border: '1px solid #D8D4C8',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '18px',
        boxShadow: '0 1px 3px rgba(0,0,0,0.03)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Lock style={{ width: '20px', height: '20px', color: '#596F7D' }} />
            <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
              Tier A: Deterministic Protocol Observations (Phase 3)
            </h4>
          </div>
          <span style={{
            fontSize: '11px',
            fontWeight: '700',
            padding: '4px 10px',
            borderRadius: '12px',
            backgroundColor: '#EDEAE1',
            border: '1px solid #D8D4C8',
            color: '#555555',
            textTransform: 'uppercase',
            letterSpacing: '0.5px'
          }}>
            OBSERVED / DETERMINISTIC FACTS
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
          {/* Protocol Identification */}
          <div style={{ backgroundColor: '#FFFDF8', padding: '16px', borderRadius: '8px', border: '1px solid #EDEAE1' }}>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#666666', marginBottom: '8px' }}>
              Protocols Detected
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {protocol_identification?.protocols_detected?.map((p) => (
                <span key={p} style={{ fontSize: '12px', fontWeight: '600', padding: '3px 8px', borderRadius: '4px', backgroundColor: '#F4F1E8', border: '1px solid #D8D4C8', color: '#252525' }}>
                  {p}
                </span>
              )) || <span style={{ fontSize: '12px', color: '#777777' }}>None</span>}
            </div>
            <div style={{ marginTop: '12px', fontSize: '12px', color: '#555555' }}>
              IP Versions: <strong>{protocol_identification?.ip_versions?.join(', ') || 'N/A'}</strong>
            </div>
          </div>

          {/* IKE Details */}
          <div style={{ backgroundColor: '#FFFDF8', padding: '16px', borderRadius: '8px', border: '1px solid #EDEAE1', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div style={{ fontSize: '13px', fontWeight: '700', color: '#666666' }}>IKE Negotiation</div>
                {ike?.detected && (
                  <button
                    onClick={() => setActiveModal('ike')}
                    style={{ fontSize: '11px', fontWeight: '600', color: '#9A7618', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '2px' }}
                  >
                    Investigate <ChevronRight style={{ width: '12px', height: '12px' }} />
                  </button>
                )}
              </div>
              <div style={{ fontSize: '13px', color: '#252525' }}>
                Detected: <strong style={{ color: ike?.detected ? '#3F7654' : '#777777' }}>{ike?.detected ? `Yes (${ike.version || 'Unknown'})` : 'No'}</strong>
              </div>
              {ike?.detected && (
                <div style={{ marginTop: '6px', fontSize: '12px', color: '#555555', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div>Exchanges: <strong>{ike.exchange_types?.join(', ') || 'None'}</strong></div>
                  <div>Initiator SPI: <code style={{ color: '#252525', backgroundColor: '#EDEAE1', padding: '2px 4px', borderRadius: '4px' }}>{ike.initiator_spi || 'N/A'}</code></div>
                </div>
              )}
            </div>
          </div>

          {/* ESP Details */}
          <div style={{ backgroundColor: '#FFFDF8', padding: '16px', borderRadius: '8px', border: '1px solid #EDEAE1', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div style={{ fontSize: '13px', fontWeight: '700', color: '#666666' }}>ESP Payload Analysis</div>
                {esp?.detected && (
                  <button
                    onClick={() => setActiveModal('esp')}
                    style={{ fontSize: '11px', fontWeight: '600', color: '#9A7618', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '2px' }}
                  >
                    Investigate <ChevronRight style={{ width: '12px', height: '12px' }} />
                  </button>
                )}
              </div>
              <div style={{ fontSize: '13px', color: '#252525' }}>
                Detected: <strong style={{ color: esp?.detected ? '#3F7654' : '#777777' }}>{esp?.detected ? `Yes (${esp.packet_count} packets)` : 'No'}</strong>
              </div>
              {esp?.detected && (
                <div style={{ marginTop: '6px', fontSize: '12px', color: '#555555', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div>Encapsulation: <strong>{esp.encapsulation}</strong></div>
                  <div>Observed SPIs: {esp.spis?.map(s => <code key={s} style={{ color: '#252525', backgroundColor: '#EDEAE1', padding: '2px 4px', borderRadius: '4px', marginRight: '4px' }}>{s}</code>) || 'None'}</div>
                </div>
              )}
            </div>
          </div>

          {/* Inferred Mode */}
          <div style={{ backgroundColor: '#FFFDF8', padding: '16px', borderRadius: '8px', border: '1px solid #EDEAE1' }}>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#666666', marginBottom: '8px' }}>
              Mode Inference
            </div>
            <div style={{ fontSize: '14px', fontWeight: '700', color: '#9A7618' }}>
              Inferred Mode: {mode_inference?.inferred_mode?.value || 'Unknown'}
            </div>
            <div style={{ fontSize: '12px', color: '#555555', marginTop: '4px' }}>
              Confidence: <strong>{((mode_inference?.inferred_mode?.confidence || 0) * 100).toFixed(0)}%</strong>
            </div>
            {mode_inference?.inferred_mode?.evidence?.map((ev, i) => (
              <div key={i} style={{ fontSize: '11px', color: '#666666', marginTop: '4px' }}>• {ev}</div>
            ))}
          </div>
        </div>
      </div>

      {/* TIER B: SECURITY ASSESSMENT ENGINE */}
      {security_assessment && (
        <div style={{
          backgroundColor: '#FFFFFF',
          borderRadius: '12px',
          border: '1px solid #D8D4C8',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '18px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.03)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldCheck style={{ width: '20px', height: '20px', color: riskStyle.indicator }} />
              <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                Tier B: Security Assessment Engine (Phase 4)
              </h4>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{
                fontSize: '11px',
                fontWeight: '700',
                padding: '4px 10px',
                borderRadius: '12px',
                backgroundColor: '#EDEAE1',
                border: '1px solid #D8D4C8',
                color: '#555555',
                textTransform: 'uppercase',
                letterSpacing: '0.5px'
              }}>
                POLICY-BASED EVALUATION
              </span>
              <span style={{
                fontSize: '12px',
                fontWeight: '700',
                padding: '4px 12px',
                borderRadius: '12px',
                backgroundColor: riskStyle.bg,
                border: `1px solid ${riskStyle.border}`,
                color: riskStyle.text
              }}>
                {security_assessment.overall_status} (Risk: {security_assessment.risk_level})
              </span>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
            <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '16px', borderRadius: '8px', textAlign: 'center', position: 'relative' }}>
              <div style={{ fontSize: '12px', color: '#666666', fontWeight: '600' }}>Security Score</div>
              <div style={{ fontSize: '32px', fontWeight: '800', color: riskStyle.indicator, marginTop: '4px' }}>
                {security_assessment.security_score.toFixed(1)} <span style={{ fontSize: '16px', color: '#777777' }}>/ 100</span>
              </div>
              <button
                onClick={() => setActiveModal('score')}
                style={{ fontSize: '11px', fontWeight: '600', color: '#9A7618', background: 'none', border: 'none', cursor: 'pointer', marginTop: '4px' }}
              >
                View Breakdown →
              </button>
            </div>

            <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '16px', borderRadius: '8px', display: 'flex', justifyContent: 'space-around', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '12px', color: '#3F7654', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <CheckCircle2 style={{ width: '14px' }} /> Passed
                </div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#252525', marginTop: '2px' }}>
                  {security_assessment.passed_checks}
                </div>
              </div>
              <div style={{ width: '1px', height: '36px', backgroundColor: '#EDEAE1' }} />
              <div>
                <div style={{ fontSize: '12px', color: '#A94B43', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <XCircle style={{ width: '14px' }} /> Failed
                </div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#252525', marginTop: '2px' }}>
                  {security_assessment.failed_checks}
                </div>
              </div>
              <div style={{ width: '1px', height: '36px', backgroundColor: '#EDEAE1' }} />
              <div>
                <div style={{ fontSize: '12px', color: '#666666', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <HelpCircle style={{ width: '14px' }} /> Unknown
                </div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#252525', marginTop: '2px' }}>
                  {security_assessment.unknown_checks}
                </div>
              </div>
            </div>
          </div>

          {/* Findings List */}
          {security_assessment.findings && security_assessment.findings.length > 0 && (
            <div style={{ marginTop: '8px' }}>
              <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525', marginBottom: '12px' }}>
                Security Policy Checks & Findings
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {security_assessment.findings.map((f, i) => {
                  const findingStyle = getRiskBadgeStyle(f.status === 'PASS' ? 'SECURE' : f.severity);
                  return (
                    <div key={i} style={{
                      backgroundColor: '#FFFDF8',
                      borderRadius: '8px',
                      padding: '14px 16px',
                      border: '1px solid #EDEAE1',
                      borderLeft: `4px solid ${findingStyle.indicator}`
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                        <span style={{ fontSize: '13px', fontWeight: '700', color: '#252525' }}>
                          {f.title}
                        </span>
                        <span style={{
                          fontSize: '11px',
                          fontWeight: '700',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          backgroundColor: findingStyle.bg,
                          color: findingStyle.text,
                          border: `1px solid ${findingStyle.border}`
                        }}>
                          [{f.severity}] {f.status}
                        </span>
                      </div>
                      <p style={{ margin: '0 0 8px', fontSize: '12px', color: '#555555', lineHeight: '1.4' }}>
                        {f.description}
                      </p>
                      {f.recommendation && (
                        <div style={{ fontSize: '12px', color: '#7E5B18', backgroundColor: '#FBF4E4', border: '1px solid #E8D7B2', padding: '8px 12px', borderRadius: '6px' }}>
                          💡 <strong>Recommendation:</strong> {f.recommendation}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TIER C: ML TRAFFIC CLASSIFICATION INFERENCE */}
      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: '12px',
        border: '1px solid #D8D4C8',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '18px',
        boxShadow: '0 1px 3px rgba(0,0,0,0.03)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Cpu style={{ width: '20px', height: '20px', color: '#9A7618' }} />
            <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
              Tier C: ML Traffic Classification Inference (Phase 5)
            </h4>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {traffic_classification && (
              <button
                onClick={() => setActiveModal('ml')}
                style={{ fontSize: '12px', fontWeight: '600', color: '#9A7618', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                Inspect ML Details <ExternalLink style={{ width: '12px', height: '12px' }} />
              </button>
            )}
            <span style={{
              fontSize: '11px',
              fontWeight: '700',
              padding: '4px 10px',
              borderRadius: '12px',
              backgroundColor: '#EDEAE1',
              border: '1px solid #D8D4C8',
              color: '#555555',
              textTransform: 'uppercase',
              letterSpacing: '0.5px'
            }}>
              ML PROBABILISTIC INFERENCE
            </span>
          </div>
        </div>

        {/* Mandatory ML Disclaimer Notice Box */}
        <div style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '10px',
          padding: '12px 16px',
          backgroundColor: '#FBF4E4',
          border: '1px solid #E8D7B2',
          borderRadius: '8px',
          color: '#7E5B18',
          fontSize: '12px',
          lineHeight: '1.5'
        }}>
          <Info style={{ width: '18px', height: '18px', color: '#9A7618', flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>ML Inference Policy Notice:</strong>{' '}
            {traffic_classification?.disclaimer || "This classification is an ML model inference based on encrypted flow statistics and is NOT an observed protocol fact."}
          </div>
        </div>

        {traffic_classification ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Top metrics summary */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
              <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '12px', color: '#666666', fontWeight: '600' }}>Inferred Dominant Class</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#9A7618', marginTop: '2px' }}>
                  {traffic_classification.dominant_class}
                </div>
              </div>
              <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '12px', color: '#666666', fontWeight: '600' }}>Model Confidence</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#252525', marginTop: '2px' }}>
                  {(traffic_classification.confidence * 100).toFixed(2)}%
                </div>
              </div>
              <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '12px', color: '#666666', fontWeight: '600' }}>Flows Evaluated</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#252525', marginTop: '2px' }}>
                  {traffic_classification.flow_count}
                </div>
              </div>
              <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '12px', color: '#666666', fontWeight: '600' }}>ML Model Used</div>
                <div style={{ fontSize: '16px', fontWeight: '600', color: '#252525', marginTop: '4px' }}>
                  {traffic_classification.model_used || 'Random Forest'}
                </div>
              </div>
            </div>

            {/* Probability distribution chart */}
            <div>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525', marginBottom: '10px' }}>
                Class Probability Distribution across Target Classes (Sums ≈ 1.0)
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {targetClasses.map((cname) => {
                  const prob = classProbs[cname] || 0.0;
                  const pct = (prob * 100).toFixed(2);
                  const isDominant = cname === traffic_classification.dominant_class;
                  return (
                    <div key={cname} style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '12px' }}>
                      <div style={{ width: '110px', color: isDominant ? '#9A7618' : '#555555', fontWeight: isDominant ? '700' : '500' }}>
                        {cname} {isDominant && '★'}
                      </div>
                      <div style={{ flex: 1, backgroundColor: '#EDEAE1', borderRadius: '4px', height: '14px', overflow: 'hidden' }}>
                        <div style={{
                          width: `${pct}%`,
                          height: '100%',
                          backgroundColor: isDominant ? '#D6A928' : '#596F7D',
                          transition: 'width 0.3s'
                        }} />
                      </div>
                      <div style={{ width: '50px', textAlign: 'right', color: '#252525', fontFamily: 'monospace' }}>
                        {prob.toFixed(4)}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        ) : (
          <div style={{ color: '#777777', fontSize: '13px' }}>
            ML Traffic Classification unavailable for this capture.
          </div>
        )}
      </div>

      {analysis_warnings && analysis_warnings.length > 0 && (
        <div style={{ padding: '14px', backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', borderRadius: '8px', fontSize: '12px', color: '#666666' }}>
          <strong>Analysis Warnings:</strong>
          <ul style={{ margin: '4px 0 0', paddingLeft: '20px' }}>
            {analysis_warnings.map((w, idx) => <li key={idx}>{w}</li>)}
          </ul>
        </div>
      )}

      {/* INVESTIGATION MODALS */}
      {activeModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(37, 37, 37, 0.4)',
          backdropFilter: 'blur(3px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '24px'
        }}>
          <div style={{
            backgroundColor: '#FFFFFF',
            borderRadius: '12px',
            border: '1px solid #D8D4C8',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
            width: '100%',
            maxWidth: activeModal === 'score' || activeModal === 'ml' ? '900px' : '720px',
            maxHeight: '85vh',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}>
            {/* Modal Header */}
            <div style={{
              padding: '16px 20px',
              borderBottom: '1px solid #EDEAE1',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              backgroundColor: '#FFFDF8'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Maximize2 style={{ width: '18px', height: '18px', color: '#9A7618' }} />
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                  {activeModal === 'ike' && 'IKE Handshake Deep Dive Investigation'}
                  {activeModal === 'esp' && 'ESP Encapsulation Deep Dive Investigation'}
                  {activeModal === 'score' && 'Security Risk Score Detailed Breakdown'}
                  {activeModal === 'ml' && 'ML Traffic Classification Flow Features'}
                </h3>
              </div>
              <button
                onClick={() => setActiveModal(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#666666', padding: '4px' }}
              >
                <X style={{ width: '20px', height: '20px' }} />
              </button>
            </div>

            {/* Modal Content */}
            <div style={{ padding: '20px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {activeModal === 'ike' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                    <div style={{ fontWeight: '700', marginBottom: '6px' }}>IKE Header Parameters</div>
                    <div>Version: <strong>{ike?.version || 'N/A'}</strong></div>
                    <div>Initiator SPI: <code style={{ backgroundColor: '#EDEAE1', padding: '2px 6px', borderRadius: '4px' }}>{ike?.initiator_spi || 'N/A'}</code></div>
                    <div>Responder SPI: <code style={{ backgroundColor: '#EDEAE1', padding: '2px 6px', borderRadius: '4px' }}>{ike?.responder_spi || 'N/A'}</code></div>
                  </div>

                  <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                    <div style={{ fontWeight: '700', marginBottom: '6px' }}>Observed Exchanges</div>
                    {ike?.exchange_types?.map((ex, i) => (
                      <div key={i} style={{ fontSize: '12px', color: '#252525', padding: '4px 0' }}>• {ex}</div>
                    )) || <div>No exchanges recorded.</div>}
                  </div>

                  <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                    <div style={{ fontWeight: '700', marginBottom: '6px' }}>Security Proposals</div>
                    <div>Encryption: <strong>{ike?.encryption_algorithms?.join(', ') || 'Encrypted / Unobservable'}</strong></div>
                    <div>Integrity: <strong>{ike?.integrity_algorithms?.join(', ') || 'Encrypted / Unobservable'}</strong></div>
                    <div>DH Groups: <strong>{ike?.dh_groups?.join(', ') || 'Encrypted / Unobservable'}</strong></div>
                  </div>
                </div>
              )}

              {activeModal === 'esp' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                    <div style={{ fontWeight: '700', marginBottom: '6px' }}>ESP Encapsulation Stats</div>
                    <div>Packet Count: <strong>{esp?.packet_count || 0}</strong></div>
                    <div>Encapsulation Type: <strong>{esp?.encapsulation || 'ESP'}</strong></div>
                  </div>

                  <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                    <div style={{ fontWeight: '700', marginBottom: '8px' }}>Observed Security Parameters Indexes (SPIs)</div>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                      <thead>
                        <tr style={{ backgroundColor: '#F4F1E8', borderBottom: '1px solid #D8D4C8', textAlign: 'left' }}>
                          <th style={{ padding: '8px' }}>Index</th>
                          <th style={{ padding: '8px' }}>Hex SPI Value</th>
                          <th style={{ padding: '8px' }}>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {esp?.spis?.map((spi, i) => (
                          <tr key={i} style={{ borderBottom: '1px solid #EDEAE1' }}>
                            <td style={{ padding: '8px' }}>#{i + 1}</td>
                            <td style={{ padding: '8px', fontFamily: 'monospace' }}>{spi}</td>
                            <td style={{ padding: '8px', color: '#3F7654', fontWeight: '600' }}>Active Flow</td>
                          </tr>
                        )) || (
                          <tr><td colSpan="3" style={{ padding: '8px', color: '#777777' }}>No SPIs detected</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {activeModal === 'score' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                    <div style={{ fontWeight: '700', marginBottom: '6px' }}>Scoring Methodology</div>
                    <p style={{ margin: 0, fontSize: '12px', color: '#555555' }}>
                      The Security Assessment Score is evaluated deterministically against NIST SP 800-77 / BSI TR-02102 IPsec guidelines.
                    </p>
                  </div>

                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ backgroundColor: '#F4F1E8', borderBottom: '1px solid #D8D4C8', textAlign: 'left' }}>
                        <th style={{ padding: '8px' }}>Rule Title</th>
                        <th style={{ padding: '8px' }}>Severity</th>
                        <th style={{ padding: '8px' }}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {security_assessment?.findings?.map((f, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid #EDEAE1' }}>
                          <td style={{ padding: '8px', fontWeight: '600' }}>{f.title}</td>
                          <td style={{ padding: '8px' }}>{f.severity}</td>
                          <td style={{ padding: '8px', color: f.status === 'PASS' ? '#3F7654' : '#A94B43', fontWeight: '700' }}>{f.status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {activeModal === 'ml' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                    <div style={{ fontWeight: '700', marginBottom: '6px' }}>ML Classification Details</div>
                    <div>Dominant Class: <strong style={{ color: '#9A7618' }}>{traffic_classification?.dominant_class}</strong></div>
                    <div>Confidence Score: <strong>{((traffic_classification?.confidence || 0) * 100).toFixed(2)}%</strong></div>
                    <div>Flow Count: <strong>{traffic_classification?.flow_count}</strong></div>
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div style={{
              padding: '12px 20px',
              borderTop: '1px solid #EDEAE1',
              display: 'flex',
              justifyContent: 'flex-end',
              backgroundColor: '#FFFDF8'
            }}>
              <button
                onClick={() => setActiveModal(null)}
                style={{
                  padding: '6px 16px',
                  borderRadius: '6px',
                  border: '1px solid #D8D4C8',
                  backgroundColor: '#252525',
                  color: '#FFFFFF',
                  fontWeight: '600',
                  cursor: 'pointer',
                  fontSize: '13px'
                }}
              >
                Close Investigation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
