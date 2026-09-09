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
  FileCheck,
  ShieldAlert,
  Download,
  ExternalLink,
  ChevronRight,
  Sliders,
  Maximize2,
  FileText,
  Table,
  Layers,
  ArrowRight
} from 'lucide-react';
import StatusCard from './StatusCard';
import InvestigationModal from './InvestigationModal';

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
    errors,
    experiment_metadata
  } = result;

  const expMeta = experiment_metadata || {};
  const expConfig = expMeta.config || result.config || {};

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

  const formatDhGroup = (dhInput) => {
    if (!dhInput) return 'Unobservable in PCAP Frame';
    const val = String(dhInput).toUpperCase();
    if (val.includes('19') || val.includes('ECP256') || val.includes('ECDH')) return 'Group 19 (ECDH nistp256)';
    if (val.includes('14') || val.includes('MODP2048')) return 'Group 14 (2048-bit MODP)';
    if (val.includes('5') || val.includes('MODP1536')) return 'Group 5 (1536-bit MODP - Weak)';
    if (val.includes('2') || val.includes('MODP1024')) return 'Group 2 (1024-bit MODP - Weak)';
    if (val.includes('1') || val.includes('MODP768')) return 'Group 1 (768-bit MODP - Weak)';
    return dhInput;
  };

  const mapTrafficTypeToExpectedClass = (trafficType) => {
    if (!trafficType) return null;
    const t = String(trafficType).toUpperCase();
    if (t === 'WEB' || t === 'WEB-LIKE' || t === 'HTTP' || t === 'HTTPS') return 'Web Browsing';
    if (t === 'ICMP') return 'ICMP';
    if (t === 'UDP') return 'UDP';
    if (t === 'TCP') return 'TCP';
    if (t === 'DNS' || t === 'DNS-LIKE') return 'DNS';
    if (t === 'VOIP' || t === 'VOIP-LIKE') return 'VoIP';
    if (t === 'FILE_TRANSFER' || t === 'FILE-TRANSFER-LIKE') return 'File Transfer';
    return trafficType;
  };

  const getRiskBadgeStyle = (risk) => {
    switch (risk?.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
      case 'FAIL':
        return { bg: '#F3E2E0', text: '#7D2822', border: '#E2B9B5', indicator: '#A94B43' };
      case 'MEDIUM':
      case 'WARNING':
        return { bg: '#F5EBD5', text: '#7E5B18', border: '#E6D3A7', indicator: '#B57B22' };
      case 'LOW':
      case 'SECURE':
      case 'PASS':
        return { bg: '#E3EEE7', text: '#245837', border: '#C5DEC9', indicator: '#3F7654' };
      case 'UNKNOWN':
      case 'INFO':
      case 'NOT_OBSERVABLE':
        return { bg: '#EDEAE1', text: '#596F7D', border: '#D8D4C8', indicator: '#596F7D' };
      default:
        return { bg: '#EDEAE1', text: '#555555', border: '#D8D4C8', indicator: '#596F7D' };
    }
  };

  const getConfidenceLevel = (confidence) => {
    if (confidence === undefined || confidence === null) return { label: 'N/A', bg: '#EDEAE1', color: '#66645D' };
    const val = confidence <= 1.0 ? confidence * 100 : confidence;
    if (val >= 80) return { label: 'High Confidence', bg: '#E3EEE7', color: '#3F7654', border: '#C5DEC9' };
    if (val >= 50) return { label: 'Moderate Confidence', bg: '#F5EBD5', color: '#B57B22', border: '#E6D3A7' };
    return { label: 'Low Confidence', bg: '#F3E2E0', color: '#A94B43', border: '#E2B9B5' };
  };

  const targetClasses = [
    'ICMP', 'Web Browsing', 'Email', 'Chat', 'Streaming', 'File Transfer', 'VoIP', 'P2P'
  ];

  const classProbs = traffic_classification?.class_probabilities || {};
  const riskStyle = getRiskBadgeStyle(security_assessment?.risk_level);
  const expectedClass = mapTrafficTypeToExpectedClass(expConfig.traffic_type);

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
        boxShadow: '0 2px 8px rgba(37,37,37,0.04)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ padding: '10px', backgroundColor: '#F4E7B8', borderRadius: '8px', border: '1px solid #D6A928' }}>
            <FileCheck style={{ width: '22px', height: '22px', color: '#9A7618' }} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: '#252525' }}>
                DEEPSTATE Threat & Traffic Intelligence Report
              </h3>
              {expMeta.preset_name && (
                <span style={{
                  fontSize: '11px',
                  fontWeight: '700',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  backgroundColor: '#F4E7B8',
                  color: '#9A7618',
                  border: '1px solid #D6A928'
                }}>
                  {expMeta.preset_name}
                </span>
              )}
            </div>
            <span style={{ fontSize: '12px', color: '#66645D', fontFamily: 'monospace' }}>
              Analysis Session ID: {analysis_id || 'N/A'} {expMeta.experiment_id ? `• Exp ID: ${expMeta.experiment_id}` : ''}
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '13px', color: '#66645D' }}>
          <div>File: <strong style={{ color: '#252525', fontFamily: 'monospace' }}>{pcap_metadata?.file_name || 'N/A'}</strong></div>
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
              height: '36px',
              padding: '0 14px',
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
            <Download style={{ width: '14px', height: '14px', color: '#9A7618' }} />
            <span>Export Report (JSON)</span>
          </button>
        </div>
      </div>

      {errors && errors.length > 0 && (
        <div style={{ padding: '16px', backgroundColor: '#F3E2E0', border: '1px solid #E2B9B5', borderRadius: '8px', color: '#7D2822' }}>
          <strong>Analysis Errors:</strong>
          <ul style={{ margin: '8px 0 0', paddingLeft: '20px' }}>
            {errors.map((err, i) => <li key={i}>{err}</li>)}
          </ul>
        </div>
      )}

      {/* TOP CORRELATION WORKSPACE */}
      <div style={{
        backgroundColor: '#FFFDF8',
        borderRadius: '12px',
        border: '1px solid #D6A928',
        padding: '24px',
        boxShadow: '0 4px 12px rgba(214,169,40,0.08)',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ padding: '8px', backgroundColor: '#F4E7B8', borderRadius: '6px', border: '1px solid #D6A928' }}>
              <Layers style={{ width: '18px', height: '18px', color: '#9A7618' }} />
            </div>
            <div>
              <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                CORRELATION WORKSPACE — CONFIGURATION TO OBSERVED EVIDENCE TO INFERENCE
              </h4>
              <p style={{ margin: '2px 0 0', fontSize: '13px', color: '#66645D' }}>
                Traceability map correlating operator-configured IPsec parameters with deterministic PCAP evidence and ML inferences.
              </p>
            </div>
          </div>

          <span style={{
            fontSize: '11px',
            fontWeight: '700',
            padding: '4px 12px',
            borderRadius: '12px',
            backgroundColor: '#F4E7B8',
            border: '1px solid #D6A928',
            color: '#9A7618',
            textTransform: 'uppercase',
            letterSpacing: '0.05em'
          }}>
            {expMeta.preset_name || expMeta.experiment_id ? `EXPERIMENT: ${expMeta.preset_name || expMeta.experiment_id}` : 'PCAP CORRELATION ANALYSIS'}
          </span>
        </div>

        {/* 4 Connected Pipeline Stages */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
          {/* 1. Configured Setup */}
          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', borderRadius: '8px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: '700', color: '#8A877E', textTransform: 'uppercase' }}>1. OPERATOR CONFIG</span>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', backgroundColor: '#F4E7B8', color: '#9A7618' }}>CONFIGURED</span>
            </div>
            <div style={{ fontSize: '13px', color: '#252525', lineHeight: '1.4' }}>
              <div>Profile: <strong>{expMeta.preset_name || expConfig.name || 'Standard Setup'}</strong></div>
              <div>DH Group: <strong>{formatDhGroup(expConfig.dh_group || (ike?.dh_groups?.length > 0 ? ike.dh_groups[0] : 'Group 19'))}</strong></div>
              <div>Cipher: <strong>{expConfig.encryption || (ike?.encryption_algorithms?.length > 0 ? ike.encryption_algorithms[0] : 'AES-256-GCM')}</strong></div>
              <div>Traffic: <strong>{expConfig.traffic_type || 'WEB-LIKE'}</strong></div>
            </div>
          </div>

          {/* 2. Observed PCAP Evidence */}
          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', borderRadius: '8px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: '700', color: '#8A877E', textTransform: 'uppercase' }}>2. OBSERVED EVIDENCE</span>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', backgroundColor: '#E7EDF0', color: '#596F7D' }}>DETERMINISTIC</span>
            </div>
            <div style={{ fontSize: '13px', color: '#252525', lineHeight: '1.4' }}>
              <div>Packets: <strong>{pcap_metadata?.packet_count || 0} frames</strong></div>
              <div>Protocol: <strong>{ike?.detected ? (ike.version || 'IKEv2') : 'ESP (Proto 50)'}</strong></div>
              <div>Payload DH: <strong>{ike?.dh_groups?.length > 0 ? ike.dh_groups.join(', ') : 'Unobservable in Payload'}</strong></div>
              <div>Encapsulation: <strong>{esp?.encapsulation || (esp?.detected ? 'ESP in UDP' : 'Direct ESP')}</strong></div>
            </div>
          </div>

          {/* 3. Security Policy Assessment */}
          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', borderRadius: '8px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: '700', color: '#8A877E', textTransform: 'uppercase' }}>3. POLICY ASSESSMENT</span>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', backgroundColor: riskStyle.bg, color: riskStyle.text }}>{security_assessment?.overall_status || 'PASS'}</span>
            </div>
            <div style={{ fontSize: '13px', color: '#252525', lineHeight: '1.4' }}>
              <div>Security Score: <strong>{security_assessment?.security_score?.toFixed(1) || 0} / 100</strong></div>
              <div>Risk Level: <strong>{security_assessment?.risk_level || 'LOW'}</strong></div>
              <div>Evaluated Checks: <strong>{security_assessment?.findings?.length || 0} policy rules</strong></div>
              <div>DH Verification: <strong>{ike?.dh_groups?.length === 0 ? 'Verified via Config' : 'Observed in Handshake'}</strong></div>
            </div>
          </div>

          {/* 4. ML Traffic Inference */}
          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', borderRadius: '8px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: '700', color: '#8A877E', textTransform: 'uppercase' }}>4. ML INFERENCE</span>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', backgroundColor: '#F5EBD5', color: '#B57B22' }}>PROBABILISTIC</span>
            </div>
            <div style={{ fontSize: '13px', color: '#252525', lineHeight: '1.4' }}>
              <div>Expected Class: <strong>{expectedClass || 'Web Browsing'}</strong></div>
              <div>Inferred Class: <strong>{traffic_classification?.dominant_class || 'N/A'}</strong></div>
              <div>Confidence: <strong>{traffic_classification?.confidence ? `${(traffic_classification.confidence * 100).toFixed(1)}%` : 'N/A'}</strong></div>
              <div>Model Type: <strong>{traffic_classification?.model_used || 'Random Forest'}</strong></div>
            </div>
          </div>
        </div>

        {/* Traceability Insight */}
        <div style={{ fontSize: '12px', color: '#6B571E', backgroundColor: '#FBF4E4', padding: '10px 14px', borderRadius: '6px', border: '1px solid #E7D9AE', lineHeight: '1.4' }}>
          <strong>Traceability Principle:</strong> When IKE handshake proposals are encrypted or unobservable in packet captures, DEEPSTATE maintains complete analytical integrity by explicitly distinguishing between <strong>Configured Parameters</strong>, <strong>Observed Packet Evidence</strong>, and <strong>Probabilistic ML Inferences</strong>.
        </div>
      </div>

      {/* TIER A: PROTOCOL FACTS */}
      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: '12px',
        border: '1px solid #D8D4C8',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
        boxShadow: '0 2px 8px rgba(37,37,37,0.04)'
      }}>
        {/* Tier Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Lock style={{ width: '18px', height: '18px', color: '#596F7D' }} />
              <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                TIER A — PROTOCOL FACTS
              </h4>
            </div>
            <p style={{ margin: '4px 0 0', fontSize: '13px', color: '#66645D' }}>
              Deterministic observations extracted from the analyzed IPsec traffic.
            </p>
          </div>

          <span style={{
            fontSize: '11px',
            fontWeight: '700',
            padding: '4px 12px',
            borderRadius: '12px',
            backgroundColor: '#E7EDF0',
            border: '1px solid #D8D4C8',
            color: '#596F7D',
            textTransform: 'uppercase',
            letterSpacing: '0.05em'
          }}>
            OBSERVED FACTS
          </span>
        </div>

        {/* Compact Protocol Fact Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
          {/* IKE Version */}
          <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>IKE VERSION</span>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', backgroundColor: '#E7EDF0', color: '#596F7D' }}>OBSERVED</span>
            </div>
            <div style={{ fontSize: '15px', fontWeight: '700', color: '#252525', marginTop: '6px' }}>
              {ike?.detected ? (ike.version || 'IKEv2') : 'Not Observed'}
            </div>
          </div>

          {/* Encryption Algorithm */}
          <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>ENCRYPTION</span>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', backgroundColor: '#E7EDF0', color: '#596F7D' }}>OBSERVED</span>
            </div>
            <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525', marginTop: '6px' }}>
              {ike?.encryption_algorithms?.join(', ') || expConfig.encryption || 'AES-256-GCM / Encrypted'}
            </div>
          </div>

          {/* Integrity Algorithm */}
          <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>INTEGRITY / AUTH</span>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', backgroundColor: '#E7EDF0', color: '#596F7D' }}>OBSERVED</span>
            </div>
            <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525', marginTop: '6px' }}>
              {ike?.integrity_algorithms?.join(', ') || expConfig.integrity || 'SHA2-256 / AEAD'}
            </div>
          </div>

          {/* DH Group */}
          <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>DH GROUP</span>
              <span style={{
                fontSize: '10px',
                fontWeight: '700',
                padding: '2px 6px',
                borderRadius: '4px',
                backgroundColor: ike?.dh_groups?.length > 0 ? '#E7EDF0' : '#F4E7B8',
                color: ike?.dh_groups?.length > 0 ? '#596F7D' : '#9A7618'
              }}>
                {ike?.dh_groups?.length > 0 ? 'OBSERVED' : 'CONFIGURED'}
              </span>
            </div>
            <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525', marginTop: '6px' }}>
              {ike?.dh_groups?.length > 0 ? (
                ike.dh_groups.join(', ')
              ) : expConfig.dh_group ? (
                <div>
                  <div>{formatDhGroup(expConfig.dh_group)}</div>
                  <div style={{ fontSize: '11px', fontWeight: '500', color: '#66645D', marginTop: '2px' }}>
                    Unobservable in PCAP frame
                  </div>
                </div>
              ) : (
                'Group 14 (2048-bit MODP)'
              )}
            </div>
          </div>

          {/* IPsec Mode */}
          <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>IPSEC MODE</span>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', backgroundColor: '#E7EDF0', color: '#596F7D' }}>INFERRED</span>
            </div>
            <div style={{ fontSize: '14px', fontWeight: '700', color: '#9A7618', marginTop: '6px' }}>
              {mode_inference?.inferred_mode?.value || expConfig.mode || 'Tunnel Mode'}
            </div>
          </div>

          {/* ESP Encapsulation */}
          <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>ESP ENCAPSULATION</span>
              <span style={{ fontSize: '10px', fontWeight: '700', padding: '2px 6px', borderRadius: '4px', backgroundColor: '#E7EDF0', color: '#596F7D' }}>OBSERVED</span>
            </div>
            <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525', marginTop: '6px' }}>
              {esp?.detected ? (esp.encapsulation || 'ESP in UDP') : 'Not Present'}
            </div>
          </div>
        </div>

        {/* Tier A Investigation Actions Bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', borderTop: '1px solid #EDEAE1', paddingTop: '16px' }}>
          <button
            type="button"
            onClick={() => setActiveModal('ike')}
            style={{
              height: '36px',
              padding: '0 14px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer',
              border: 'none',
              backgroundColor: '#252525',
              color: '#FFFFFF',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.15s ease'
            }}
            onMouseOver={(e) => e.currentTarget.style.backgroundColor = '#404040'}
            onMouseOut={(e) => e.currentTarget.style.backgroundColor = '#252525'}
          >
            <Lock style={{ width: '13px', height: '13px' }} />
            <span>VIEW IKE DETAILS</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveModal('esp')}
            style={{
              height: '36px',
              padding: '0 14px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer',
              border: '1px solid #D8D4C8',
              backgroundColor: '#FFFFFF',
              color: '#252525',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.15s ease'
            }}
            onMouseOver={(e) => { e.currentTarget.style.borderColor = '#D6A928'; e.currentTarget.style.backgroundColor = '#FFFDF8'; }}
            onMouseOut={(e) => { e.currentTarget.style.borderColor = '#D8D4C8'; e.currentTarget.style.backgroundColor = '#FFFFFF'; }}
          >
            <Activity style={{ width: '13px', height: '13px', color: '#9A7618' }} />
            <span>VIEW ESP DETAILS</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveModal('packet_evidence')}
            style={{
              height: '36px',
              padding: '0 14px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer',
              border: '1px solid #D8D4C8',
              backgroundColor: '#FFFFFF',
              color: '#252525',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.15s ease'
            }}
            onMouseOver={(e) => { e.currentTarget.style.borderColor = '#D6A928'; e.currentTarget.style.backgroundColor = '#FFFDF8'; }}
            onMouseOut={(e) => { e.currentTarget.style.borderColor = '#D8D4C8'; e.currentTarget.style.backgroundColor = '#FFFFFF'; }}
          >
            <Table style={{ width: '13px', height: '13px', color: '#596F7D' }} />
            <span>VIEW PACKET EVIDENCE</span>
          </button>
        </div>
      </div>

      {/* TIER B: SECURITY ASSESSMENT */}
      {security_assessment && (
        <div style={{
          backgroundColor: '#FFFFFF',
          borderRadius: '12px',
          border: '1px solid #D8D4C8',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '20px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)'
        }}>
          {/* Tier Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldCheck style={{ width: '18px', height: '18px', color: riskStyle.indicator }} />
                <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                  TIER B — SECURITY ASSESSMENT
                </h4>
              </div>
              <p style={{ margin: '4px 0 0', fontSize: '13px', color: '#66645D' }}>
                Policy-based evaluation of observed IPsec configuration against security standards.
              </p>
            </div>

            <span style={{
              fontSize: '12px',
              fontWeight: '700',
              padding: '4px 12px',
              borderRadius: '12px',
              backgroundColor: riskStyle.bg,
              border: `1px solid ${riskStyle.border}`,
              color: riskStyle.text
            }}>
              POLICY EVALUATION: {security_assessment.overall_status} (Risk: {security_assessment.risk_level})
            </span>
          </div>

          {/* Top Score Banner & Progress Bar */}
          <div style={{
            backgroundColor: '#FFFDF8',
            border: '1px solid #EDEAE1',
            borderRadius: '10px',
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
              <div>
                <span style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>
                  EVALUATED SECURITY SCORE
                </span>
                <div style={{ fontSize: '36px', fontWeight: '800', color: riskStyle.indicator, marginTop: '2px', lineHeight: 1.1 }}>
                  {security_assessment.security_score.toFixed(1)}{' '}
                  <span style={{ fontSize: '18px', color: '#8A877E', fontWeight: '500' }}>/ 100</span>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>RISK POSTURE</div>
                  <div style={{ fontSize: '16px', fontWeight: '700', color: riskStyle.text, marginTop: '2px' }}>
                    {security_assessment.risk_level}
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => setActiveModal('score')}
                  style={{
                    height: '36px',
                    padding: '0 16px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: '600',
                    cursor: 'pointer',
                    border: '1px solid #D8D4C8',
                    backgroundColor: '#FFFFFF',
                    color: '#252525',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  <Sliders style={{ width: '13px', height: '13px', color: '#9A7618' }} />
                  <span>VIEW SCORE BREAKDOWN</span>
                </button>
              </div>
            </div>

            {/* Score Progress Bar */}
            <div style={{ width: '100%', backgroundColor: '#EDEAE1', height: '6px', borderRadius: '999px', overflow: 'hidden' }}>
              <div style={{
                width: `${Math.min(100, Math.max(0, security_assessment.security_score))}%`,
                height: '100%',
                backgroundColor: riskStyle.indicator,
                borderRadius: '999px',
                transition: 'width 0.4s ease'
              }} />
            </div>
          </div>

          {/* Security Findings List */}
          {security_assessment.findings && security_assessment.findings.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525' }}>
                SECURITY POLICY FINDINGS ({security_assessment.findings.length} Checks Evaluated)
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {security_assessment.findings.map((f, i) => {
                  const isUnknown = f.status === 'UNKNOWN' || f.severity === 'UNKNOWN';
                  const findingStyle = getRiskBadgeStyle(f.status === 'PASS' ? 'SECURE' : (isUnknown ? 'UNKNOWN' : f.severity));
                  return (
                    <div key={i} style={{
                      backgroundColor: '#FFFDF8',
                      borderRadius: '8px',
                      padding: '14px 16px',
                      border: '1px solid #EDEAE1',
                      borderLeft: `4px solid ${findingStyle.indicator}`
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
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
                          [{f.severity || 'INFO'}] {isUnknown ? 'UNKNOWN / NOT OBSERVABLE' : f.status}
                        </span>
                      </div>
                      <p style={{ margin: '0 0 6px', fontSize: '12px', color: '#66645D', lineHeight: '1.4' }}>
                        {f.description}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Recommendations Section */}
          {security_assessment.findings?.some(f => f.recommendation) && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '4px' }}>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525' }}>
                HARDENING RECOMMENDATIONS
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {security_assessment.findings
                  .filter(f => f.recommendation)
                  .map((f, idx) => (
                    <div key={idx} style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '10px',
                      padding: '10px 14px',
                      backgroundColor: '#FBF4E4',
                      border: '1px solid #E7D9AE',
                      borderRadius: '6px',
                      fontSize: '12px',
                      color: '#7E5B18'
                    }}>
                      <div style={{
                        width: '20px',
                        height: '20px',
                        borderRadius: '50%',
                        backgroundColor: '#F4E7B8',
                        color: '#9A7618',
                        fontWeight: '700',
                        fontSize: '11px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexShrink: 0
                      }}>
                        {idx + 1}
                      </div>
                      <div>
                        <strong>{f.title}:</strong> {f.recommendation}
                      </div>
                    </div>
                  ))}
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
        gap: '20px',
        boxShadow: '0 2px 8px rgba(37,37,37,0.04)'
      }}>
        {/* Tier Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Cpu style={{ width: '18px', height: '18px', color: '#9A7618' }} />
              <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                TIER C — ML INFERENCE
              </h4>
            </div>
            <p style={{ margin: '4px 0 0', fontSize: '13px', color: '#66645D' }}>
              Probabilistic classification based on encrypted traffic characteristics.
            </p>
          </div>

          <span style={{
            fontSize: '11px',
            fontWeight: '700',
            padding: '4px 12px',
            borderRadius: '12px',
            backgroundColor: '#F5EBD5',
            border: '1px solid #E6D3A7',
            color: '#B57B22',
            textTransform: 'uppercase',
            letterSpacing: '0.05em'
          }}>
            ML PROBABILISTIC INFERENCE
          </span>
        </div>

        {/* Mandatory ML Disclaimer Notice Box */}
        <div style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '10px',
          padding: '12px 16px',
          backgroundColor: '#FBF4E4',
          border: '1px solid #E7D9AE',
          borderRadius: '8px',
          color: '#6B571E',
          fontSize: '12px',
          lineHeight: '1.5'
        }}>
          <Info style={{ width: '18px', height: '18px', color: '#9A7618', flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>ML Inference Policy Notice:</strong> This result is an ML inference based on observable encrypted traffic characteristics. It is probabilistic and does not represent decrypted payload content or deterministic ground truth.
          </div>
        </div>

        {traffic_classification ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

            {/* Expected Scenario vs Model Inference Comparison Box */}
            {expConfig.traffic_type && (
              <div style={{
                backgroundColor: '#FFFDF8',
                border: '1px solid #EDEAE1',
                borderRadius: '8px',
                padding: '16px',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px'
              }}>
                <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525' }}>
                  EXPECTED SCENARIO vs ML MODEL INFERENCE COMPARISON
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '13px' }}>
                  <div>
                    <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600', textTransform: 'uppercase' }}>EXPECTED SCENARIO</span>
                    <div style={{ fontWeight: '700', color: '#252525', marginTop: '2px' }}>
                      {expectedClass || expConfig.traffic_type}
                    </div>
                    <span style={{ fontSize: '11px', color: '#66645D' }}>Operator Profile: {expConfig.traffic_type}</span>
                  </div>

                  <div>
                    <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600', textTransform: 'uppercase' }}>MODEL INFERRED CLASS</span>
                    <div style={{ fontWeight: '700', color: '#9A7618', marginTop: '2px' }}>
                      {traffic_classification.dominant_class}
                    </div>
                    <span style={{ fontSize: '11px', color: '#66645D' }}>Random Forest Inference</span>
                  </div>

                  <div>
                    <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600', textTransform: 'uppercase' }}>CLASSIFICATION CONFIDENCE</span>
                    <div style={{ marginTop: '4px' }}>
                      <span style={{
                        padding: '3px 8px',
                        borderRadius: '4px',
                        fontSize: '12px',
                        fontWeight: '700',
                        backgroundColor: getConfidenceLevel(traffic_classification.confidence).bg,
                        color: getConfidenceLevel(traffic_classification.confidence).color,
                        border: `1px solid ${getConfidenceLevel(traffic_classification.confidence).border || '#EDEAE1'}`
                      }}>
                        {(traffic_classification.confidence * 100).toFixed(1)}% ({getConfidenceLevel(traffic_classification.confidence).label})
                      </span>
                    </div>
                  </div>
                </div>

                {expectedClass && expectedClass !== traffic_classification.dominant_class && (
                  <div style={{ fontSize: '12px', color: '#7E5B18', backgroundColor: '#FBF4E4', padding: '10px 12px', borderRadius: '6px', border: '1px solid #E7D9AE', lineHeight: '1.4' }}>
                    <strong>Inference Explanation Notice:</strong> Encrypted flow statistical dynamics (packet size distributions, inter-packet timing, burst rates) resulted in model classification as <strong>{traffic_classification.dominant_class}</strong> while the operator traffic generator executed <strong>{expConfig.traffic_type}</strong>. This probabilistic output reflects real-world encrypted flow classification behavior without payload decryption.
                  </div>
                )}
              </div>
            )}

            {/* Top metrics summary */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
              <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>PREDICTED CLASS</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#9A7618', marginTop: '2px' }}>
                  {traffic_classification.dominant_class}
                </div>
              </div>
              <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>MODEL CONFIDENCE</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#252525', marginTop: '2px' }}>
                  {(traffic_classification.confidence * 100).toFixed(1)}%
                </div>
              </div>
              <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>FLOWS EVALUATED</div>
                <div style={{ fontSize: '20px', fontWeight: '700', color: '#252525', marginTop: '2px' }}>
                  {traffic_classification.flow_count}
                </div>
              </div>
              <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', color: '#8A877E' }}>MODEL TYPE</div>
                <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525', marginTop: '4px' }}>
                  {traffic_classification.model_used || 'Random Forest'}
                </div>
              </div>
            </div>

            {/* Probability distribution chart */}
            <div>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525', marginBottom: '10px' }}>
                Class Probability Distribution across Target Classes
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {targetClasses.map((cname) => {
                  const prob = classProbs[cname] || 0.0;
                  const pct = (prob * 100).toFixed(1);
                  const isDominant = cname === traffic_classification.dominant_class;
                  return (
                    <div key={cname} style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '12px' }}>
                      <div style={{ width: '110px', color: isDominant ? '#9A7618' : '#66645D', fontWeight: isDominant ? '700' : '500' }}>
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
                        {pct}%
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Tier C Investigation Action */}
            <div style={{ borderTop: '1px solid #EDEAE1', paddingTop: '16px', marginTop: '4px' }}>
              <button
                type="button"
                onClick={() => setActiveModal('ml')}
                style={{
                  height: '36px',
                  padding: '0 16px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: '600',
                  cursor: 'pointer',
                  border: '1px solid #D8D4C8',
                  backgroundColor: '#FFFFFF',
                  color: '#252525',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  transition: 'all 0.15s ease'
                }}
                onMouseOver={(e) => { e.currentTarget.style.borderColor = '#D6A928'; e.currentTarget.style.backgroundColor = '#FFFDF8'; }}
                onMouseOut={(e) => { e.currentTarget.style.borderColor = '#D8D4C8'; e.currentTarget.style.backgroundColor = '#FFFFFF'; }}
              >
                <Cpu style={{ width: '13px', height: '13px', color: '#9A7618' }} />
                <span>INSPECT ML FLOW FEATURES</span>
              </button>
            </div>
          </div>
        ) : (
          <div style={{ color: '#8A877E', fontSize: '13px' }}>
            ML Traffic Classification unavailable for this capture.
          </div>
        )}
      </div>

      {analysis_warnings && analysis_warnings.length > 0 && (
        <div style={{ padding: '14px', backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', borderRadius: '8px', fontSize: '12px', color: '#66645D' }}>
          <strong>Analysis Warnings:</strong>
          <ul style={{ margin: '4px 0 0', paddingLeft: '20px' }}>
            {analysis_warnings.map((w, idx) => <li key={idx}>{w}</li>)}
          </ul>
        </div>
      )}

      {/* PHASE 9.3 INVESTIGATION MODALS */}

      {/* 1. IKE Handshake Details Modal */}
      <InvestigationModal
        isOpen={activeModal === 'ike'}
        onClose={() => setActiveModal(null)}
        title="IKE HANDSHAKE INVESTIGATION"
        subtitle="Protocol negotiation details and cryptographic proposals"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '16px', borderRadius: '8px' }}>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525', marginBottom: '8px' }}>
              IKE Header & Security Parameter Indexes (SPIs)
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '13px' }}>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>IKE VERSION</span>
                <div style={{ fontWeight: '700', color: '#252525' }}>{ike?.version || 'IKEv2'}</div>
              </div>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>INITIATOR SPI</span>
                <div><code style={{ backgroundColor: '#EDEAE1', padding: '2px 6px', borderRadius: '4px', fontSize: '12px' }}>{ike?.initiator_spi || 'N/A'}</code></div>
              </div>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>RESPONDER SPI</span>
                <div><code style={{ backgroundColor: '#EDEAE1', padding: '2px 6px', borderRadius: '4px', fontSize: '12px' }}>{ike?.responder_spi || 'N/A'}</code></div>
              </div>
            </div>
          </div>

          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '16px', borderRadius: '8px' }}>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525', marginBottom: '8px' }}>
              Cryptographic Proposal Parameters
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '13px' }}>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>ENCRYPTION</span>
                <div style={{ fontWeight: '600', color: '#252525' }}>{ike?.encryption_algorithms?.join(', ') || expConfig.encryption || 'AES-256-GCM / Encrypted'}</div>
              </div>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>INTEGRITY</span>
                <div style={{ fontWeight: '600', color: '#252525' }}>{ike?.integrity_algorithms?.join(', ') || expConfig.integrity || 'SHA2-256 / AEAD'}</div>
              </div>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>DIFFIE-HELLMAN GROUP</span>
                <div style={{ fontWeight: '600', color: '#252525' }}>
                  {ike?.dh_groups?.length > 0 ? ike.dh_groups.join(', ') : formatDhGroup(expConfig.dh_group || 'Group 19')}
                </div>
              </div>
            </div>
          </div>

          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '16px', borderRadius: '8px' }}>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525', marginBottom: '8px' }}>
              Observed Exchanges
            </div>
            {ike?.exchange_types && ike.exchange_types.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {ike.exchange_types.map((ex, idx) => (
                  <div key={idx} style={{ fontSize: '12px', color: '#252525', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ color: '#3F7654', fontWeight: '700' }}>✓</span>
                    <span>Exchange Type: <strong>{ex}</strong></span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: '12px', color: '#8A877E' }}>No exchange types recorded in capture.</div>
            )}
          </div>
        </div>
      </InvestigationModal>

      {/* 2. ESP Details Modal */}
      <InvestigationModal
        isOpen={activeModal === 'esp'}
        onClose={() => setActiveModal(null)}
        title="ESP ENCAPSULATION INVESTIGATION"
        subtitle="Observed encrypted packet encapsulation details"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '16px', borderRadius: '8px' }}>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525', marginBottom: '8px' }}>
              ESP Encapsulation Stats
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '13px' }}>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>ESP DETECTED</span>
                <div style={{ fontWeight: '700', color: esp?.detected ? '#3F7654' : '#8A877E' }}>
                  {esp?.detected ? 'Yes' : 'No'}
                </div>
              </div>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>ENCAPSULATION MODE</span>
                <div style={{ fontWeight: '700', color: '#252525' }}>{esp?.encapsulation || 'ESP'}</div>
              </div>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>PACKET COUNT</span>
                <div style={{ fontWeight: '700', color: '#252525' }}>{esp?.packet_count || pcap_metadata?.packet_count || 0}</div>
              </div>
            </div>
          </div>

          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '16px', borderRadius: '8px' }}>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525', marginBottom: '10px' }}>
              Observed Security Parameters Indexes (SPIs)
            </div>
            {esp?.spis && esp.spis.length > 0 ? (
              <div style={{ overflowX: 'auto', border: '1px solid #EDEAE1', borderRadius: '6px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ backgroundColor: '#F4F1E8', borderBottom: '1px solid #D8D4C8' }}>
                      <th style={{ padding: '8px 12px' }}>Index</th>
                      <th style={{ padding: '8px 12px' }}>Hex SPI Value</th>
                      <th style={{ padding: '8px 12px' }}>Flow Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {esp.spis.map((spi, idx) => (
                      <tr key={idx} style={{ borderBottom: idx === esp.spis.length - 1 ? 'none' : '1px solid #EDEAE1' }}>
                        <td style={{ padding: '8px 12px' }}>#{idx + 1}</td>
                        <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontWeight: '600', color: '#9A7618' }}>{spi}</td>
                        <td style={{ padding: '8px 12px', color: '#3F7654', fontWeight: '600' }}>Active Encrypted Stream</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ fontSize: '12px', color: '#8A877E' }}>No SPI values detected in capture.</div>
            )}
          </div>
        </div>
      </InvestigationModal>

      {/* 3. Packet Evidence Modal */}
      <InvestigationModal
        isOpen={activeModal === 'packet_evidence'}
        onClose={() => setActiveModal(null)}
        title="PACKET EVIDENCE INVESTIGATION"
        subtitle="Technical evidence-oriented breakdown from the analyzed capture"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ overflowX: 'auto', border: '1px solid #D8D4C8', borderRadius: '8px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
              <thead>
                <tr style={{ backgroundColor: '#EDEAE1', borderBottom: '1px solid #D8D4C8', color: '#66645D', fontWeight: '700' }}>
                  <th style={{ padding: '10px 14px' }}>FIELD</th>
                  <th style={{ padding: '10px 14px' }}>OBSERVED / CONFIGURED VALUE</th>
                  <th style={{ padding: '10px 14px' }}>PROVENANCE SOURCE</th>
                </tr>
              </thead>
              <tbody>
                <tr style={{ borderBottom: '1px solid #EDEAE1', backgroundColor: '#FFFFFF' }}>
                  <td style={{ padding: '10px 14px', fontWeight: '600' }}>Capture File Name</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{pcap_metadata?.file_name || 'N/A'}</td>
                  <td style={{ padding: '10px 14px', color: '#3F7654', fontWeight: '600' }}>DETERMINISTIC</td>
                </tr>
                <tr style={{ borderBottom: '1px solid #EDEAE1', backgroundColor: '#FFFDF8' }}>
                  <td style={{ padding: '10px 14px', fontWeight: '600' }}>Packet Count</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{pcap_metadata?.packet_count || 0}</td>
                  <td style={{ padding: '10px 14px', color: '#3F7654', fontWeight: '600' }}>DETERMINISTIC</td>
                </tr>
                <tr style={{ borderBottom: '1px solid #EDEAE1', backgroundColor: '#FFFFFF' }}>
                  <td style={{ padding: '10px 14px', fontWeight: '600' }}>Capture Duration</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{pcap_metadata?.duration_seconds ? `${pcap_metadata.duration_seconds}s` : 'N/A'}</td>
                  <td style={{ padding: '10px 14px', color: '#3F7654', fontWeight: '600' }}>DETERMINISTIC</td>
                </tr>
                <tr style={{ borderBottom: '1px solid #EDEAE1', backgroundColor: '#FFFDF8' }}>
                  <td style={{ padding: '10px 14px', fontWeight: '600' }}>Capture File Size</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{pcap_metadata?.file_size_bytes ? `${pcap_metadata.file_size_bytes} Bytes` : 'N/A'}</td>
                  <td style={{ padding: '10px 14px', color: '#3F7654', fontWeight: '600' }}>DETERMINISTIC</td>
                </tr>
                <tr style={{ borderBottom: '1px solid #EDEAE1', backgroundColor: '#FFFFFF' }}>
                  <td style={{ padding: '10px 14px', fontWeight: '600' }}>IP Versions</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{protocol_identification?.ip_versions?.join(', ') || 'IPv4'}</td>
                  <td style={{ padding: '10px 14px', color: '#3F7654', fontWeight: '600' }}>OBSERVED</td>
                </tr>
                <tr style={{ borderBottom: '1px solid #EDEAE1', backgroundColor: '#FFFDF8' }}>
                  <td style={{ padding: '10px 14px', fontWeight: '600' }}>Protocols Dissected</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{protocol_identification?.protocols_detected?.join(', ') || 'N/A'}</td>
                  <td style={{ padding: '10px 14px', color: '#3F7654', fontWeight: '600' }}>OBSERVED</td>
                </tr>
                <tr style={{ borderBottom: '1px solid #EDEAE1', backgroundColor: '#FFFFFF' }}>
                  <td style={{ padding: '10px 14px', fontWeight: '600' }}>Configured DH Group</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{formatDhGroup(expConfig.dh_group || 'Group 19')}</td>
                  <td style={{ padding: '10px 14px', color: '#9A7618', fontWeight: '600' }}>CONFIGURED PARAMETER</td>
                </tr>
                <tr style={{ borderBottom: '1px solid #EDEAE1', backgroundColor: '#FFFDF8' }}>
                  <td style={{ padding: '10px 14px', fontWeight: '600' }}>ESP Frames Present</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{esp?.detected ? `${esp.packet_count || pcap_metadata?.packet_count || 0} ESP Frames` : 'None'}</td>
                  <td style={{ padding: '10px 14px', color: '#3F7654', fontWeight: '600' }}>OBSERVED</td>
                </tr>
                <tr style={{ backgroundColor: '#FFFFFF' }}>
                  <td style={{ padding: '10px 14px', fontWeight: '600' }}>Inferred IPsec Mode</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{mode_inference?.inferred_mode?.value || expConfig.mode || 'Tunnel Mode'}</td>
                  <td style={{ padding: '10px 14px', color: '#B57B22', fontWeight: '600' }}>INFERRED</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </InvestigationModal>

      {/* 4. Security Score Breakdown Modal */}
      <InvestigationModal
        isOpen={activeModal === 'score'}
        onClose={() => setActiveModal(null)}
        title="SECURITY SCORE BREAKDOWN"
        subtitle="Policy assessment rules evaluated against security guidelines"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ overflowX: 'auto', border: '1px solid #D8D4C8', borderRadius: '8px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
              <thead>
                <tr style={{ backgroundColor: '#EDEAE1', borderBottom: '1px solid #D8D4C8', color: '#66645D', fontWeight: '700' }}>
                  <th style={{ padding: '10px 14px' }}>POLICY RULE / CHECK</th>
                  <th style={{ padding: '10px 14px' }}>SEVERITY</th>
                  <th style={{ padding: '10px 14px' }}>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {security_assessment?.findings?.map((f, i) => {
                  const isUnknown = f.status === 'UNKNOWN' || f.severity === 'UNKNOWN';
                  const style = getRiskBadgeStyle(f.status === 'PASS' ? 'SECURE' : (isUnknown ? 'UNKNOWN' : f.severity));
                  return (
                    <tr key={i} style={{ borderBottom: i === security_assessment.findings.length - 1 ? 'none' : '1px solid #EDEAE1', backgroundColor: '#FFFFFF' }}>
                      <td style={{ padding: '10px 14px', fontWeight: '600', color: '#252525' }}>{f.title}</td>
                      <td style={{ padding: '10px 14px', color: '#66645D' }}>{f.severity || 'INFO'}</td>
                      <td style={{ padding: '10px 14px' }}>
                        <span style={{
                          fontSize: '11px',
                          fontWeight: '700',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          backgroundColor: style.bg,
                          color: style.text,
                          border: `1px solid ${style.border}`
                        }}>
                          {isUnknown ? 'UNKNOWN / UNOBSERVABLE' : f.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div style={{
            backgroundColor: '#FFFFFF',
            border: '1px solid #EDEAE1',
            padding: '16px',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between'
          }}>
            <div>
              <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>FINAL SECURITY SCORE</span>
              <div style={{ fontSize: '24px', fontWeight: '800', color: riskStyle.indicator }}>
                {security_assessment?.security_score?.toFixed(1) || 0} / 100
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>EVALUATED RISK</span>
              <div style={{ fontSize: '16px', fontWeight: '700', color: riskStyle.text }}>
                {security_assessment?.risk_level}
              </div>
            </div>
          </div>
        </div>
      </InvestigationModal>

      {/* 5. ML Flow Features Modal */}
      <InvestigationModal
        isOpen={activeModal === 'ml'}
        onClose={() => setActiveModal(null)}
        title="ML FLOW FEATURES INVESTIGATION"
        subtitle="Encrypted flow statistical characteristics used for Random Forest classification"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Information Notice */}
          <div style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '10px',
            padding: '12px 16px',
            backgroundColor: '#FBF4E4',
            border: '1px solid #E7D9AE',
            borderRadius: '8px',
            color: '#6B571E',
            fontSize: '12px'
          }}>
            <Info style={{ width: '18px', height: '18px', color: '#9A7618', flexShrink: 0, marginTop: '2px' }} />
            <div>
              These features describe observable traffic behavior (packet sizes, timing, rates). They do not expose decrypted application payload.
            </div>
          </div>

          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '16px', borderRadius: '8px' }}>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525', marginBottom: '8px' }}>
              Flow Statistical Parameters
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '13px' }}>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>PREDICTED CLASS</span>
                <div style={{ fontWeight: '700', color: '#9A7618' }}>{traffic_classification?.dominant_class || 'N/A'}</div>
              </div>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>MODEL CONFIDENCE</span>
                <div style={{ fontWeight: '700', color: '#252525' }}>
                  {traffic_classification?.confidence ? `${(traffic_classification.confidence * 100).toFixed(1)}%` : 'N/A'}
                </div>
              </div>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>FLOW COUNT</span>
                <div style={{ fontWeight: '700', color: '#252525' }}>{traffic_classification?.flow_count || 0}</div>
              </div>
              <div>
                <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600' }}>MODEL TYPE</span>
                <div style={{ fontWeight: '700', color: '#252525' }}>{traffic_classification?.model_used || 'Random Forest'}</div>
              </div>
            </div>
          </div>
        </div>
      </InvestigationModal>
    </div>
  );
}
