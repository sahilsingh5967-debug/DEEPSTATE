import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  Cpu,
  Lock,
  ChevronRight,
  FlaskConical,
  Play,
  FileText,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  ArrowRight
} from 'lucide-react';

export default function Dashboard({
  analysisResult,
  onAnalyze,
  onNavigate,
  health,
  pcaps = [],
  onViewFullAnalysis
}) {
  const backendOk = health?.status === 'ok' || health?.status === 'healthy';

  const securityScore = analysisResult?.security_assessment?.security_score;
  const riskLevel = analysisResult?.security_assessment?.risk_level || 'UNEVALUATED';
  const packetCount = analysisResult?.pcap_metadata?.packet_count;
  const dominantClass = analysisResult?.traffic_classification?.dominant_class;
  const mlConfidence = analysisResult?.traffic_classification?.confidence;

  const getRiskStyle = (level) => {
    switch (level?.toUpperCase()) {
      case 'SECURE':
      case 'PASS':
      case 'LOW':
        return { bg: '#E3EEE7', text: '#3F7654', border: '#C5DEC9' };
      case 'MEDIUM':
      case 'WARNING':
        return { bg: '#F5EBD5', text: '#B57B22', border: '#E6D3A7' };
      case 'HIGH':
      case 'CRITICAL':
      case 'FAIL':
        return { bg: '#F3E2E0', text: '#A94B43', border: '#E2B9B5' };
      default:
        return { bg: '#EDEAE1', text: '#8A877E', border: '#D8D4C8' };
    }
  };

  const riskStyle = getRiskStyle(riskLevel);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

      {/* 4. DASHBOARD PAGE HEADER */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          {/* Breadcrumb */}
          <div style={{
            fontSize: '12px',
            fontWeight: '600',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            color: '#8A877E',
            marginBottom: '6px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}>
            <span>DEEPSTATE</span>
            <ChevronRight style={{ width: '12px', height: '12px' }} />
            <span style={{ color: '#9A7618' }}>Security Intelligence</span>
          </div>

          {/* Main Title */}
          <h1 style={{
            margin: '0 0 6px',
            fontSize: '30px',
            fontWeight: '700',
            lineHeight: '1.2',
            color: '#252525',
            letterSpacing: '-0.02em'
          }}>
            DEEPSTATE — IPsec VPN Security Intelligence Center
          </h1>

          {/* Subtitle */}
          <p style={{
            margin: 0,
            fontSize: '14px',
            color: '#66645D',
            maxWidth: '850px',
            lineHeight: '1.4'
          }}>
            Deterministic Protocol Parsing • Policy Security Assessment • Encrypted Traffic ML Classification
          </p>
        </div>

        {/* Primary Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            type="button"
            onClick={() => onNavigate('lab')}
            style={{
              height: '40px',
              padding: '0 18px',
              borderRadius: '8px',
              backgroundColor: '#D6A928',
              color: '#252525',
              fontWeight: '700',
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
              transition: 'background-color 0.15s ease'
            }}
            onMouseOver={(e) => e.currentTarget.style.backgroundColor = '#BF941F'}
            onMouseOut={(e) => e.currentTarget.style.backgroundColor = '#D6A928'}
          >
            <FlaskConical style={{ width: '15px', height: '15px', color: '#252525' }} />
            <span>Demonstration Lab</span>
          </button>

          <button
            type="button"
            onClick={() => onNavigate('analyze')}
            style={{
              height: '40px',
              padding: '0 18px',
              borderRadius: '8px',
              backgroundColor: '#FFFFFF',
              color: '#252525',
              border: '1px solid #D8D4C8',
              fontWeight: '600',
              fontSize: '13px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
              transition: 'all 0.15s ease'
            }}
            onMouseOver={(e) => e.currentTarget.style.backgroundColor = '#EDEAE1'}
            onMouseOut={(e) => e.currentTarget.style.backgroundColor = '#FFFFFF'}
          >
            <Play style={{ width: '14px', height: '14px', color: '#9A7618' }} />
            <span>Analyze PCAP</span>
          </button>
        </div>
      </div>

      {/* 5. KPI SECTION (4 Cards Row) */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '16px'
      }}>
        {/* KPI 1 — SECURITY SCORE */}
        <div style={{
          backgroundColor: '#FFFFFF',
          border: '1px solid #D8D4C8',
          borderRadius: '12px',
          padding: '20px',
          minHeight: '128px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
          position: 'relative',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          overflow: 'hidden'
        }}>
          {/* Accent Line */}
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: '3px',
            backgroundColor: '#D6A928'
          }} />
          <div style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#8A877E' }}>
            SECURITY SCORE
          </div>
          <div>
            <div style={{ fontSize: '28px', fontWeight: '700', color: '#252525', marginTop: '4px' }}>
              {securityScore !== undefined ? `${securityScore.toFixed(1)}` : '—'}{' '}
              <span style={{ fontSize: '15px', color: '#8A877E', fontWeight: '500' }}>/ 100</span>
            </div>
            <div style={{ fontSize: '13px', color: '#66645D', marginTop: '2px' }}>
              Overall security posture
            </div>
          </div>
        </div>

        {/* KPI 2 — OVERALL RISK POSTURE */}
        <div style={{
          backgroundColor: '#FFFFFF',
          border: '1px solid #D8D4C8',
          borderRadius: '12px',
          padding: '20px',
          minHeight: '128px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between'
        }}>
          <div style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#8A877E' }}>
            OVERALL RISK POSTURE
          </div>
          <div>
            <div style={{ marginTop: '6px' }}>
              <span style={{
                display: 'inline-block',
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '14px',
                fontWeight: '700',
                backgroundColor: riskStyle.bg,
                color: riskStyle.text,
                border: `1px solid ${riskStyle.border}`
              }}>
                {riskLevel}
              </span>
            </div>
            <div style={{ fontSize: '13px', color: '#66645D', marginTop: '8px' }}>
              Policy evaluation assessment
            </div>
          </div>
        </div>

        {/* KPI 3 — PACKETS ANALYZED */}
        <div style={{
          backgroundColor: '#FFFFFF',
          border: '1px solid #D8D4C8',
          borderRadius: '12px',
          padding: '20px',
          minHeight: '128px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between'
        }}>
          <div style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#8A877E' }}>
            PACKETS ANALYZED
          </div>
          <div>
            <div style={{ fontSize: '28px', fontWeight: '700', color: '#252525', marginTop: '4px' }}>
              {packetCount !== undefined ? packetCount.toLocaleString() : '0'}
            </div>
            <div style={{ fontSize: '13px', color: '#66645D', marginTop: '2px' }}>
              {analysisResult?.pcap_metadata?.file_name || 'No capture loaded'}
            </div>
          </div>
        </div>

        {/* KPI 4 — ENCRYPTED ML CLASSIFICATION */}
        <div style={{
          backgroundColor: '#FFFFFF',
          border: '1px solid #D8D4C8',
          borderRadius: '12px',
          padding: '20px',
          minHeight: '128px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between'
        }}>
          <div style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#8A877E' }}>
            ENCRYPTED ML CLASSIFICATION
          </div>
          <div>
            <div style={{ fontSize: '22px', fontWeight: '700', color: '#252525', marginTop: '4px' }}>
              {dominantClass || 'N/A'}
            </div>
            <div style={{ fontSize: '13px', color: '#66645D', marginTop: '2px' }}>
              {mlConfidence !== undefined ? `${(mlConfidence * 100).toFixed(1)}% confidence` : 'Random Forest Model'}
            </div>
          </div>
        </div>
      </div>

      {/* 6. PRIMARY ANALYSIS WORKSPACE (Desktop: ~2/3 + 1/3 Grid) */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 2fr) minmax(320px, 1fr)',
        gap: '16px'
      }}>

        {/* 7. CURRENT ANALYSIS CARD */}
        <div style={{
          backgroundColor: '#FFFFFF',
          border: '1px solid #D8D4C8',
          borderRadius: '12px',
          padding: '24px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          gap: '20px'
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                CURRENT ANALYSIS
              </h3>
              {analysisResult && (
                <span style={{ fontSize: '12px', fontFamily: 'monospace', color: '#8A877E' }}>
                  ID: {analysisResult.analysis_id}
                </span>
              )}
            </div>
            <p style={{ margin: 0, fontSize: '13px', color: '#66645D' }}>
              Latest analyzed PCAP and three-tier security intelligence.
            </p>
          </div>

          {analysisResult ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {/* TIER A */}
              <div style={{
                backgroundColor: '#FFFDF8',
                border: '1px solid #EDEAE1',
                borderRadius: '8px',
                padding: '14px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}>
                <div>
                  <span style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#8A877E' }}>
                    TIER A
                  </span>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525' }}>
                    Protocol Facts
                  </div>
                  <div style={{ fontSize: '12px', color: '#66645D', marginTop: '2px' }}>
                    Protocols: <strong>{analysisResult.protocol_identification?.protocols_detected?.join(', ') || 'None'}</strong> • IKE: <strong>{analysisResult.ike?.detected ? `v${analysisResult.ike.version}` : 'None'}</strong> • ESP: <strong>{analysisResult.esp?.detected ? `${analysisResult.esp.packet_count} pkts` : 'None'}</strong>
                  </div>
                </div>
                <span style={{
                  fontSize: '11px',
                  fontWeight: '600',
                  padding: '3px 8px',
                  borderRadius: '6px',
                  backgroundColor: '#E7EDF0',
                  color: '#596F7D',
                  border: '1px solid #D8D4C8'
                }}>
                  OBSERVED
                </span>
              </div>

              {/* TIER B */}
              <div style={{
                backgroundColor: '#FFFDF8',
                border: '1px solid #EDEAE1',
                borderRadius: '8px',
                padding: '14px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}>
                <div>
                  <span style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#8A877E' }}>
                    TIER B
                  </span>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525' }}>
                    Security Assessment
                  </div>
                  <div style={{ fontSize: '12px', color: '#66645D', marginTop: '2px' }}>
                    Score: <strong>{analysisResult.security_assessment?.security_score?.toFixed(1) || 0}/100</strong> • Passed: <strong style={{ color: '#3F7654' }}>{analysisResult.security_assessment?.passed_checks || 0}</strong> • Failed: <strong style={{ color: '#A94B43' }}>{analysisResult.security_assessment?.failed_checks || 0}</strong>
                  </div>
                </div>
                <span style={{
                  fontSize: '11px',
                  fontWeight: '600',
                  padding: '3px 8px',
                  borderRadius: '6px',
                  backgroundColor: riskStyle.bg,
                  color: riskStyle.text,
                  border: `1px solid ${riskStyle.border}`
                }}>
                  {analysisResult.security_assessment?.overall_status || 'EVALUATED'}
                </span>
              </div>

              {/* TIER C */}
              <div style={{
                backgroundColor: '#FFFDF8',
                border: '1px solid #EDEAE1',
                borderRadius: '8px',
                padding: '14px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}>
                <div>
                  <span style={{ fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#8A877E' }}>
                    TIER C
                  </span>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525' }}>
                    ML Classification
                  </div>
                  <div style={{ fontSize: '12px', color: '#66645D', marginTop: '2px' }}>
                    Class: <strong style={{ color: '#9A7618' }}>{analysisResult.traffic_classification?.dominant_class || 'N/A'}</strong> • Confidence: <strong>{((analysisResult.traffic_classification?.confidence || 0) * 100).toFixed(1)}%</strong> • Flows: <strong>{analysisResult.traffic_classification?.flow_count || 0}</strong>
                  </div>
                </div>
                <span style={{
                  fontSize: '11px',
                  fontWeight: '600',
                  padding: '3px 8px',
                  borderRadius: '6px',
                  backgroundColor: '#F5EBD5',
                  color: '#B57B22',
                  border: '1px solid #E6D3A7'
                }}>
                  INFERRED
                </span>
              </div>

              <div style={{ marginTop: '6px' }}>
                <button
                  type="button"
                  onClick={onViewFullAnalysis}
                  style={{
                    height: '38px',
                    padding: '0 16px',
                    borderRadius: '8px',
                    backgroundColor: '#FFFFFF',
                    border: '1px solid #D8D4C8',
                    color: '#252525',
                    fontSize: '13px',
                    fontWeight: '600',
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseOver={(e) => e.currentTarget.style.backgroundColor = '#EDEAE1'}
                  onMouseOut={(e) => e.currentTarget.style.backgroundColor = '#FFFFFF'}
                >
                  <span>VIEW FULL ANALYSIS</span>
                  <ArrowRight style={{ width: '14px', height: '14px', color: '#9A7618' }} />
                </button>
              </div>
            </div>
          ) : (
            <div style={{
              backgroundColor: '#FFFDF8',
              border: '1px solid #EDEAE1',
              borderRadius: '8px',
              padding: '24px',
              textAlign: 'center',
              color: '#66645D',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '12px'
            }}>
              <ShieldAlert style={{ width: '28px', height: '28px', color: '#8A877E' }} />
              <div>
                <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525' }}>
                  No PCAP analyses available in active workspace
                </div>
                <div style={{ fontSize: '13px', color: '#66645D', marginTop: '4px' }}>
                  Analyze a PCAP or run a Demonstration Lab experiment to populate this workspace.
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px', marginTop: '6px' }}>
                <button
                  type="button"
                  onClick={() => onNavigate('analyze')}
                  style={{
                    height: '36px',
                    padding: '0 14px',
                    borderRadius: '8px',
                    backgroundColor: '#D6A928',
                    color: '#252525',
                    fontSize: '12px',
                    fontWeight: '700',
                    border: 'none',
                    cursor: 'pointer'
                  }}
                >
                  Analyze PCAP
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate('lab')}
                  style={{
                    height: '36px',
                    padding: '0 14px',
                    borderRadius: '8px',
                    backgroundColor: '#FFFFFF',
                    border: '1px solid #D8D4C8',
                    color: '#252525',
                    fontSize: '12px',
                    fontWeight: '600',
                    cursor: 'pointer'
                  }}
                >
                  Demonstration Lab
                </button>
              </div>
            </div>
          )}
        </div>

        {/* 8. SYSTEM STATUS CARD */}
        <div style={{
          backgroundColor: '#FFFFFF',
          border: '1px solid #D8D4C8',
          borderRadius: '12px',
          padding: '24px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px'
        }}>
          <div>
            <h3 style={{ margin: '0 0 4px', fontSize: '16px', fontWeight: '700', color: '#252525' }}>
              SYSTEM STATUS
            </h3>
            <p style={{ margin: 0, fontSize: '13px', color: '#66645D' }}>
              Operational subsystem readiness
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {/* Row 1: Backend */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px', backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', borderRadius: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: '600', color: '#252525' }}>Backend</span>
              <span style={{
                fontSize: '12px',
                fontWeight: '600',
                padding: '3px 10px',
                borderRadius: '6px',
                backgroundColor: backendOk ? '#E3EEE7' : '#F3E2E0',
                color: backendOk ? '#3F7654' : '#A94B43',
                border: `1px solid ${backendOk ? '#C5DEC9' : '#E2B9B5'}`
              }}>
                {backendOk ? 'Operational' : 'Offline'}
              </span>
            </div>

            {/* Row 2: Analysis Pipeline */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px', backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', borderRadius: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: '600', color: '#252525' }}>Analysis Pipeline</span>
              <span style={{
                fontSize: '12px',
                fontWeight: '600',
                padding: '3px 10px',
                borderRadius: '6px',
                backgroundColor: '#F4E7B8',
                color: '#9A7618',
                border: '1px solid #E3D08C'
              }}>
                Ready
              </span>
            </div>

            {/* Row 3: Frontend */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px', backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', borderRadius: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: '600', color: '#252525' }}>Frontend</span>
              <span style={{
                fontSize: '12px',
                fontWeight: '600',
                padding: '3px 10px',
                borderRadius: '6px',
                backgroundColor: '#E3EEE7',
                color: '#3F7654',
                border: '1px solid #C5DEC9'
              }}>
                Operational
              </span>
            </div>

            {/* Row 4: Test Suite */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px', backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', borderRadius: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: '600', color: '#252525' }}>Test Suite</span>
              <span style={{
                fontSize: '12px',
                fontWeight: '600',
                padding: '3px 10px',
                borderRadius: '6px',
                backgroundColor: '#E3EEE7',
                color: '#3F7654',
                border: '1px solid #C5DEC9'
              }}>
                111 / 111 Passing
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 9. RECENT PCAPS SECTION */}
      <div style={{
        backgroundColor: '#FFFFFF',
        border: '1px solid #D8D4C8',
        borderRadius: '12px',
        padding: '24px',
        boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h3 style={{ margin: '0 0 4px', fontSize: '16px', fontWeight: '700', color: '#252525' }}>
              RECENT PCAPS
            </h3>
            <p style={{ margin: 0, fontSize: '13px', color: '#66645D' }}>
              Preset PCAP dataset library and past session captures.
            </p>
          </div>

          <button
            type="button"
            onClick={() => onNavigate('library')}
            style={{
              fontSize: '13px',
              fontWeight: '600',
              color: '#9A7618',
              backgroundColor: 'transparent',
              border: 'none',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '4px'
            }}
          >
            <span>VIEW PCAP LIBRARY</span>
            <ArrowRight style={{ width: '14px', height: '14px' }} />
          </button>
        </div>

        {pcaps && pcaps.length > 0 ? (
          <div style={{ overflowX: 'auto', border: '1px solid #D8D4C8', borderRadius: '8px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
              <thead>
                <tr style={{ backgroundColor: '#EDEAE1', borderBottom: '1px solid #D8D4C8', color: '#66645D', fontSize: '12px', fontWeight: '700' }}>
                  <th style={{ padding: '10px 14px' }}>Filename</th>
                  <th style={{ padding: '10px 14px' }}>Packets / Size</th>
                  <th style={{ padding: '10px 14px' }}>Risk</th>
                  <th style={{ padding: '10px 14px' }}>ML Class</th>
                  <th style={{ padding: '10px 14px' }}>Category</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {pcaps.slice(0, 5).map((p, idx) => (
                  <tr key={p.id || idx} style={{ borderBottom: idx === Math.min(pcaps.length, 5) - 1 ? 'none' : '1px solid #EDEAE1', backgroundColor: '#FFFFFF' }}>
                    <td style={{ padding: '10px 14px', fontWeight: '600', color: '#252525', fontFamily: 'monospace' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <FileText style={{ width: '14px', height: '14px', color: '#9A7618' }} />
                        <span>{p.name}</span>
                      </div>
                    </td>
                    <td style={{ padding: '10px 14px', color: '#66645D', fontFamily: 'monospace' }}>
                      {p.size_bytes ? `${p.size_bytes} B` : 'Preset'}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{
                        fontSize: '11px',
                        fontWeight: '600',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        backgroundColor: '#EDEAE1',
                        color: '#66645D'
                      }}>
                        {p.category === 'real' ? 'TEST FIXTURE' : 'PRESET'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px', color: '#66645D' }}>
                      Random Forest Target
                    </td>
                    <td style={{ padding: '10px 14px', color: '#8A877E' }}>
                      {p.category}
                    </td>
                    <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                      <button
                        type="button"
                        onClick={() => onAnalyze(p.file_path)}
                        style={{
                          padding: '5px 12px',
                          borderRadius: '6px',
                          fontSize: '12px',
                          fontWeight: '600',
                          backgroundColor: '#F4E7B8',
                          border: '1px solid #D6A928',
                          color: '#252525',
                          cursor: 'pointer'
                        }}
                      >
                        ANALYZE
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{
            backgroundColor: '#FFFDF8',
            border: '1px solid #EDEAE1',
            borderRadius: '8px',
            padding: '24px',
            textAlign: 'center',
            color: '#66645D',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '12px'
          }}>
            <div>
              <div style={{ fontSize: '14px', fontWeight: '700', color: '#252525' }}>
                No PCAP analyses available
              </div>
              <div style={{ fontSize: '13px', color: '#66645D', marginTop: '4px' }}>
                Analyze a PCAP or run a Demonstration Lab experiment to populate this workspace.
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', marginTop: '6px' }}>
              <button
                type="button"
                onClick={() => onNavigate('analyze')}
                style={{
                  height: '36px',
                  padding: '0 14px',
                  borderRadius: '8px',
                  backgroundColor: '#D6A928',
                  color: '#252525',
                  fontSize: '12px',
                  fontWeight: '700',
                  border: 'none',
                  cursor: 'pointer'
                }}
              >
                Analyze PCAP
              </button>
              <button
                type="button"
                onClick={() => onNavigate('lab')}
                style={{
                  height: '36px',
                  padding: '0 14px',
                  borderRadius: '8px',
                  backgroundColor: '#FFFFFF',
                  border: '1px solid #D8D4C8',
                  color: '#252525',
                  fontSize: '12px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                Demonstration Lab
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
