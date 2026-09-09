import React, { useState, useEffect } from 'react';
import {
  FlaskConical, Play, CheckCircle2, AlertTriangle, Info, Server,
  Shield, Cpu, Activity, History, ArrowRight, X, Sliders, RefreshCw
} from 'lucide-react';
import {
  fetchTestbedOptions, fetchTestbedStatus, validateExperimentConfig,
  executeExperimentRun, fetchExperimentHistory, analyzeExperimentRecord
} from '../api/client';

export default function DemonstrationLab({ onAnalyzeResult }) {
  const [options, setOptions] = useState(null);
  const [testbedStatus, setTestbedStatus] = useState(null);
  const [history, setHistory] = useState([]);
  const [selectedPreset, setSelectedPreset] = useState('SECURE_ENTERPRISE');

  const [config, setConfig] = useState({
    name: 'Secure Enterprise VPN',
    ike_version: 'IKEv2',
    mode: 'tunnel',
    encryption: 'AES-256-GCM',
    integrity: 'NONE',
    dh_group: 'ECP256',
    traffic_type: 'WEB',
    destination_port: 443,
    packet_count: 50,
    packet_rate: 20,
    payload_size: 512,
    duration: 5,
    execution_mode: 'auto'
  });

  const [validation, setValidation] = useState(null);
  const [executing, setExecuting] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [executionResult, setExecutionResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [infoModal, setInfoModal] = useState(null);

  useEffect(() => {
    async function loadData() {
      const [opts, st, hist] = await Promise.all([
        fetchTestbedOptions(),
        fetchTestbedStatus(),
        fetchExperimentHistory()
      ]);
      if (opts) setOptions(opts);
      if (st) setTestbedStatus(st);
      if (hist) setHistory(hist);
    }
    loadData();
  }, []);

  const handleSelectPreset = (presetId) => {
    setSelectedPreset(presetId);
    if (!options || !options.presets) return;
    const preset = options.presets.find(p => p.preset_id === presetId);
    if (preset && preset.config) {
      setConfig({ ...preset.config });
      setValidation(null);
      setExecutionResult(null);
      setErrorMsg('');
    }
  };

  const handleValidate = async () => {
    setErrorMsg('');
    const res = await validateExperimentConfig(config);
    setValidation(res);
    return res;
  };

  const handleRunExperiment = async () => {
    setExecuting(true);
    setErrorMsg('');
    setExecutionResult(null);
    setCurrentStep(1);

    try {
      // Step 1: Validate
      const val = await handleValidate();
      if (val && !val.valid) {
        throw new Error(val.errors.join(', '));
      }
      setCurrentStep(2); // Peer verification
      await new Promise(r => setTimeout(r, 600));

      setCurrentStep(3); // Initiate SA
      await new Promise(r => setTimeout(r, 800));

      setCurrentStep(4); // Start capture & traffic
      const result = await executeExperimentRun(config);
      setCurrentStep(5); // Finalize PCAP
      await new Promise(r => setTimeout(r, 400));

      setCurrentStep(6); // Done
      setExecutionResult(result);

      // Refresh history
      const updatedHist = await fetchExperimentHistory();
      setHistory(updatedHist);
    } catch (err) {
      setErrorMsg(err.message || 'Experiment execution failed.');
    } finally {
      setExecuting(false);
    }
  };

  const handleAnalyzeHandoff = async (expId) => {
    try {
      setExecuting(true);
      setErrorMsg('');
      const analysisData = await analyzeExperimentRecord(expId || executionResult.experiment_id);
      if (onAnalyzeResult) {
        onAnalyzeResult(analysisData);
      }
    } catch (err) {
      setErrorMsg(err.message || 'Analysis handoff failed.');
    } finally {
      setExecuting(false);
    }
  };

  const openInfoModal = (key) => {
    if (options && options.educational_kb && options.educational_kb[key]) {
      setInfoModal(options.educational_kb[key]);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div style={{
        backgroundColor: '#0f172a',
        borderRadius: '12px',
        border: '1px solid #1e293b',
        padding: '24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '44px', height: '44px', borderRadius: '10px',
            backgroundColor: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#38bdf8'
          }}>
            <FlaskConical style={{ width: '24px', height: '24px' }} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: '#f8fafc' }}>
              DEEPSTATE Demonstration Lab 2.0 — Operator-Controlled Experimentation
            </h3>
            <p style={{ margin: '4px 0 0', fontSize: '13px', color: '#94a3b8' }}>
              Design custom IPsec peer configurations & encrypted traffic flows, capture PCAP artifacts, and evaluate DEEPSTATE 3-Tier analysis.
            </p>
          </div>
        </div>

        {/* Live status badge */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: '10px',
          backgroundColor: '#1e293b', padding: '8px 16px', borderRadius: '8px', border: '1px solid #334155'
        }}>
          <Server style={{ width: '16px', height: '16px', color: testbedStatus?.peer_a_status === 'running' ? '#4ade80' : '#f59e0b' }} />
          <span style={{ fontSize: '13px', fontWeight: '600', color: '#f1f5f9' }}>
            Environment: {testbedStatus?.peer_a_status === 'running' ? 'LIVE STRONGSWAN TESTBED' : 'SYNTHETIC FALLBACK'}
          </span>
        </div>
      </div>

      {/* Presets Toolbar */}
      <div style={{
        backgroundColor: '#0f172a', borderRadius: '12px', border: '1px solid #1e293b', padding: '16px 20px',
        display: 'flex', flexDirection: 'column', gap: '10px'
      }}>
        <div style={{ fontSize: '12px', fontWeight: '700', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Demonstration Starting Presets (Click to Populate Controls)
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          {[
            { id: 'SECURE_ENTERPRISE', label: 'Secure Enterprise', icon: Shield, color: '#38bdf8' },
            { id: 'LEGACY_VPN', label: 'Legacy VPN (CBC)', icon: Cpu, color: '#f59e0b' },
            { id: 'TRANSPORT_MODE', label: 'Transport Mode', icon: Activity, color: '#a855f7' },
            { id: 'HIGH_VOLUME_UDP', label: 'High-Volume UDP', icon: Activity, color: '#ec4899' },
            { id: 'VOIP_LIKE', label: 'VoIP-like (UDP/5060)', icon: Activity, color: '#22c55e' },
            { id: 'WEB_LIKE', label: 'Web-like (TCP/443)', icon: Activity, color: '#06b6d4' },
            { id: 'CUSTOM_EXPERIMENT', label: 'Custom Operator', icon: Sliders, color: '#e2e8f0' }
          ].map(p => {
            const Icon = p.icon;
            const active = selectedPreset === p.id;
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => handleSelectPreset(p.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: '6px',
                  padding: '8px 14px', borderRadius: '8px', fontSize: '13px', fontWeight: '600',
                  cursor: 'pointer', border: active ? `1px solid ${p.color}` : '1px solid #334155',
                  backgroundColor: active ? 'rgba(56, 189, 248, 0.15)' : '#1e293b',
                  color: active ? '#ffffff' : '#94a3b8', transition: 'all 0.2s'
                }}
              >
                <Icon style={{ width: '14px', height: '14px', color: p.color }} />
                <span>{p.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Experiment Setup Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: '20px' }}>

        {/* Column 1: IPsec Peer & Cipher Configuration */}
        <div style={{
          backgroundColor: '#0f172a', borderRadius: '12px', border: '1px solid #1e293b', padding: '20px',
          display: 'flex', flexDirection: 'column', gap: '16px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #1e293b', paddingBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Shield style={{ width: '18px', height: '18px', color: '#38bdf8' }} />
              <h4 style={{ margin: 0, fontSize: '15px', fontWeight: '700', color: '#f8fafc' }}>
                1. IPsec & Peer Configuration
              </h4>
            </div>
            <span style={{ fontSize: '11px', color: '#64748b' }}>StrongSwan Engine</span>
          </div>

          {/* Topology Peer Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div style={{ backgroundColor: '#1e293b', padding: '10px', borderRadius: '8px', border: '1px solid #334155' }}>
              <div style={{ fontSize: '11px', color: '#94a3b8', fontWeight: '700' }}>PEER A (Initiator)</div>
              <div style={{ fontSize: '13px', fontWeight: '600', color: '#38bdf8', fontFamily: 'monospace' }}>192.168.100.2</div>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace' }}>Subnet: 10.1.0.1/24</div>
            </div>
            <div style={{ backgroundColor: '#1e293b', padding: '10px', borderRadius: '8px', border: '1px solid #334155' }}>
              <div style={{ fontSize: '11px', color: '#94a3b8', fontWeight: '700' }}>PEER B (Responder)</div>
              <div style={{ fontSize: '13px', fontWeight: '600', color: '#38bdf8', fontFamily: 'monospace' }}>192.168.100.3</div>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace' }}>Subnet: 10.2.0.1/24</div>
            </div>
          </div>

          {/* IKE Version */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: '#94a3b8' }}>IKE Version:</label>
              <button type="button" onClick={() => openInfoModal('IKEv2')} style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer' }}>
                <Info style={{ width: '14px', height: '14px' }} />
              </button>
            </div>
            <div style={{ padding: '8px 12px', borderRadius: '6px', backgroundColor: '#1e293b', border: '1px solid #334155', color: '#f8fafc', fontSize: '13px', fontWeight: '600' }}>
              IKEv2 (Internet Key Exchange v2)
            </div>
          </div>

          {/* VPN Mode */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: '#94a3b8' }}>IPsec Mode:</label>
              <button type="button" onClick={() => openInfoModal(config.mode === 'tunnel' ? 'Tunnel' : 'Transport')} style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer' }}>
                <Info style={{ width: '14px', height: '14px' }} />
              </button>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              {['tunnel', 'transport'].map(m => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setConfig({ ...config, mode: m })}
                  style={{
                    flex: 1, padding: '8px', borderRadius: '6px', fontSize: '12px', fontWeight: '600', cursor: 'pointer',
                    backgroundColor: config.mode === m ? '#2563eb' : '#1e293b', border: 'none', color: config.mode === m ? '#ffffff' : '#94a3b8'
                  }}
                >
                  {m.toUpperCase()} Mode
                </button>
              ))}
            </div>
          </div>

          {/* Encryption Algorithm */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: '#94a3b8' }}>Encryption Cipher:</label>
              <button type="button" onClick={() => openInfoModal(config.encryption)} style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer' }}>
                <Info style={{ width: '14px', height: '14px' }} />
              </button>
            </div>
            <select
              value={config.encryption}
              onChange={(e) => setConfig({ ...config, encryption: e.target.value })}
              style={{
                width: '100%', padding: '8px 12px', borderRadius: '6px', backgroundColor: '#1e293b',
                border: '1px solid #334155', color: '#f8fafc', fontSize: '13px', outline: 'none'
              }}
            >
              <option value="AES-256-GCM">AES-256-GCM (AEAD Modern High-Security)</option>
              <option value="AES-128-CBC">AES-128-CBC (Legacy Enterprise)</option>
              <option value="AES-256-CBC">AES-256-CBC (Legacy Enterprise High-Bit)</option>
            </select>
          </div>

          {/* Integrity & DH Group */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#94a3b8', marginBottom: '6px' }}>Integrity:</label>
              <select
                value={config.integrity}
                onChange={(e) => setConfig({ ...config, integrity: e.target.value })}
                style={{
                  width: '100%', padding: '8px 12px', borderRadius: '6px', backgroundColor: '#1e293b',
                  border: '1px solid #334155', color: '#f8fafc', fontSize: '13px', outline: 'none'
                }}
              >
                <option value="NONE">AEAD Implicit (None)</option>
                <option value="SHA256">HMAC-SHA-256</option>
                <option value="SHA384">HMAC-SHA-384</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#94a3b8', marginBottom: '6px' }}>DH Group:</label>
              <select
                value={config.dh_group}
                onChange={(e) => setConfig({ ...config, dh_group: e.target.value })}
                style={{
                  width: '100%', padding: '8px 12px', borderRadius: '6px', backgroundColor: '#1e293b',
                  border: '1px solid #334155', color: '#f8fafc', fontSize: '13px', outline: 'none'
                }}
              >
                <option value="ECP256">Group 19 (ECP256)</option>
                <option value="ECP384">Group 20 (ECP384)</option>
                <option value="MODP2048">Group 14 (MODP2048)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Column 2: Traffic Profile & Generation Parameters */}
        <div style={{
          backgroundColor: '#0f172a', borderRadius: '12px', border: '1px solid #1e293b', padding: '20px',
          display: 'flex', flexDirection: 'column', gap: '16px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #1e293b', paddingBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity style={{ width: '18px', height: '18px', color: '#38bdf8' }} />
              <h4 style={{ margin: 0, fontSize: '15px', fontWeight: '700', color: '#f8fafc' }}>
                2. Traffic Generation Parameters
              </h4>
            </div>
            <span style={{ fontSize: '11px', color: '#64748b' }}>L4 / L7 Pattern Engine</span>
          </div>

          {/* Traffic Type Selector */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: '#94a3b8' }}>Traffic Pattern Model:</label>
              <button type="button" onClick={() => openInfoModal(config.traffic_type)} style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer' }}>
                <Info style={{ width: '14px', height: '14px' }} />
              </button>
            </div>
            <select
              value={config.traffic_type}
              onChange={(e) => {
                const val = e.target.value;
                const p = val === 'VOIP-LIKE' ? 5060 : val === 'WEB' ? 443 : val === 'DNS-LIKE' ? 53 : 5001;
                setConfig({ ...config, traffic_type: val, destination_port: p });
              }}
              style={{
                width: '100%', padding: '8px 12px', borderRadius: '6px', backgroundColor: '#1e293b',
                border: '1px solid #334155', color: '#f8fafc', fontSize: '13px', outline: 'none'
              }}
            >
              <option value="WEB">Web HTTPS/HTTP Simulation (TCP/443)</option>
              <option value="VOIP-LIKE">VoIP / RTP Audio Simulation (UDP/5060)</option>
              <option value="ICMP">ICMP Ping Echo Burst</option>
              <option value="UDP">UDP Datagram Stream</option>
              <option value="TCP">TCP Connection Stream</option>
              <option value="DNS-LIKE">DNS Query Stream (UDP/53)</option>
              <option value="FILE-TRANSFER-LIKE">Bulk File Transfer (TCP/443)</option>
            </select>
          </div>

          {/* Destination Port & Payload Size */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#94a3b8', marginBottom: '6px' }}>Dest Port:</label>
              <input
                type="number"
                value={config.destination_port}
                onChange={(e) => setConfig({ ...config, destination_port: parseInt(e.target.value) || 5001 })}
                style={{
                  width: '100%', padding: '8px 12px', borderRadius: '6px', backgroundColor: '#1e293b',
                  border: '1px solid #334155', color: '#f8fafc', fontSize: '13px', fontFamily: 'monospace'
                }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#94a3b8', marginBottom: '6px' }}>Payload Size (Bytes):</label>
              <input
                type="number"
                value={config.payload_size}
                onChange={(e) => setConfig({ ...config, payload_size: parseInt(e.target.value) || 512 })}
                style={{
                  width: '100%', padding: '8px 12px', borderRadius: '6px', backgroundColor: '#1e293b',
                  border: '1px solid #334155', color: '#f8fafc', fontSize: '13px', fontFamily: 'monospace'
                }}
              />
            </div>
          </div>

          {/* Packet Count Slider */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>
              <span>Packet Count:</span>
              <strong style={{ color: '#38bdf8' }}>{config.packet_count} packets</strong>
            </div>
            <input
              type="range"
              min="5"
              max="200"
              step="5"
              value={config.packet_count}
              onChange={(e) => setConfig({ ...config, packet_count: parseInt(e.target.value) })}
              style={{ width: '100%', accentColor: '#38bdf8' }}
            />
          </div>

          {/* Packet Rate Slider */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>
              <span>Packet Rate:</span>
              <strong style={{ color: '#38bdf8' }}>{config.packet_rate} pkts/sec</strong>
            </div>
            <input
              type="range"
              min="5"
              max="100"
              step="5"
              value={config.packet_rate}
              onChange={(e) => setConfig({ ...config, packet_rate: parseInt(e.target.value) })}
              style={{ width: '100%', accentColor: '#38bdf8' }}
            />
          </div>
        </div>
      </div>

      {/* Action Controls & Execution State */}
      <div style={{
        backgroundColor: '#0f172a', borderRadius: '12px', border: '1px solid #1e293b', padding: '20px',
        display: 'flex', flexDirection: 'column', gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              type="button"
              onClick={handleValidate}
              disabled={executing}
              style={{
                padding: '10px 18px', borderRadius: '8px', fontSize: '13px', fontWeight: '600',
                backgroundColor: '#1e293b', border: '1px solid #334155', color: '#f1f5f9', cursor: 'pointer'
              }}
            >
              Validate Config
            </button>
            <button
              type="button"
              onClick={handleRunExperiment}
              disabled={executing}
              style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                padding: '10px 24px', borderRadius: '8px', fontSize: '14px', fontWeight: '700',
                backgroundColor: executing ? '#475569' : '#0284c7', border: 'none', color: '#ffffff', cursor: executing ? 'not-allowed' : 'pointer'
              }}
            >
              {executing ? <RefreshCw style={{ width: '16px', height: '16px', animation: 'spin 1s linear infinite' }} /> : <Play style={{ width: '16px', height: '16px' }} />}
              <span>{executing ? 'Executing Experiment Pipeline...' : 'Execute IPsec Experiment'}</span>
            </button>
          </div>

          {executionResult && (
            <button
              type="button"
              onClick={() => handleAnalyzeHandoff(executionResult.experiment_id)}
              disabled={executing}
              style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                padding: '10px 20px', borderRadius: '8px', fontSize: '14px', fontWeight: '700',
                backgroundColor: '#16a34a', border: 'none', color: '#ffffff', cursor: 'pointer'
              }}
            >
              <span>Analyze Captured PCAP with DEEPSTATE</span>
              <ArrowRight style={{ width: '16px', height: '16px' }} />
            </button>
          )}
        </div>

        {/* Validation result alert */}
        {validation && (
          <div style={{
            padding: '12px 16px', borderRadius: '8px', fontSize: '13px',
            backgroundColor: validation.valid ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
            border: `1px solid ${validation.valid ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
            color: validation.valid ? '#4ade80' : '#f87171'
          }}>
            {validation.valid ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 style={{ width: '16px', height: '16px' }} />
                <span>Configuration Validated! Ready for execution on StrongSwan testbed.</span>
              </div>
            ) : (
              <div>
                <strong>Validation Errors:</strong> {validation.errors.join(', ')}
              </div>
            )}
          </div>
        )}

        {/* Execution Error alert */}
        {errorMsg && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: '10px', padding: '12px 16px', borderRadius: '8px',
            backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', fontSize: '13px'
          }}>
            <AlertTriangle style={{ width: '18px', height: '18px' }} />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Execution Step Timeline */}
        {executing && (
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderTop: '1px solid #1e293b' }}>
            {[
              '1. Validate', '2. Verify Peers', '3. Establish SA', '4. Capture & Traffic', '5. Finalize PCAP'
            ].map((stepLabel, idx) => {
              const stepNum = idx + 1;
              const isDone = currentStep > stepNum;
              const isCurrent = currentStep === stepNum;
              return (
                <div key={stepLabel} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
                  <div style={{
                    width: '20px', height: '20px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    backgroundColor: isDone ? '#22c55e' : isCurrent ? '#0284c7' : '#334155', color: '#ffffff', fontWeight: '700', fontSize: '10px'
                  }}>
                    {isDone ? '✓' : stepNum}
                  </div>
                  <span style={{ color: isDone ? '#4ade80' : isCurrent ? '#38bdf8' : '#64748b', fontWeight: isCurrent ? '700' : '400' }}>
                    {stepLabel}
                  </span>
                </div>
              );
            })}
          </div>
        )}

        {/* Execution Result Summary Card */}
        {executionResult && (
          <div style={{
            backgroundColor: '#1e293b', borderRadius: '8px', border: '1px solid #334155', padding: '16px',
            display: 'flex', flexDirection: 'column', gap: '10px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#4ade80', fontWeight: '700', fontSize: '14px' }}>
                <CheckCircle2 style={{ width: '18px', height: '18px' }} />
                <span>Experiment Capture Finalized ({executionResult.execution_mode})</span>
              </div>
              <span style={{ fontSize: '12px', fontFamily: 'monospace', color: '#94a3b8' }}>ID: {executionResult.experiment_id}</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '12px', marginTop: '6px' }}>
              <div>
                <span style={{ display: 'block', fontSize: '11px', color: '#64748b' }}>PCAP Path:</span>
                <span style={{ fontSize: '12px', fontFamily: 'monospace', color: '#38bdf8' }}>{executionResult.file_path}</span>
              </div>
              <div>
                <span style={{ display: 'block', fontSize: '11px', color: '#64748b' }}>Packet Count:</span>
                <span style={{ fontSize: '12px', fontWeight: '600', color: '#f1f5f9' }}>{executionResult.packet_count} pkts</span>
              </div>
              <div>
                <span style={{ display: 'block', fontSize: '11px', color: '#64748b' }}>Size Bytes:</span>
                <span style={{ fontSize: '12px', fontWeight: '600', color: '#f1f5f9' }}>{executionResult.size_bytes} bytes</span>
              </div>
              <div>
                <span style={{ display: 'block', fontSize: '11px', color: '#64748b' }}>Duration:</span>
                <span style={{ fontSize: '12px', fontWeight: '600', color: '#f1f5f9' }}>{executionResult.duration_seconds}s</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Experiment History Section */}
      {history.length > 0 && (
        <div style={{
          backgroundColor: '#0f172a', borderRadius: '12px', border: '1px solid #1e293b', padding: '20px',
          display: 'flex', flexDirection: 'column', gap: '14px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '10px' }}>
            <History style={{ width: '18px', height: '18px', color: '#38bdf8' }} />
            <h4 style={{ margin: 0, fontSize: '15px', fontWeight: '700', color: '#f8fafc' }}>
              Experiment History Log ({history.length} Captured Runs)
            </h4>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '280px', overflowY: 'auto' }}>
            {history.map((exp) => (
              <div
                key={exp.experiment_id}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '10px 14px', borderRadius: '8px', backgroundColor: '#1e293b', border: '1px solid #334155'
                }}
              >
                <div>
                  <div style={{ fontSize: '13px', fontWeight: '600', color: '#f8fafc' }}>
                    {exp.name || exp.experiment_id} ({exp.config?.mode || 'tunnel'} | {exp.config?.encryption || 'AES'} | {exp.config?.traffic_type || 'UDP'})
                  </div>
                  <div style={{ fontSize: '11px', color: '#94a3b8', fontFamily: 'monospace' }}>
                    {exp.file_path} ({exp.packet_count} pkts, {exp.size_bytes}B) — {exp.timestamp}
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => handleAnalyzeHandoff(exp.experiment_id)}
                  style={{
                    padding: '6px 12px', borderRadius: '6px', fontSize: '12px', fontWeight: '600',
                    backgroundColor: '#0284c7', border: 'none', color: '#ffffff', cursor: 'pointer'
                  }}
                >
                  Analyze with DEEPSTATE
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Educational Knowledge Base Modal */}
      {infoModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.7)', zIndex: 1000,
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px'
        }}>
          <div style={{
            backgroundColor: '#0f172a', border: '1px solid #38bdf8', borderRadius: '12px',
            maxWidth: '540px', width: '100%', padding: '24px', display: 'flex', flexDirection: 'column', gap: '14px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <h3 style={{ margin: 0, fontSize: '17px', color: '#38bdf8' }}>{infoModal.title}</h3>
              <button type="button" onClick={() => setInfoModal(null)} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}>
                <X style={{ width: '20px', height: '20px' }} />
              </button>
            </div>
            {infoModal.rfc && <div style={{ fontSize: '11px', color: '#64748b', fontWeight: '700' }}>{infoModal.rfc}</div>}
            <div style={{ fontSize: '13px', color: '#cbd5e1', lineHeight: '1.5' }}>
              <strong>What it does:</strong> {infoModal.explanation}
            </div>
            <div style={{ fontSize: '13px', color: '#cbd5e1', lineHeight: '1.5' }}>
              <strong>What DEEPSTATE Observes:</strong> {infoModal.observable_facts}
            </div>
            <div style={{ fontSize: '13px', color: '#f87171', lineHeight: '1.5' }}>
              <strong>Limitations:</strong> {infoModal.limitations}
            </div>
            <button
              type="button"
              onClick={() => setInfoModal(null)}
              style={{
                alignSelf: 'flex-end', padding: '8px 16px', borderRadius: '6px',
                backgroundColor: '#2563eb', border: 'none', color: '#ffffff', cursor: 'pointer', fontSize: '13px', fontWeight: '600'
              }}
            >
              Close Explanation
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
