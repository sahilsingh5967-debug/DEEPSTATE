import React, { useState, useEffect } from 'react';
import {
  FlaskConical, Play, CheckCircle2, AlertTriangle, Info, Server,
  Shield, Activity, History, ArrowRight, X, Sliders, RefreshCw, RotateCcw
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

  const defaultState = {
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
  };

  const [config, setConfig] = useState(defaultState);
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

  const handleReset = () => {
    setConfig(defaultState);
    setSelectedPreset('SECURE_ENTERPRISE');
    setValidation(null);
    setExecutionResult(null);
    setErrorMsg('');
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
      const val = await handleValidate();
      if (val && !val.valid) {
        throw new Error(val.errors.join(', '));
      }
      setCurrentStep(2);
      await new Promise(r => setTimeout(r, 600));

      setCurrentStep(3);
      await new Promise(r => setTimeout(r, 500));

      setCurrentStep(4);
      const result = await executeExperimentRun(config);
      setCurrentStep(5);
      await new Promise(r => setTimeout(r, 300));

      setCurrentStep(6);
      setExecutionResult(result);

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

  const isLive = testbedStatus?.peer_a_status === 'running';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: '10px',
        border: '1px solid #D8D4C8',
        padding: '24px',
        boxShadow: '0 2px 8px rgba(30, 30, 20, 0.05)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '44px', height: '44px', borderRadius: '10px',
            backgroundColor: '#F4E7B8', border: '1px solid #D6A928',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9A7618'
          }}>
            <FlaskConical style={{ width: '22px', height: '22px' }} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '20px', fontWeight: '700', color: '#252525' }}>
              DEEPSTATE Demonstration Lab 2.0
            </h3>
            <p style={{ margin: '4px 0 0', fontSize: '13px', color: '#66645D' }}>
              Operator-controlled IPsec experiment design and encrypted traffic analysis workstation.
            </p>
          </div>
        </div>

        {/* Environment Badge */}
        <div style={{
          height: '32px',
          padding: '0 12px',
          borderRadius: '16px',
          backgroundColor: isLive ? '#E3EEE7' : '#F5EBD5',
          color: isLive ? '#3F7654' : '#B57B22',
          border: `1px solid ${isLive ? '#BFD7C7' : '#E3D08C'}`,
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '12px',
          fontWeight: '600'
        }}>
          <Server style={{ width: '14px', height: '14px' }} />
          <span>Environment: {isLive ? 'STRONGSWAN LIVE' : 'SYNTHETIC FALLBACK'}</span>
        </div>
      </div>

      {/* Presets Toolbar */}
      <div style={{
        backgroundColor: '#FFFFFF', borderRadius: '10px', border: '1px solid #D8D4C8', padding: '16px 20px',
        boxShadow: '0 2px 8px rgba(30, 30, 20, 0.05)', display: 'flex', flexDirection: 'column', gap: '10px'
      }}>
        <div style={{ fontSize: '11px', fontWeight: '700', color: '#8A877E', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          Demonstration Starting Presets (Click to Populate Controls)
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          {[
            { id: 'SECURE_ENTERPRISE', label: 'Secure Enterprise', icon: Shield },
            { id: 'LEGACY_VPN', label: 'Legacy VPN (CBC)', icon: Cpu },
            { id: 'TRANSPORT_MODE', label: 'Transport Mode', icon: Activity },
            { id: 'HIGH_VOLUME_UDP', label: 'High-Volume UDP', icon: Activity },
            { id: 'VOIP_LIKE', label: 'VoIP-like (UDP/5060)', icon: Activity },
            { id: 'WEB_LIKE', label: 'Web-like (TCP/443)', icon: Activity },
            { id: 'CUSTOM_EXPERIMENT', label: 'Custom Operator', icon: Sliders }
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
                  height: '38px', padding: '0 14px', borderRadius: '7px', fontSize: '13px', fontWeight: '600',
                  cursor: 'pointer', border: active ? '1px solid #D6A928' : '1px solid #D8D4C8',
                  backgroundColor: active ? '#F4E7B8' : '#EDEAE1',
                  color: active ? '#252525' : '#66645D', transition: 'all 0.15s ease'
                }}
              >
                <Icon style={{ width: '14px', height: '14px', color: active ? '#9A7618' : '#8A877E' }} />
                <span>{p.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Experiment Setup Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: '20px' }}>

        {/* Column 1: IPsec & Peer Setup */}
        <div style={{
          backgroundColor: '#FFFFFF', borderRadius: '10px', border: '1px solid #D8D4C8', padding: '22px',
          boxShadow: '0 2px 8px rgba(30, 30, 20, 0.05)', display: 'flex', flexDirection: 'column', gap: '16px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #E3DFD4', paddingBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Shield style={{ width: '18px', height: '18px', color: '#D6A928' }} />
              <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                1. IPsec & Peer Configuration
              </h4>
            </div>
            <span style={{ fontSize: '11px', fontWeight: '600', color: '#8A877E' }}>StrongSwan Engine</span>
          </div>

          {/* Compact Peer Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div style={{ backgroundColor: '#F4F1E8', padding: '12px', borderRadius: '8px', border: '1px solid #D8D4C8', height: '80px', boxSizing: 'border-box' }}>
              <div style={{ fontSize: '11px', color: '#8A877E', fontWeight: '700', textTransform: 'uppercase' }}>PEER A (Initiator)</div>
              <div style={{ fontSize: '15px', fontWeight: '700', color: '#252525', fontFamily: 'monospace' }}>192.168.100.2</div>
              <div style={{ fontSize: '11px', color: '#66645D', fontFamily: 'monospace' }}>Subnet: 10.1.0.1/24</div>
            </div>
            <div style={{ backgroundColor: '#F4F1E8', padding: '12px', borderRadius: '8px', border: '1px solid #D8D4C8', height: '80px', boxSizing: 'border-box' }}>
              <div style={{ fontSize: '11px', color: '#8A877E', fontWeight: '700', textTransform: 'uppercase' }}>PEER B (Responder)</div>
              <div style={{ fontSize: '15px', fontWeight: '700', color: '#252525', fontFamily: 'monospace' }}>192.168.100.3</div>
              <div style={{ fontSize: '11px', color: '#66645D', fontFamily: 'monospace' }}>Subnet: 10.2.0.1/24</div>
            </div>
          </div>

          {/* IKE Version */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: '#66645D' }}>IKE Version:</label>
              <button type="button" onClick={() => openInfoModal('IKEv2')} style={{ background: 'none', border: 'none', color: '#9A7618', cursor: 'pointer' }}>
                <Info style={{ width: '14px', height: '14px' }} />
              </button>
            </div>
            <div style={{ height: '40px', padding: '0 12px', borderRadius: '7px', backgroundColor: '#EDEAE1', border: '1px solid #D8D4C8', color: '#252525', fontSize: '13px', fontWeight: '600', display: 'flex', alignItems: 'center' }}>
              IKEv2 (Internet Key Exchange v2)
            </div>
          </div>

          {/* Segmented Mode Control */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: '#66645D' }}>IPsec Mode:</label>
              <button type="button" onClick={() => openInfoModal(config.mode === 'tunnel' ? 'Tunnel' : 'Transport')} style={{ background: 'none', border: 'none', color: '#9A7618', cursor: 'pointer' }}>
                <Info style={{ width: '14px', height: '14px' }} />
              </button>
            </div>
            <div style={{ display: 'flex', backgroundColor: '#EDEAE1', padding: '3px', borderRadius: '8px', border: '1px solid #D8D4C8', height: '40px', boxSizing: 'border-box' }}>
              {['tunnel', 'transport'].map(m => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setConfig({ ...config, mode: m })}
                  style={{
                    flex: 1, borderRadius: '6px', fontSize: '12px', fontWeight: '700', cursor: 'pointer', border: 'none',
                    backgroundColor: config.mode === m ? '#D6A928' : 'transparent',
                    color: config.mode === m ? '#252525' : '#66645D', transition: 'all 0.15s ease'
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
              <label style={{ fontSize: '12px', fontWeight: '600', color: '#66645D' }}>Encryption Cipher:</label>
              <button type="button" onClick={() => openInfoModal(config.encryption)} style={{ background: 'none', border: 'none', color: '#9A7618', cursor: 'pointer' }}>
                <Info style={{ width: '14px', height: '14px' }} />
              </button>
            </div>
            <select
              value={config.encryption}
              onChange={(e) => setConfig({ ...config, encryption: e.target.value })}
              style={{
                width: '100%', height: '40px', padding: '0 12px', borderRadius: '7px', backgroundColor: '#FFFFFF',
                border: '1px solid #CFCABE', color: '#252525', fontSize: '13px', outline: 'none'
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
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '6px' }}>Integrity:</label>
              <select
                value={config.integrity}
                onChange={(e) => setConfig({ ...config, integrity: e.target.value })}
                style={{
                  width: '100%', height: '40px', padding: '0 12px', borderRadius: '7px', backgroundColor: '#FFFFFF',
                  border: '1px solid #CFCABE', color: '#252525', fontSize: '13px', outline: 'none'
                }}
              >
                <option value="NONE">AEAD Implicit (None)</option>
                <option value="SHA256">HMAC-SHA-256</option>
                <option value="SHA384">HMAC-SHA-384</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '6px' }}>DH Group:</label>
              <select
                value={config.dh_group}
                onChange={(e) => setConfig({ ...config, dh_group: e.target.value })}
                style={{
                  width: '100%', height: '40px', padding: '0 12px', borderRadius: '7px', backgroundColor: '#FFFFFF',
                  border: '1px solid #CFCABE', color: '#252525', fontSize: '13px', outline: 'none'
                }}
              >
                <option value="ECP256">Group 19 (ECP256)</option>
                <option value="ECP384">Group 20 (ECP384)</option>
                <option value="MODP2048">Group 14 (MODP2048)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Column 2: Traffic Profile & Parameters */}
        <div style={{
          backgroundColor: '#FFFFFF', borderRadius: '10px', border: '1px solid #D8D4C8', padding: '22px',
          boxShadow: '0 2px 8px rgba(30, 30, 20, 0.05)', display: 'flex', flexDirection: 'column', gap: '16px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #E3DFD4', paddingBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity style={{ width: '18px', height: '18px', color: '#D6A928' }} />
              <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                2. Traffic Generation Parameters
              </h4>
            </div>
            <span style={{ fontSize: '11px', fontWeight: '600', color: '#8A877E' }}>Pattern Simulator</span>
          </div>

          {/* Traffic Type Selector */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: '#66645D' }}>Traffic Pattern Model:</label>
              <button type="button" onClick={() => openInfoModal(config.traffic_type)} style={{ background: 'none', border: 'none', color: '#9A7618', cursor: 'pointer' }}>
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
                width: '100%', height: '40px', padding: '0 12px', borderRadius: '7px', backgroundColor: '#FFFFFF',
                border: '1px solid #CFCABE', color: '#252525', fontSize: '13px', outline: 'none'
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
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '6px' }}>Dest Port:</label>
              <input
                type="number"
                value={config.destination_port}
                onChange={(e) => setConfig({ ...config, destination_port: parseInt(e.target.value) || 5001 })}
                style={{
                  width: '100%', height: '40px', padding: '0 12px', borderRadius: '7px', backgroundColor: '#FFFFFF',
                  border: '1px solid #CFCABE', color: '#252525', fontSize: '13px', fontFamily: 'monospace'
                }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '6px' }}>Payload Size (Bytes):</label>
              <input
                type="number"
                value={config.payload_size}
                onChange={(e) => setConfig({ ...config, payload_size: parseInt(e.target.value) || 512 })}
                style={{
                  width: '100%', height: '40px', padding: '0 12px', borderRadius: '7px', backgroundColor: '#FFFFFF',
                  border: '1px solid #CFCABE', color: '#252525', fontSize: '13px', fontFamily: 'monospace'
                }}
              />
            </div>
          </div>

          {/* Packet Count Slider */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#66645D', marginBottom: '4px' }}>
              <span>Packet Count:</span>
              <strong style={{ color: '#252525' }}>{config.packet_count} packets</strong>
            </div>
            <input
              type="range"
              min="5"
              max="200"
              step="5"
              value={config.packet_count}
              onChange={(e) => setConfig({ ...config, packet_count: parseInt(e.target.value) })}
              style={{ width: '100%', accentColor: '#D6A928' }}
            />
          </div>

          {/* Packet Rate Slider */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#66645D', marginBottom: '4px' }}>
              <span>Packet Rate:</span>
              <strong style={{ color: '#252525' }}>{config.packet_rate} pkts/sec</strong>
            </div>
            <input
              type="range"
              min="5"
              max="100"
              step="5"
              value={config.packet_rate}
              onChange={(e) => setConfig({ ...config, packet_rate: parseInt(e.target.value) })}
              style={{ width: '100%', accentColor: '#D6A928' }}
            />
          </div>
        </div>
      </div>

      {/* Action Controls & Execution State */}
      <div style={{
        backgroundColor: '#FFFFFF', borderRadius: '10px', border: '1px solid #D8D4C8', padding: '22px',
        boxShadow: '0 2px 8px rgba(30, 30, 20, 0.05)', display: 'flex', flexDirection: 'column', gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              type="button"
              onClick={handleRunExperiment}
              disabled={executing}
              style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                height: '44px', padding: '0 24px', borderRadius: '8px', fontSize: '14px', fontWeight: '700',
                backgroundColor: executing ? '#77736A' : '#252525', border: 'none', color: '#FFFFFF', cursor: executing ? 'not-allowed' : 'pointer',
                transition: 'background-color 0.15s'
              }}
            >
              {executing ? <RefreshCw style={{ width: '16px', height: '16px', animation: 'spin 1s linear infinite' }} /> : <Play style={{ width: '16px', height: '16px', color: '#D6A928' }} />}
              <span>{executing ? 'Executing Pipeline...' : 'RUN EXPERIMENT'}</span>
            </button>

            <button
              type="button"
              onClick={handleValidate}
              disabled={executing}
              style={{
                height: '44px', padding: '0 18px', borderRadius: '8px', fontSize: '13px', fontWeight: '600',
                backgroundColor: '#F4E7B8', border: '1px solid #D6A928', color: '#252525', cursor: 'pointer'
              }}
            >
              VALIDATE CONFIGURATION
            </button>

            <button
              type="button"
              onClick={handleReset}
              disabled={executing}
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                height: '44px', padding: '0 16px', borderRadius: '8px', fontSize: '13px', fontWeight: '600',
                backgroundColor: 'transparent', border: '1px solid #D8D4C8', color: '#66645D', cursor: 'pointer'
              }}
            >
              <RotateCcw style={{ width: '14px', height: '14px' }} />
              <span>RESET</span>
            </button>
          </div>

          {executionResult && (
            <button
              type="button"
              onClick={() => handleAnalyzeHandoff(executionResult.experiment_id)}
              disabled={executing}
              style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                height: '44px', padding: '0 22px', borderRadius: '8px', fontSize: '14px', fontWeight: '700',
                backgroundColor: '#3F7654', border: 'none', color: '#FFFFFF', cursor: 'pointer'
              }}
            >
              <span>ANALYZE WITH DEEPSTATE</span>
              <ArrowRight style={{ width: '16px', height: '16px' }} />
            </button>
          )}
        </div>

        {/* Validation Result Alert */}
        {validation && (
          <div style={{
            padding: '12px 16px', borderRadius: '8px', fontSize: '13px',
            backgroundColor: validation.valid ? '#E3EEE7' : '#F3E2E0',
            border: `1px solid ${validation.valid ? '#BFD7C7' : '#E8C4C1'}`,
            color: validation.valid ? '#3F7654' : '#A94B43'
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

        {/* Execution Error Alert */}
        {errorMsg && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: '10px', padding: '12px 16px', borderRadius: '8px',
            backgroundColor: '#F3E2E0', border: '1px solid #E8C4C1', color: '#A94B43', fontSize: '13px'
          }}>
            <AlertTriangle style={{ width: '18px', height: '18px' }} />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Execution Timeline Step Progress */}
        {executing && (
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '14px 0', borderTop: '1px solid #E3DFD4' }}>
            {['1. Validate', '2. Verify Peers', '3. Establish SA', '4. Capture & Traffic', '5. Finalize PCAP'].map((stepLabel, idx) => {
              const stepNum = idx + 1;
              const isDone = currentStep > stepNum;
              const isCurrent = currentStep === stepNum;
              return (
                <div key={stepLabel} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
                  <div style={{
                    width: '20px', height: '20px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    backgroundColor: isDone ? '#3F7654' : isCurrent ? '#D6A928' : '#EDEAE1', color: isDone || isCurrent ? '#FFFFFF' : '#66645D', fontWeight: '700', fontSize: '10px'
                  }}>
                    {isDone ? '✓' : stepNum}
                  </div>
                  <span style={{ color: isDone ? '#3F7654' : isCurrent ? '#9A7618' : '#8A877E', fontWeight: isCurrent ? '700' : '400' }}>
                    {stepLabel}
                  </span>
                </div>
              );
            })}
          </div>
        )}

        {/* Execution Result Summary */}
        {executionResult && (
          <div style={{
            backgroundColor: '#F4F1E8', borderRadius: '8px', border: '1px solid #D8D4C8', padding: '16px',
            display: 'flex', flexDirection: 'column', gap: '10px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#3F7654', fontWeight: '700', fontSize: '14px' }}>
                <CheckCircle2 style={{ width: '18px', height: '18px' }} />
                <span>Experiment Capture Finalized ({executionResult.execution_mode})</span>
              </div>
              <span style={{ fontSize: '12px', fontFamily: 'monospace', color: '#8A877E' }}>ID: {executionResult.experiment_id}</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '12px', marginTop: '4px' }}>
              <div>
                <span style={{ display: 'block', fontSize: '11px', color: '#8A877E' }}>PCAP Path:</span>
                <span style={{ fontSize: '12px', fontFamily: 'monospace', color: '#9A7618', fontWeight: '600' }}>{executionResult.file_path}</span>
              </div>
              <div>
                <span style={{ display: 'block', fontSize: '11px', color: '#8A877E' }}>Packet Count:</span>
                <span style={{ fontSize: '12px', fontWeight: '600', color: '#252525' }}>{executionResult.packet_count} pkts</span>
              </div>
              <div>
                <span style={{ display: 'block', fontSize: '11px', color: '#8A877E' }}>Size Bytes:</span>
                <span style={{ fontSize: '12px', fontWeight: '600', color: '#252525' }}>{executionResult.size_bytes} bytes</span>
              </div>
              <div>
                <span style={{ display: 'block', fontSize: '11px', color: '#8A877E' }}>Duration:</span>
                <span style={{ fontSize: '12px', fontWeight: '600', color: '#252525' }}>{executionResult.duration_seconds}s</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Persistent Experiment History Log */}
      {history.length > 0 && (
        <div style={{
          backgroundColor: '#FFFFFF', borderRadius: '10px', border: '1px solid #D8D4C8', padding: '20px',
          boxShadow: '0 2px 8px rgba(30, 30, 20, 0.05)', display: 'flex', flexDirection: 'column', gap: '14px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #E3DFD4', paddingBottom: '10px' }}>
            <History style={{ width: '18px', height: '18px', color: '#D6A928' }} />
            <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
              Experiment History Log ({history.length} Captured Runs)
            </h4>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '280px', overflowY: 'auto' }}>
            {history.map((exp) => (
              <div
                key={exp.experiment_id}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '12px 16px', borderRadius: '8px', backgroundColor: '#F4F1E8', border: '1px solid #D8D4C8'
                }}
              >
                <div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525' }}>
                    {exp.name || exp.experiment_id} ({exp.config?.mode || 'tunnel'} | {exp.config?.encryption || 'AES'} | {exp.config?.traffic_type || 'UDP'})
                  </div>
                  <div style={{ fontSize: '11px', color: '#66645D', fontFamily: 'monospace', marginTop: '2px' }}>
                    {exp.file_path} ({exp.packet_count} pkts, {exp.size_bytes}B) — {exp.timestamp}
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => handleAnalyzeHandoff(exp.experiment_id)}
                  style={{
                    padding: '6px 14px', borderRadius: '6px', fontSize: '12px', fontWeight: '600',
                    backgroundColor: '#F4E7B8', border: '1px solid #D6A928', color: '#252525', cursor: 'pointer'
                  }}
                >
                  Analyze with DEEPSTATE
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Centered Educational Info Overlay Modal */}
      {infoModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(37,37,37,0.35)', zIndex: 1000,
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px'
        }}>
          <div style={{
            backgroundColor: '#FFFDF8', border: '1px solid #D8D4C8', borderRadius: '12px',
            maxWidth: '720px', width: '100%', padding: '24px', boxShadow: '0 16px 50px rgba(30,30,20,0.18)',
            display: 'flex', flexDirection: 'column', gap: '16px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #E3DFD4', paddingBottom: '12px' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: '#252525' }}>{infoModal.title}</h3>
              <button
                type="button"
                onClick={() => setInfoModal(null)}
                style={{
                  width: '32px', height: '32px', borderRadius: '6px', backgroundColor: '#F0EDE5',
                  border: 'none', color: '#66645D', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center'
                }}
              >
                <X style={{ width: '18px', height: '18px' }} />
              </button>
            </div>
            {infoModal.rfc && <div style={{ fontSize: '12px', color: '#9A7618', fontWeight: '700' }}>{infoModal.rfc}</div>}
            <div style={{ fontSize: '13px', color: '#252525', lineHeight: '1.5' }}>
              <strong>What it does:</strong> {infoModal.explanation}
            </div>
            <div style={{ fontSize: '13px', color: '#252525', lineHeight: '1.5' }}>
              <strong>What DEEPSTATE Observes:</strong> {infoModal.observable_facts}
            </div>
            <div style={{ fontSize: '13px', color: '#A94B43', lineHeight: '1.5' }}>
              <strong>Limitations:</strong> {infoModal.limitations}
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: '12px', borderTop: '1px solid #E3DFD4' }}>
              <button
                type="button"
                onClick={() => setInfoModal(null)}
                style={{
                  padding: '8px 20px', borderRadius: '6px',
                  backgroundColor: '#252525', border: 'none', color: '#FFFFFF', cursor: 'pointer', fontSize: '13px', fontWeight: '600'
                }}
              >
                Close Explanation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
