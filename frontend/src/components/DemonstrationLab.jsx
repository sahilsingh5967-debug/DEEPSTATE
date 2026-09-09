import React, { useState, useEffect } from 'react';
import {
  FlaskConical, Play, CheckCircle2, AlertTriangle, Info, Server,
  Shield, Activity, History, ArrowRight, X, Sliders, RefreshCw, RotateCcw,
  Check, Lock, Terminal, Cpu, ChevronRight, HelpCircle
} from 'lucide-react';
import {
  fetchTestbedOptions, fetchTestbedStatus, validateExperimentConfig,
  executeExperimentRun, fetchExperimentHistory, analyzeExperimentRecord
} from '../api/client';
import InvestigationModal from './InvestigationModal';

export default function DemonstrationLab({ onAnalyzeResult }) {
  const [options, setOptions] = useState(null);
  const [testbedStatus, setTestbedStatus] = useState(null);
  const [history, setHistory] = useState([]);
  const [selectedPreset, setSelectedPreset] = useState('SECURE_ENTERPRISE');
  const [showAdvanced, setShowAdvanced] = useState(false);

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
  const [infoModalKey, setInfoModalKey] = useState(null);

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
      setCurrentStep(0);
    }
  };

  const handleReset = () => {
    setConfig(defaultState);
    setSelectedPreset('SECURE_ENTERPRISE');
    setValidation(null);
    setExecutionResult(null);
    setErrorMsg('');
    setCurrentStep(0);
  };

  const handleValidate = async () => {
    setErrorMsg('');
    const res = await validateExperimentConfig(config);
    setValidation(res);
    if (res && res.valid && currentStep === 0) {
      setCurrentStep(1);
    }
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
      const analysisData = await analyzeExperimentRecord(expId || executionResult?.experiment_id);
      if (onAnalyzeResult) {
        onAnalyzeResult(analysisData);
      }
    } catch (err) {
      setErrorMsg(err.message || 'Analysis handoff failed.');
    } finally {
      setExecuting(false);
    }
  };

  const educationalTopics = {
    ike: {
      title: 'WHAT IS IKE (INTERNET KEY EXCHANGE)?',
      explanation: 'Internet Key Exchange (IKEv2) negotiates security parameters and establishes IPsec Security Associations (SAs).',
      observable_facts: 'DEEPSTATE extracts IKE header SPIs, exchange types, encryption algorithms, integrity algorithms, and DH groups.',
      limitations: 'IKE payloads after authentication are encrypted and cannot be inspected without private keys.'
    },
    esp: {
      title: 'WHAT IS ESP (ENCAPSULATING SECURITY PAYLOAD)?',
      explanation: 'Encapsulating Security Payload (ESP) protects IPsec packets by providing payload confidentiality and integrity.',
      observable_facts: 'DEEPSTATE inspects outer ESP headers, Security Parameter Indexes (SPIs), and packet size distributions.',
      limitations: 'Encrypted ESP inner IP headers and application payloads are strictly unobservable.'
    },
    dh: {
      title: 'WHAT IS A DIFFIE-HELLMAN (DH) GROUP?',
      explanation: 'Diffie-Hellman groups define the mathematical strength of the key exchange used to generate shared secret keys.',
      observable_facts: 'DEEPSTATE checks DH group strength against NIST SP 800-77 and BSI security guidelines.',
      limitations: 'DH groups 1, 2, and 5 are considered cryptographically weak and trigger security score deductions.'
    },
    mode: {
      title: 'TUNNEL MODE VS TRANSPORT MODE',
      explanation: 'Tunnel Mode encrypts the entire original IP packet and adds a new outer IP header. Transport Mode encrypts only the payload.',
      observable_facts: 'DEEPSTATE infers IPsec mode based on packet size overhead and header layout statistics.',
      limitations: 'Mode inference is probabilistic based on observed frame structure.'
    }
  };

  const isLive = testbedStatus?.peer_a_status === 'running' || testbedStatus?.mode === 'docker_live';

  const trafficTypes = [
    { id: 'ICMP', label: 'ICMP', desc: 'Ping ECHO pattern' },
    { id: 'UDP', label: 'UDP', desc: 'Custom UDP flow' },
    { id: 'TCP', label: 'TCP', desc: 'Stream TCP pattern' },
    { id: 'WEB', label: 'WEB-LIKE', desc: 'HTTP/S web flow' },
    { id: 'DNS', label: 'DNS-LIKE', desc: 'Query/Response' },
    { id: 'VOIP', label: 'VOIP-LIKE', desc: 'RTP stream pattern' },
    { id: 'FILE_TRANSFER', label: 'FILE-TRANSFER', desc: 'Bulk file flow' }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

      {/* 3. PAGE HEADER */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{
            fontSize: '12px',
            fontWeight: '650',
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
            <span style={{ color: '#9A7618' }}>DEMONSTRATION LAB</span>
          </div>

          <h1 style={{ margin: '0 0 6px', fontSize: '30px', fontWeight: '700', color: '#252525', letterSpacing: '-0.02em' }}>
            DEEPSTATE Demonstration Lab 2.0
          </h1>
          <p style={{ margin: 0, fontSize: '14px', color: '#66645D', maxWidth: '850px', lineHeight: '1.4' }}>
            Controlled IPsec experimentation, encrypted traffic generation, PCAP capture, and analysis handoff.
          </p>
        </div>

        {/* Environment Status Badge */}
        <div style={{
          height: '32px',
          padding: '0 14px',
          borderRadius: '999px',
          backgroundColor: isLive ? '#E3EEE7' : '#F5EBD5',
          color: isLive ? '#3F7654' : '#B57B22',
          border: `1px solid ${isLive ? '#C5DEC9' : '#E6D3A7'}`,
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '12px',
          fontWeight: '700'
        }}>
          <span style={{ width: '7px', height: '7px', borderRadius: '50%', backgroundColor: isLive ? '#3F7654' : '#B57B22' }} />
          <span>ENVIRONMENT: {testbedStatus?.mode === 'docker_live' ? 'STRONGSWAN TESTBED READY' : 'SYNTHETIC EXPERIMENT ENGINE READY'}</span>
        </div>
      </div>

      {/* 4. EXPERIMENT WORKFLOW INDICATOR */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(5, 1fr)',
        gap: '8px',
        backgroundColor: '#FFFFFF',
        border: '1px solid #D8D4C8',
        borderRadius: '10px',
        padding: '12px 16px',
        boxShadow: '0 2px 8px rgba(37,37,37,0.04)'
      }}>
        {[
          { step: 1, label: '01 CONFIGURE' },
          { step: 2, label: '02 VALIDATE' },
          { step: 3, label: '03 EXECUTE' },
          { step: 4, label: '04 CAPTURE' },
          { step: 5, label: '05 ANALYZE' }
        ].map((item) => {
          const isCompleted = currentStep > item.step || (item.step === 4 && executionResult);
          const isActive = currentStep === item.step || (item.step === 1 && currentStep === 0);

          let bg = '#EDEAE1';
          let color = '#8A877E';
          let border = '1px solid transparent';

          if (isCompleted) {
            bg = '#E3EEE7';
            color = '#245837';
            border = '1px solid #C5DEC9';
          } else if (isActive) {
            bg = '#F4E7B8';
            color = '#9A7618';
            border = '1px solid #D6A928';
          }

          return (
            <div key={item.step} style={{
              height: '44px',
              borderRadius: '7px',
              backgroundColor: bg,
              color: color,
              border: border,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '12px',
              fontWeight: '700',
              letterSpacing: '0.04em',
              transition: 'all 0.2s ease'
            }}>
              <span>{isCompleted ? `✓ ${item.label}` : item.label}</span>
            </div>
          );
        })}
      </div>

      {/* 5. PRESET SYSTEM */}
      <div style={{
        backgroundColor: '#FFFFFF',
        border: '1px solid #D8D4C8',
        borderRadius: '10px',
        padding: '20px',
        boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: '14px'
      }}>
        <div>
          <h3 style={{ margin: '0 0 4px', fontSize: '15px', fontWeight: '700', color: '#252525' }}>
            EXPERIMENT PRESETS
          </h3>
          <p style={{ margin: 0, fontSize: '13px', color: '#66645D' }}>
            Select a starting configuration or create a custom experiment profile.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px', overflowX: 'auto', paddingBottom: '4px' }}>
          {[
            { id: 'SECURE_ENTERPRISE', label: 'SECURE ENTERPRISE' },
            { id: 'WEAK_LEGACY', label: 'LEGACY VPN (WEAK)' },
            { id: 'AES_GCM_FAST', label: 'AES-GCM' },
            { id: 'NULL_ENCRYPTION', label: 'NULL AUTH / ENC' },
            { id: 'CUSTOM_OPERATOR', label: 'CUSTOM OPERATOR' }
          ].map(preset => {
            const isActive = selectedPreset === preset.id;
            return (
              <button
                key={preset.id}
                type="button"
                onClick={() => handleSelectPreset(preset.id)}
                style={{
                  height: '42px',
                  padding: '0 16px',
                  borderRadius: '7px',
                  fontSize: '12px',
                  fontWeight: isActive ? '700' : '600',
                  cursor: 'pointer',
                  border: isActive ? '1px solid #D6A928' : '1px solid #D8D4C8',
                  backgroundColor: isActive ? '#F4E7B8' : '#FFFFFF',
                  color: isActive ? '#9A7618' : '#252525',
                  whiteSpace: 'nowrap',
                  transition: 'all 0.15s ease'
                }}
                onMouseOver={(e) => { if (!isActive) e.currentTarget.style.backgroundColor = '#EDEAE1'; }}
                onMouseOut={(e) => { if (!isActive) e.currentTarget.style.backgroundColor = '#FFFFFF'; }}
              >
                {preset.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* 6. MAIN CONFIGURATION GRID (50% / 50% Desktop) */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
        gap: '20px'
      }}>

        {/* 7. LEFT CARD — IPsec PEER CONFIGURATION */}
        <div style={{
          backgroundColor: '#FFFFFF',
          border: '1px solid #D8D4C8',
          borderRadius: '10px',
          padding: '20px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
          display: 'flex',
          flexDirection: 'column',
          gap: '18px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #EDEAE1', paddingBottom: '12px' }}>
            <h3 style={{ margin: 0, fontSize: '15px', fontWeight: '700', color: '#252525' }}>
              01 IPsec PEER CONFIGURATION
            </h3>
            <span style={{ fontSize: '11px', fontWeight: '600', color: '#8A877E', textTransform: 'uppercase' }}>
              STRONGSWAN ENGINE
            </span>
          </div>

          {/* Peer A & Peer B Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', borderRadius: '8px', padding: '12px' }}>
              <span style={{ fontSize: '10px', fontWeight: '700', color: '#9A7618', textTransform: 'uppercase' }}>PEER A (INITIATOR)</span>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525', marginTop: '4px', fontFamily: 'monospace' }}>
                192.168.1.10
              </div>
              <div style={{ fontSize: '11px', color: '#66645D', marginTop: '2px' }}>Subnet: 10.1.0.0/24</div>
            </div>

            <div style={{ backgroundColor: '#FFFDF8', border: '1px solid #EDEAE1', borderRadius: '8px', padding: '12px' }}>
              <span style={{ fontSize: '10px', fontWeight: '700', color: '#596F7D', textTransform: 'uppercase' }}>PEER B (RESPONDER)</span>
              <div style={{ fontSize: '13px', fontWeight: '700', color: '#252525', marginTop: '4px', fontFamily: 'monospace' }}>
                192.168.1.20
              </div>
              <div style={{ fontSize: '11px', color: '#66645D', marginTop: '2px' }}>Subnet: 10.2.0.0/24</div>
            </div>
          </div>

          {/* 8. IKE Version */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: '#66645D' }}>IKE VERSION</label>
              <button onClick={() => setInfoModalKey('ike')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#9A7618' }}>
                <HelpCircle style={{ width: '14px', height: '14px' }} />
              </button>
            </div>
            <select
              value={config.ike_version}
              onChange={(e) => setConfig({ ...config, ike_version: e.target.value })}
              disabled={executing}
              style={{
                width: '100%',
                height: '40px',
                padding: '0 12px',
                borderRadius: '6px',
                backgroundColor: '#FFFFFF',
                border: '1px solid #D8D4C8',
                color: '#252525',
                fontSize: '13px',
                fontWeight: '600'
              }}
            >
              <option value="IKEv2">IKEv2 (Recommended / Standard)</option>
              <option value="IKEv1">IKEv1 (Legacy / Phase 1 Main Mode)</option>
            </select>
          </div>

          {/* 9. IPsec Mode Segmented Control */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: '#66645D' }}>IPsec MODE</label>
              <button onClick={() => setInfoModalKey('mode')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#9A7618' }}>
                <HelpCircle style={{ width: '14px', height: '14px' }} />
              </button>
            </div>
            <div style={{ display: 'flex', backgroundColor: '#EDEAE1', padding: '3px', borderRadius: '7px', gap: '4px' }}>
              {['tunnel', 'transport'].map(m => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setConfig({ ...config, mode: m })}
                  disabled={executing}
                  style={{
                    flex: 1,
                    height: '36px',
                    borderRadius: '5px',
                    fontSize: '12px',
                    fontWeight: '700',
                    textTransform: 'uppercase',
                    cursor: 'pointer',
                    border: 'none',
                    backgroundColor: config.mode === m ? '#D6A928' : 'transparent',
                    color: config.mode === m ? '#252525' : '#66645D',
                    transition: 'all 0.15s ease'
                  }}
                >
                  {m} MODE
                </button>
              ))}
            </div>
          </div>

          {/* 10. Cryptographic Parameters */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '6px' }}>
                ENCRYPTION ALGORITHM
              </label>
              <select
                value={config.encryption}
                onChange={(e) => setConfig({ ...config, encryption: e.target.value })}
                disabled={executing}
                style={{
                  width: '100%',
                  height: '40px',
                  padding: '0 12px',
                  borderRadius: '6px',
                  backgroundColor: '#FFFFFF',
                  border: '1px solid #D8D4C8',
                  color: '#252525',
                  fontSize: '13px'
                }}
              >
                <option value="AES-256-GCM">AES-256-GCM (Secure AEAD)</option>
                <option value="AES-128-CBC">AES-128-CBC (Standard CBC)</option>
                <option value="3DES-CBC">3DES-CBC (Legacy / Weak)</option>
                <option value="NULL">NULL (No Encryption / Test)</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '6px' }}>
                INTEGRITY / AUTH ALGORITHM
              </label>
              <select
                value={config.integrity}
                onChange={(e) => setConfig({ ...config, integrity: e.target.value })}
                disabled={executing}
                style={{
                  width: '100%',
                  height: '40px',
                  padding: '0 12px',
                  borderRadius: '6px',
                  backgroundColor: '#FFFFFF',
                  border: '1px solid #D8D4C8',
                  color: '#252525',
                  fontSize: '13px'
                }}
              >
                <option value="NONE">NONE (AEAD Combined Mode)</option>
                <option value="HMAC-SHA2-256">HMAC-SHA2-256 (Recommended)</option>
                <option value="HMAC-MD5-96">HMAC-MD5-96 (Insecure / Weak)</option>
              </select>
            </div>

            {/* 11. DH Group */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                <label style={{ fontSize: '12px', fontWeight: '600', color: '#66645D' }}>DIFFIE-HELLMAN (DH) GROUP</label>
                <button onClick={() => setInfoModalKey('dh')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#9A7618' }}>
                  <HelpCircle style={{ width: '14px', height: '14px' }} />
                </button>
              </div>
              <select
                value={config.dh_group}
                onChange={(e) => setConfig({ ...config, dh_group: e.target.value })}
                disabled={executing}
                style={{
                  width: '100%',
                  height: '40px',
                  padding: '0 12px',
                  borderRadius: '6px',
                  backgroundColor: '#FFFFFF',
                  border: '1px solid #D8D4C8',
                  color: '#252525',
                  fontSize: '13px'
                }}
              >
                <option value="ECP256">Group 19 (ECP-256 / Secure)</option>
                <option value="MODP2048">Group 14 (MODP-2048 / Standard)</option>
                <option value="MODP1024">Group 2 (MODP-1024 / Weak)</option>
                <option value="NONE">NONE (No Key Exchange / Insecure)</option>
              </select>
            </div>
          </div>
        </div>

        {/* 12. RIGHT CARD — TRAFFIC GENERATION */}
        <div style={{
          backgroundColor: '#FFFFFF',
          border: '1px solid #D8D4C8',
          borderRadius: '10px',
          padding: '20px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
          display: 'flex',
          flexDirection: 'column',
          gap: '18px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #EDEAE1', paddingBottom: '12px' }}>
            <h3 style={{ margin: 0, fontSize: '15px', fontWeight: '700', color: '#252525' }}>
              02 TRAFFIC GENERATION
            </h3>
            <span style={{ fontSize: '11px', fontWeight: '600', color: '#8A877E', textTransform: 'uppercase' }}>
              L4/L7 PATTERN ENGINE
            </span>
          </div>

          {/* 14. Selectable Traffic Scenario Cards */}
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '8px' }}>
              SELECT TRAFFIC SCENARIO PATTERN
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: '8px' }}>
              {trafficTypes.map(t => {
                const isSelected = config.traffic_type === t.id;
                return (
                  <div
                    key={t.id}
                    onClick={() => !executing && setConfig({ ...config, traffic_type: t.id })}
                    style={{
                      height: '60px',
                      padding: '8px',
                      borderRadius: '6px',
                      border: isSelected ? '1px solid #D6A928' : '1px solid #D8D4C8',
                      backgroundColor: isSelected ? '#F4E7B8' : '#FFFDF8',
                      cursor: executing ? 'not-allowed' : 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'center',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <span style={{ fontSize: '12px', fontWeight: '700', color: isSelected ? '#9A7618' : '#252525' }}>
                      {t.label}
                    </span>
                    <span style={{ fontSize: '10px', color: '#66645D', marginTop: '2px' }}>
                      {t.desc}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 13. Numeric Traffic Parameters */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '4px' }}>
                DESTINATION PORT
              </label>
              <input
                type="number"
                value={config.destination_port}
                onChange={(e) => setConfig({ ...config, destination_port: parseInt(e.target.value) || 80 })}
                disabled={executing}
                style={{
                  width: '100%', height: '40px', padding: '0 12px', borderRadius: '6px',
                  border: '1px solid #D8D4C8', fontSize: '13px', fontFamily: 'monospace'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '4px' }}>
                PACKET COUNT
              </label>
              <input
                type="number"
                value={config.packet_count}
                onChange={(e) => setConfig({ ...config, packet_count: parseInt(e.target.value) || 10 })}
                disabled={executing}
                style={{
                  width: '100%', height: '40px', padding: '0 12px', borderRadius: '6px',
                  border: '1px solid #D8D4C8', fontSize: '13px', fontFamily: 'monospace'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '4px' }}>
                PAYLOAD SIZE (BYTES)
              </label>
              <input
                type="number"
                value={config.payload_size}
                onChange={(e) => setConfig({ ...config, payload_size: parseInt(e.target.value) || 64 })}
                disabled={executing}
                style={{
                  width: '100%', height: '40px', padding: '0 12px', borderRadius: '6px',
                  border: '1px solid #D8D4C8', fontSize: '13px', fontFamily: 'monospace'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '4px' }}>
                PACKET RATE (PKTS/SEC)
              </label>
              <input
                type="number"
                value={config.packet_rate}
                onChange={(e) => setConfig({ ...config, packet_rate: parseInt(e.target.value) || 10 })}
                disabled={executing}
                style={{
                  width: '100%', height: '40px', padding: '0 12px', borderRadius: '6px',
                  border: '1px solid #D8D4C8', fontSize: '13px', fontFamily: 'monospace'
                }}
              />
            </div>
          </div>

          {/* 15. Collapsible Advanced Settings */}
          <div style={{ borderTop: '1px solid #EDEAE1', paddingTop: '12px' }}>
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                fontSize: '12px', fontWeight: '700', color: '#9A7618',
                display: 'flex', alignItems: 'center', gap: '6px'
              }}
            >
              <Sliders style={{ width: '14px', height: '14px' }} />
              <span>{showAdvanced ? 'HIDE ADVANCED SETTINGS ▲' : 'SHOW ADVANCED OPERATOR SETTINGS ▼'}</span>
            </button>

            {showAdvanced && (
              <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: '600', color: '#8A877E', marginBottom: '4px' }}>
                    EXECUTION MODE
                  </label>
                  <select
                    value={config.execution_mode}
                    onChange={(e) => setConfig({ ...config, execution_mode: e.target.value })}
                    disabled={executing}
                    style={{ width: '100%', height: '36px', borderRadius: '6px', border: '1px solid #D8D4C8', fontSize: '12px' }}
                  >
                    <option value="auto">Automated Testbed Execution</option>
                    <option value="manual">Manual Step Controls</option>
                  </select>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 16. VALIDATION & ACTIONS PANEL */}
      <div style={{
        backgroundColor: '#FFFFFF',
        border: '1px solid #D8D4C8',
        borderRadius: '10px',
        padding: '20px',
        boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px'
      }}>
        {/* Validation Status Message Box */}
        {validation && (
          <div style={{
            padding: '12px 16px',
            borderRadius: '8px',
            backgroundColor: validation.valid ? '#E3EEE7' : '#F3E2E0',
            border: `1px solid ${validation.valid ? '#C5DEC9' : '#E2B9B5'}`,
            color: validation.valid ? '#245837' : '#7D2822',
            fontSize: '13px'
          }}>
            <strong>Validation Status:</strong> {validation.valid ? 'Experiment configuration valid and ready for execution.' : validation.errors?.join(', ')}
          </div>
        )}

        {/* Action Buttons Row */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              type="button"
              onClick={handleValidate}
              disabled={executing}
              style={{
                height: '42px',
                padding: '0 18px',
                borderRadius: '7px',
                backgroundColor: '#F4E7B8',
                border: '1px solid #D6A928',
                color: '#9A7618',
                fontWeight: '700',
                fontSize: '13px',
                cursor: executing ? 'not-allowed' : 'pointer'
              }}
            >
              VALIDATE CONFIGURATION
            </button>

            <button
              type="button"
              onClick={handleReset}
              disabled={executing}
              style={{
                height: '42px',
                padding: '0 16px',
                borderRadius: '7px',
                backgroundColor: '#FFFFFF',
                border: '1px solid #D8D4C8',
                color: '#66645D',
                fontWeight: '600',
                fontSize: '13px',
                cursor: executing ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}
            >
              <RotateCcw style={{ width: '14px', height: '14px' }} />
              <span>RESET EXPERIMENT</span>
            </button>
          </div>

          {/* 17. Primary Action: RUN EXPERIMENT */}
          <button
            type="button"
            onClick={handleRunExperiment}
            disabled={executing}
            style={{
              height: '46px',
              padding: '0 24px',
              borderRadius: '7px',
              backgroundColor: executing ? '#8A877E' : '#252525',
              color: '#FFFFFF',
              border: 'none',
              fontWeight: '750',
              fontSize: '13px',
              letterSpacing: '0.04em',
              cursor: executing ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              boxShadow: '0 2px 8px rgba(37,37,37,0.08)'
            }}
          >
            <Play style={{ width: '16px', height: '16px', color: '#D6A928' }} />
            <span>{executing ? 'RUNNING EXPERIMENT...' : 'RUN EXPERIMENT'}</span>
          </button>
        </div>
      </div>

      {/* 24. ERROR HANDLING PANEL */}
      {errorMsg && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          padding: '16px',
          backgroundColor: '#F3E2E0',
          border: '1px solid #E2B9B5',
          borderRadius: '10px',
          color: '#7D2822'
        }}>
          <AlertTriangle style={{ width: '20px', height: '20px', flexShrink: 0, color: '#A94B43' }} />
          <div>
            <strong>EXPERIMENT FAILED:</strong> {errorMsg}
          </div>
        </div>
      )}

      {/* 18. EXECUTION TIMELINE */}
      {(executing || currentStep > 0) && (
        <div style={{
          backgroundColor: '#FFFFFF',
          border: '1px solid #D8D4C8',
          borderRadius: '10px',
          padding: '20px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
          display: 'flex',
          flexDirection: 'column',
          gap: '12px'
        }}>
          <h4 style={{ margin: 0, fontSize: '15px', fontWeight: '700', color: '#252525' }}>
            EXPERIMENT EXECUTION TIMELINE
          </h4>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {[
              { num: 1, name: 'Validation & Options Check' },
              { num: 2, name: 'Peer SA Negotiation' },
              { num: 3, name: 'Traffic Pattern Generation' },
              { num: 4, name: 'PCAP Frame Capture' },
              { num: 5, name: 'DEEPSTATE Analysis Handoff' }
            ].map(stepItem => {
              const isStepDone = currentStep > stepItem.num;
              const isStepRunning = currentStep === stepItem.num && executing;

              let bg = '#EDEAE1';
              let text = '#8A877E';
              let statusText = 'WAITING';

              if (isStepDone) {
                bg = '#E3EEE7';
                text = '#3F7654';
                statusText = 'COMPLETE';
              } else if (isStepRunning) {
                bg = '#F4E7B8';
                text = '#9A7618';
                statusText = 'RUNNING';
              }

              return (
                <div key={stepItem.num} style={{
                  height: '52px',
                  padding: '0 16px',
                  borderRadius: '8px',
                  backgroundColor: bg,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  fontSize: '13px',
                  fontWeight: '600'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: text }}>
                    <span style={{ width: '24px', height: '24px', borderRadius: '50%', border: `1px solid ${text}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: '700' }}>
                      {stepItem.num}
                    </span>
                    <span>{stepItem.name}</span>
                  </div>
                  <span style={{ fontSize: '11px', fontWeight: '700', color: text }}>
                    {statusText}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 19. CAPTURE RESULT & 20. ANALYSIS HANDOFF */}
      {executionResult && (
        <div style={{
          backgroundColor: '#FFFDF8',
          border: '1px solid #D6A928',
          borderRadius: '10px',
          padding: '24px',
          boxShadow: '0 4px 12px rgba(214,169,40,0.08)',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <CheckCircle2 style={{ width: '22px', height: '22px', color: '#3F7654' }} />
              <div>
                <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                  EXPERIMENT RUN EXECUTED & PCAP CAPTURED
                </h4>
                <div style={{ fontSize: '12px', color: '#66645D', marginTop: '2px' }}>
                  Experiment ID: <code style={{ color: '#9A7618', fontWeight: '700' }}>{executionResult.experiment_id}</code> • Mode: <strong>{executionResult.execution_mode === 'live_container' ? 'StrongSwan Testbed' : 'Synthetic Engine'}</strong>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => handleAnalyzeHandoff(executionResult.experiment_id)}
              disabled={executing}
              style={{
                height: '42px',
                padding: '0 22px',
                borderRadius: '8px',
                backgroundColor: '#D6A928',
                color: '#252525',
                fontWeight: '700',
                fontSize: '13px',
                border: 'none',
                cursor: executing ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                boxShadow: '0 2px 8px rgba(37,37,37,0.06)',
                transition: 'background-color 0.15s ease'
              }}
              onMouseOver={(e) => e.currentTarget.style.backgroundColor = '#BF941F'}
              onMouseOut={(e) => e.currentTarget.style.backgroundColor = '#D6A928'}
            >
              <ArrowRight style={{ width: '16px', height: '16px', color: '#252525' }} />
              <span>{executing ? 'ANALYZING HANDOFF...' : 'HAND OFF TO DEEPSTATE ANALYSIS WORKSPACE'}</span>
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px', fontSize: '13px' }}>
            <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '12px', borderRadius: '6px' }}>
              <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600', textTransform: 'uppercase' }}>CONFIGURED DH GROUP</span>
              <div style={{ fontWeight: '700', color: '#252525', marginTop: '2px' }}>{config.dh_group}</div>
            </div>
            <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '12px', borderRadius: '6px' }}>
              <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600', textTransform: 'uppercase' }}>ENCRYPTION / AUTH</span>
              <div style={{ fontWeight: '700', color: '#252525', marginTop: '2px' }}>{config.encryption}</div>
            </div>
            <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '12px', borderRadius: '6px' }}>
              <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600', textTransform: 'uppercase' }}>TRAFFIC PROFILE</span>
              <div style={{ fontWeight: '700', color: '#9A7618', marginTop: '2px' }}>{config.traffic_type}</div>
            </div>
            <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '12px', borderRadius: '6px' }}>
              <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600', textTransform: 'uppercase' }}>PACKETS CAPTURED</span>
              <div style={{ fontWeight: '700', color: '#252525', marginTop: '2px' }}>{executionResult.packet_count}</div>
            </div>
            <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #EDEAE1', padding: '12px', borderRadius: '6px' }}>
              <span style={{ fontSize: '11px', color: '#8A877E', fontWeight: '600', textTransform: 'uppercase' }}>FILE SIZE</span>
              <div style={{ fontWeight: '700', color: '#252525', marginTop: '2px' }}>{executionResult.size_bytes || executionResult.file_size_bytes} B</div>
            </div>
          </div>
        </div>
      )}

      {/* 21. PCAP LIBRARY INTEGRATION / RECENT EXPERIMENTS */}
      {history.length > 0 && (
        <div style={{
          backgroundColor: '#FFFFFF',
          border: '1px solid #D8D4C8',
          borderRadius: '10px',
          padding: '20px',
          boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #EDEAE1', paddingBottom: '10px' }}>
            <History style={{ width: '18px', height: '18px', color: '#9A7618' }} />
            <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
              RECENT EXPERIMENTS LOG ({history.length} Runs)
            </h4>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {history.slice(0, 5).map(exp => (
              <div
                key={exp.experiment_id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '12px 16px',
                  borderRadius: '8px',
                  backgroundColor: '#FFFDF8',
                  border: '1px solid #EDEAE1'
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
                    padding: '6px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: '600',
                    backgroundColor: '#F4E7B8',
                    border: '1px solid #D6A928',
                    color: '#252525',
                    cursor: 'pointer'
                  }}
                >
                  ANALYZE WITH DEEPSTATE
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 23. EDUCATIONAL INFORMATION MODAL */}
      {infoModalKey && educationalTopics[infoModalKey] && (
        <InvestigationModal
          isOpen={true}
          onClose={() => setInfoModalKey(null)}
          title={educationalTopics[infoModalKey].title}
          subtitle="Educational Reference & Technical Overview"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', fontSize: '13px' }}>
            <div>
              <strong>What it does:</strong>
              <p style={{ margin: '4px 0 0', color: '#66645D', lineHeight: '1.4' }}>
                {educationalTopics[infoModalKey].explanation}
              </p>
            </div>

            <div>
              <strong>What DEEPSTATE Observes:</strong>
              <p style={{ margin: '4px 0 0', color: '#66645D', lineHeight: '1.4' }}>
                {educationalTopics[infoModalKey].observable_facts}
              </p>
            </div>

            <div style={{ padding: '10px 12px', backgroundColor: '#F3E2E0', border: '1px solid #E2B9B5', borderRadius: '6px', color: '#7D2822' }}>
              <strong>Limitations:</strong> {educationalTopics[infoModalKey].limitations}
            </div>
          </div>
        </InvestigationModal>
      )}

    </div>
  );
}
