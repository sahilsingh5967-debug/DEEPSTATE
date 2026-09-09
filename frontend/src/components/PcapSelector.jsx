import React, { useState, useEffect } from 'react';
import { Play, Loader2, HardDrive, AlertCircle, FileText } from 'lucide-react';
import { fetchAvailablePcaps } from '../api/client';

export default function PcapSelector({ onAnalyze, analyzing }) {
  const [pcaps, setPcaps] = useState([]);
  const [selectedPath, setSelectedPath] = useState('');
  const [customPath, setCustomPath] = useState('');
  const [useCustom, setUseCustom] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  useEffect(() => {
    async function loadPresets() {
      const items = await fetchAvailablePcaps();
      setPcaps(items);
      if (items.length > 0) {
        setSelectedPath(items[0].file_path);
      }
    }
    loadPresets();
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    setErrorMsg('');
    const targetPath = useCustom ? customPath.trim() : selectedPath;
    if (!targetPath) {
      setErrorMsg('Please select a PCAP file preset or enter a valid file path.');
      return;
    }
    onAnalyze(targetPath);
  };

  return (
    <div style={{
      backgroundColor: '#FFFFFF',
      borderRadius: '10px',
      border: '1px solid #D8D4C8',
      padding: '24px',
      boxShadow: '0 2px 8px rgba(30, 30, 20, 0.05)',
      display: 'flex',
      flexDirection: 'column',
      gap: '20px'
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #E3DFD4', paddingBottom: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ padding: '8px', borderRadius: '7px', backgroundColor: '#F4E7B8', color: '#9A7618' }}>
            <HardDrive style={{ width: '18px', height: '18px' }} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
              PCAP Ingestion & Analysis Controls
            </h3>
            <span style={{ fontSize: '12px', color: '#66645D' }}>
              Select ground-truth captures, synthetic fixtures, or custom path for 3-tier analysis
            </span>
          </div>
        </div>

        {/* Toggle Mode Buttons */}
        <div style={{ display: 'flex', gap: '6px', backgroundColor: '#EDEAE1', padding: '3px', borderRadius: '8px', border: '1px solid #D8D4C8' }}>
          <button
            type="button"
            onClick={() => setUseCustom(false)}
            style={{
              padding: '6px 14px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer',
              border: !useCustom ? '1px solid #D6A928' : 'none',
              backgroundColor: !useCustom ? '#F4E7B8' : 'transparent',
              color: !useCustom ? '#252525' : '#66645D'
            }}
          >
            PCAP Presets
          </button>
          <button
            type="button"
            onClick={() => setUseCustom(true)}
            style={{
              padding: '6px 14px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer',
              border: useCustom ? '1px solid #D6A928' : 'none',
              backgroundColor: useCustom ? '#F4E7B8' : 'transparent',
              color: useCustom ? '#252525' : '#66645D'
            }}
          >
            Custom Path
          </button>
        </div>
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {!useCustom ? (
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '6px' }}>
              Select PCAP Capture Artifact:
            </label>
            <select
              value={selectedPath}
              onChange={(e) => setSelectedPath(e.target.value)}
              disabled={analyzing}
              style={{
                width: '100%',
                height: '42px',
                padding: '0 14px',
                borderRadius: '7px',
                backgroundColor: '#FFFFFF',
                border: '1px solid #CFCABE',
                color: '#252525',
                fontSize: '13px',
                fontFamily: 'monospace',
                outline: 'none'
              }}
            >
              {pcaps.map((p) => (
                <option key={p.id} value={p.file_path}>
                  [{p.category}] {p.name} ({p.size_bytes} bytes)
                </option>
              ))}
            </select>
          </div>
        ) : (
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#66645D', marginBottom: '6px' }}>
              Enter Relative or Absolute PCAP File Path:
            </label>
            <input
              type="text"
              placeholder="e.g. data/pcaps/real/TEST-001.pcap"
              value={customPath}
              onChange={(e) => setCustomPath(e.target.value)}
              disabled={analyzing}
              style={{
                width: '100%',
                height: '42px',
                padding: '0 14px',
                borderRadius: '7px',
                backgroundColor: '#FFFFFF',
                border: '1px solid #CFCABE',
                color: '#252525',
                fontSize: '13px',
                fontFamily: 'monospace',
                outline: 'none'
              }}
            />
          </div>
        )}

        {errorMsg && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 14px',
            backgroundColor: '#F3E2E0',
            border: '1px solid #E8C4C1',
            borderRadius: '6px',
            color: '#A94B43',
            fontSize: '13px'
          }}>
            <AlertCircle style={{ width: '16px', height: '16px' }} />
            <span>{errorMsg}</span>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button
            type="submit"
            disabled={analyzing}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              height: '42px',
              padding: '0 22px',
              borderRadius: '8px',
              fontSize: '14px',
              fontWeight: '700',
              cursor: analyzing ? 'not-allowed' : 'pointer',
              border: 'none',
              backgroundColor: analyzing ? '#77736A' : '#252525',
              color: '#FFFFFF',
              transition: 'background-color 0.15s'
            }}
          >
            {analyzing ? (
              <>
                <Loader2 style={{ width: '16px', height: '16px', animation: 'spin 1s linear infinite' }} />
                <span>Executing 3-Tier Pipeline...</span>
              </>
            ) : (
              <>
                <Play style={{ width: '16px', height: '16px', color: '#D6A928' }} />
                <span>Execute Unified Analysis</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Preset PCAP Library Table */}
      {pcaps.length > 0 && !useCustom && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '10px' }}>
          <span style={{ fontSize: '11px', fontWeight: '700', color: '#8A877E', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Available PCAP Repository Files ({pcaps.length} Artifacts)
          </span>
          <div style={{ overflowX: 'auto', border: '1px solid #D8D4C8', borderRadius: '8px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
              <thead>
                <tr style={{ backgroundColor: '#EDEAE1', borderBottom: '1px solid #D8D4C8', color: '#66645D', fontSize: '12px', fontWeight: '700' }}>
                  <th style={{ padding: '10px 14px' }}>Artifact Name</th>
                  <th style={{ padding: '10px 14px' }}>Category</th>
                  <th style={{ padding: '10px 14px' }}>Size</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {pcaps.map((p, idx) => (
                  <tr key={p.id} style={{ borderBottom: idx === pcaps.length - 1 ? 'none' : '1px solid #E3DFD4', backgroundColor: '#FFFFFF' }}>
                    <td style={{ padding: '10px 14px', fontWeight: '600', color: '#252525', fontFamily: 'monospace' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <FileText style={{ width: '14px', height: '14px', color: '#D6A928' }} />
                        <span>{p.name}</span>
                      </div>
                    </td>
                    <td style={{ padding: '10px 14px', color: '#66645D' }}>{p.category}</td>
                    <td style={{ padding: '10px 14px', color: '#8A877E', fontFamily: 'monospace' }}>{p.size_bytes} bytes</td>
                    <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                      <button
                        type="button"
                        onClick={() => onAnalyze(p.file_path)}
                        disabled={analyzing}
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
                        Analyze
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
