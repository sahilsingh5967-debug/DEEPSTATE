import React, { useState, useEffect } from 'react';
import { FileText, Play, Loader2, HardDrive, AlertCircle } from 'lucide-react';
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
          <HardDrive style={{ width: '20px', height: '20px', color: '#38bdf8' }} />
          <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '600', color: '#f1f5f9' }}>
            PCAP Traffic Capture Selection
          </h3>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            onClick={() => setUseCustom(false)}
            style={{
              padding: '6px 14px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer',
              border: 'none',
              backgroundColor: !useCustom ? '#2563eb' : '#1e293b',
              color: !useCustom ? '#ffffff' : '#94a3b8'
            }}
          >
            Presets
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
              border: 'none',
              backgroundColor: useCustom ? '#2563eb' : '#1e293b',
              color: useCustom ? '#ffffff' : '#94a3b8'
            }}
          >
            Custom Path
          </button>
        </div>
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {!useCustom ? (
          <div>
            <label style={{ display: 'block', fontSize: '13px', color: '#94a3b8', marginBottom: '6px' }}>
              Select PCAP Capture Artifact:
            </label>
            <select
              value={selectedPath}
              onChange={(e) => setSelectedPath(e.target.value)}
              disabled={analyzing}
              style={{
                width: '100%',
                padding: '10px 14px',
                borderRadius: '8px',
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                color: '#f8fafc',
                fontSize: '14px',
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
            <label style={{ display: 'block', fontSize: '13px', color: '#94a3b8', marginBottom: '6px' }}>
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
                padding: '10px 14px',
                borderRadius: '8px',
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                color: '#f8fafc',
                fontSize: '14px',
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
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '6px',
            color: '#f87171',
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
              padding: '10px 20px',
              borderRadius: '8px',
              fontSize: '14px',
              fontWeight: '600',
              cursor: analyzing ? 'not-allowed' : 'pointer',
              border: 'none',
              backgroundColor: analyzing ? '#475569' : '#0284c7',
              color: '#ffffff',
              transition: 'background-color 0.2s'
            }}
          >
            {analyzing ? (
              <>
                <Loader2 style={{ width: '16px', height: '16px', animation: 'spin 1s linear infinite' }} />
                <span>Running Unified Pipeline...</span>
              </>
            ) : (
              <>
                <Play style={{ width: '16px', height: '16px' }} />
                <span>Execute Unified Analysis</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
