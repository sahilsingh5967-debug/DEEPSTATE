import React, { useState, useEffect } from 'react';
import { Play, Loader2, HardDrive, AlertCircle, FileText, Search, RefreshCw, ChevronRight } from 'lucide-react';
import { fetchAvailablePcaps } from '../api/client';

export default function PcapSelector({ onAnalyze, analyzing, viewMode = 'analyze' }) {
  const [pcaps, setPcaps] = useState([]);
  const [selectedPath, setSelectedPath] = useState('');
  const [customPath, setCustomPath] = useState('');
  const [useCustom, setUseCustom] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

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

  const handleRefresh = async () => {
    const items = await fetchAvailablePcaps();
    setPcaps(items);
  };

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

  const filteredPcaps = pcaps.filter(p => {
    const matchesSearch = p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          p.file_path.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = categoryFilter === 'ALL' || p.category?.toUpperCase() === categoryFilter;
    return matchesSearch && matchesCategory;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

      {/* Page Header */}
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
            <span style={{ color: '#9A7618' }}>{viewMode === 'library' ? 'PCAP LIBRARY' : 'PCAP INGESTION'}</span>
          </div>

          <h1 style={{ margin: '0 0 6px', fontSize: '30px', fontWeight: '700', color: '#252525', letterSpacing: '-0.02em' }}>
            {viewMode === 'library' ? 'PCAP Evidence Library' : 'PCAP Ingestion & Analysis Engine'}
          </h1>
          <p style={{ margin: 0, fontSize: '14px', color: '#66645D', maxWidth: '850px', lineHeight: '1.4' }}>
            {viewMode === 'library'
              ? 'Browse pre-packaged ground-truth test PCAPs and historical analysis captures.'
              : 'Select ground-truth captures, synthetic fixtures, or enter custom paths for 3-tier security analysis.'}
          </p>
        </div>

        {/* Selected Status Pill */}
        <div style={{
          height: '32px',
          padding: '0 14px',
          borderRadius: '999px',
          backgroundColor: analyzing ? '#F5EBD5' : selectedPath ? '#E3EEE7' : '#EDEAE1',
          color: analyzing ? '#B57B22' : selectedPath ? '#3F7654' : '#66645D',
          border: `1px solid ${analyzing ? '#E6D3A7' : selectedPath ? '#C5DEC9' : '#D8D4C8'}`,
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '12px',
          fontWeight: '700'
        }}>
          <span style={{ width: '7px', height: '7px', borderRadius: '50%', backgroundColor: analyzing ? '#B57B22' : selectedPath ? '#3F7654' : '#8A877E' }} />
          <span>STATUS: {analyzing ? 'ANALYZING PCAP...' : selectedPath ? 'ARTIFACT READY FOR INGESTION' : 'SELECT ARTIFACT'}</span>
        </div>
      </div>

      {/* Ingestion & Selection Card */}
      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: '10px',
        border: '1px solid #D8D4C8',
        padding: '24px',
        boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: '20px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #EDEAE1', paddingBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ padding: '8px', borderRadius: '6px', backgroundColor: '#F4E7B8', color: '#9A7618' }}>
              <HardDrive style={{ width: '18px', height: '18px' }} />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '700', color: '#252525' }}>
                PCAP Selection & Ingestion Controls
              </h3>
              <span style={{ fontSize: '12px', color: '#66645D' }}>
                Choose preset capture files or specify a custom filesystem path
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '6px', backgroundColor: '#EDEAE1', padding: '3px', borderRadius: '7px', border: '1px solid #D8D4C8' }}>
            <button
              type="button"
              onClick={() => setUseCustom(false)}
              style={{
                padding: '6px 14px',
                borderRadius: '5px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                border: !useCustom ? '1px solid #D6A928' : 'none',
                backgroundColor: !useCustom ? '#F4E7B8' : 'transparent',
                color: !useCustom ? '#9A7618' : '#66645D'
              }}
            >
              Preset Repository
            </button>
            <button
              type="button"
              onClick={() => setUseCustom(true)}
              style={{
                padding: '6px 14px',
                borderRadius: '5px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                border: useCustom ? '1px solid #D6A928' : 'none',
                backgroundColor: useCustom ? '#F4E7B8' : 'transparent',
                color: useCustom ? '#9A7618' : '#66645D'
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
                SELECT PCAP CAPTURE ARTIFACT:
              </label>
              <select
                value={selectedPath}
                onChange={(e) => setSelectedPath(e.target.value)}
                disabled={analyzing}
                style={{
                  width: '100%',
                  height: '40px',
                  padding: '0 12px',
                  borderRadius: '6px',
                  backgroundColor: '#FFFFFF',
                  border: '1px solid #D8D4C8',
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
                ENTER RELATIVE OR ABSOLUTE PCAP FILE PATH:
              </label>
              <input
                type="text"
                placeholder="e.g. data/pcaps/real/TEST-001.pcap"
                value={customPath}
                onChange={(e) => setCustomPath(e.target.value)}
                disabled={analyzing}
                style={{
                  width: '100%',
                  height: '40px',
                  padding: '0 12px',
                  borderRadius: '6px',
                  backgroundColor: '#FFFFFF',
                  border: '1px solid #D8D4C8',
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
              border: '1px solid #E2B9B5',
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
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: '700',
                cursor: analyzing ? 'not-allowed' : 'pointer',
                border: 'none',
                backgroundColor: analyzing ? '#8A877E' : '#252525',
                color: '#FFFFFF',
                transition: 'background-color 0.15s'
              }}
            >
              {analyzing ? (
                <>
                  <Loader2 style={{ width: '16px', height: '16px', animation: 'spin 1s linear infinite' }} />
                  <span>Executing 3-Tier Analysis...</span>
                </>
              ) : (
                <>
                  <Play style={{ width: '15px', height: '15px', color: '#D6A928' }} />
                  <span>EXECUTE UNIFIED ANALYSIS</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Preset PCAP Library Repository Table & Controls */}
      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: '10px',
        border: '1px solid #D8D4C8',
        padding: '24px',
        boxShadow: '0 2px 8px rgba(37,37,37,0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px'
      }}>
        {/* Search & Filter Toolbar */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h3 style={{ margin: '0 0 2px', fontSize: '16px', fontWeight: '700', color: '#252525' }}>
              Available PCAP Repository Artifacts ({filteredPcaps.length})
            </h3>
            <span style={{ fontSize: '12px', color: '#66645D' }}>
              Ground-truth PCAP captures and synthetic testbed fixtures
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            {/* Search Input */}
            <div style={{ position: 'relative', width: '220px' }}>
              <Search style={{ width: '14px', height: '14px', color: '#8A877E', position: 'absolute', left: '10px', top: '13px' }} />
              <input
                type="text"
                placeholder="Search PCAP name..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  height: '38px',
                  paddingLeft: '32px',
                  paddingRight: '12px',
                  borderRadius: '6px',
                  border: '1px solid #D8D4C8',
                  fontSize: '12px',
                  backgroundColor: '#FFFFFF'
                }}
              />
            </div>

            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              style={{
                height: '38px',
                padding: '0 12px',
                borderRadius: '6px',
                border: '1px solid #D8D4C8',
                fontSize: '12px',
                backgroundColor: '#FFFFFF',
                color: '#252525',
                fontWeight: '600'
              }}
            >
              <option value="ALL">All Categories</option>
              <option value="REAL">Real Ground Truth</option>
              <option value="SYNTHETIC">Synthetic Testbed</option>
            </select>

            {/* Refresh Button */}
            <button
              type="button"
              onClick={handleRefresh}
              style={{
                height: '38px',
                padding: '0 12px',
                borderRadius: '6px',
                border: '1px solid #D8D4C8',
                backgroundColor: '#FFFFFF',
                color: '#66645D',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '12px',
                fontWeight: '600'
              }}
            >
              <RefreshCw style={{ width: '14px', height: '14px' }} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Repository Table */}
        {filteredPcaps.length > 0 ? (
          <div style={{ overflowX: 'auto', border: '1px solid #D8D4C8', borderRadius: '8px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
              <thead>
                <tr style={{ backgroundColor: '#EDEAE1', borderBottom: '1px solid #D8D4C8', color: '#66645D', fontSize: '12px', fontWeight: '700' }}>
                  <th style={{ padding: '10px 14px' }}>Artifact Name</th>
                  <th style={{ padding: '10px 14px' }}>Category</th>
                  <th style={{ padding: '10px 14px' }}>File Size</th>
                  <th style={{ padding: '10px 14px' }}>Target Classifier</th>
                  <th style={{ padding: '10px 14px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredPcaps.map((p, idx) => (
                  <tr key={p.id || idx} style={{ borderBottom: idx === filteredPcaps.length - 1 ? 'none' : '1px solid #EDEAE1', backgroundColor: '#FFFFFF' }}>
                    <td style={{ padding: '10px 14px', fontWeight: '600', color: '#252525', fontFamily: 'monospace' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <FileText style={{ width: '14px', height: '14px', color: '#9A7618' }} />
                        <span>{p.name}</span>
                      </div>
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
                        {p.category}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px', color: '#8A877E', fontFamily: 'monospace' }}>
                      {p.size_bytes} bytes
                    </td>
                    <td style={{ padding: '10px 14px', color: '#66645D' }}>
                      Random Forest Model
                    </td>
                    <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                      <button
                        type="button"
                        onClick={() => onAnalyze(p.file_path)}
                        disabled={analyzing}
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
                        ANALYZE
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '24px', textAlign: 'center', color: '#8A877E', fontSize: '13px' }}>
            No PCAP artifacts match the search or filter query.
          </div>
        )}
      </div>
    </div>
  );
}
