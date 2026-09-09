import React, { useEffect, useState } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import PcapSelector from './components/PcapSelector';
import UnifiedResults from './components/UnifiedResults';
import DemonstrationLab from './components/DemonstrationLab';
import { fetchBackendHealth, analyzePcap } from './api/client';
import { AlertTriangle, ShieldCheck, FlaskConical } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('lab'); // Default to Demonstration Lab 2.0 for SIH presentation
  const [health, setHealth] = useState(null);
  const [loadingHealth, setLoadingHealth] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [apiError, setApiError] = useState('');

  useEffect(() => {
    async function loadHealth() {
      setLoadingHealth(true);
      const data = await fetchBackendHealth();
      setHealth(data);
      setLoadingHealth(false);
    }
    loadHealth();
  }, []);

  const handleAnalyze = async (filePath) => {
    setAnalyzing(true);
    setApiError('');
    setAnalysisResult(null);

    try {
      const result = await analyzePcap(filePath);
      setAnalysisResult(result);
    } catch (err) {
      setApiError(err.message || 'PCAP Analysis failed. Please verify the file path and backend status.');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleLabAnalysisResult = (result) => {
    setAnalysisResult(result);
    setApiError('');
  };

  const pipelineStatus = analyzing
    ? 'analyzing'
    : apiError
    ? 'failed'
    : analysisResult
    ? 'completed'
    : 'idle';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', backgroundColor: '#090d16', color: '#f8fafc' }}>
      <Header backendHealth={health} loading={loadingHealth} pipelineStatus={pipelineStatus} />

      <div style={{ display: 'flex', flex: 1 }}>
        <Sidebar />

        <main style={{ flex: 1, padding: '28px', display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1400px' }}>

          {/* Top Mode Selector Tabs */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #1e293b', paddingBottom: '16px' }}>
            <div>
              <h2 style={{ margin: '0 0 4px', fontSize: '22px', fontWeight: '700', color: '#f8fafc' }}>
                DEEPSTATE — IPsec VPN Security Intelligence Center
              </h2>
              <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8' }}>
                Deterministic Protocol Parsing (Tier A) • Policy Rule Scoring (Tier B) • Encrypted Traffic ML Inference (Tier C)
              </p>
            </div>

            <div style={{ display: 'flex', gap: '8px', backgroundColor: '#0f172a', padding: '4px', borderRadius: '10px', border: '1px solid #1e293b' }}>
              <button
                type="button"
                onClick={() => setActiveTab('lab')}
                style={{
                  display: 'flex', alignItems: 'center', gap: '8px',
                  padding: '8px 16px', borderRadius: '8px', fontSize: '13px', fontWeight: '700',
                  cursor: 'pointer', border: 'none',
                  backgroundColor: activeTab === 'lab' ? '#0284c7' : 'transparent',
                  color: activeTab === 'lab' ? '#ffffff' : '#94a3b8'
                }}
              >
                <FlaskConical style={{ width: '16px', height: '16px' }} />
                <span>Demonstration Lab 2.0</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('soc')}
                style={{
                  display: 'flex', alignItems: 'center', gap: '8px',
                  padding: '8px 16px', borderRadius: '8px', fontSize: '13px', fontWeight: '700',
                  cursor: 'pointer', border: 'none',
                  backgroundColor: activeTab === 'soc' ? '#0284c7' : 'transparent',
                  color: activeTab === 'soc' ? '#ffffff' : '#94a3b8'
                }}
              >
                <ShieldCheck style={{ width: '16px', height: '16px' }} />
                <span>Preset PCAP Ingestion</span>
              </button>
            </div>
          </div>

          {/* Tab 1: Demonstration Lab 2.0 */}
          {activeTab === 'lab' && (
            <DemonstrationLab onAnalyzeResult={handleLabAnalysisResult} />
          )}

          {/* Tab 2: Classic Preset Ingestion */}
          {activeTab === 'soc' && (
            <PcapSelector onAnalyze={handleAnalyze} analyzing={analyzing} />
          )}

          {/* Failure Alert */}
          {apiError && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: '10px', padding: '16px',
              backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '8px', color: '#f87171'
            }}>
              <AlertTriangle style={{ width: '20px', height: '20px', flexShrink: 0 }} />
              <div>
                <strong>Analysis Pipeline Failure:</strong> {apiError}
              </div>
            </div>
          )}

          {/* Unified 3-Tier Results Display */}
          {analysisResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', backgroundColor: '#0f172a', padding: '12px 18px', borderRadius: '8px', border: '1px solid #1e293b' }}>
                <span style={{ fontSize: '14px', fontWeight: '700', color: '#38bdf8' }}>
                  DEEPSTATE Unified Analysis Output (Session ID: {analysisResult.analysis_id})
                </span>
                <button
                  type="button"
                  onClick={() => setAnalysisResult(null)}
                  style={{ fontSize: '12px', color: '#94a3b8', background: 'none', border: 'none', cursor: 'pointer' }}
                >
                  Clear Results
                </button>
              </div>
              <UnifiedResults result={analysisResult} />
            </div>
          )}

        </main>
      </div>
    </div>
  );
}
