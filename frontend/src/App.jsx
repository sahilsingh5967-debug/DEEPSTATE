import React, { useEffect, useState } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import PcapSelector from './components/PcapSelector';
import UnifiedResults from './components/UnifiedResults';
import { fetchBackendHealth, analyzePcap } from './api/client';
import { AlertTriangle } from 'lucide-react';

export default function App() {
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
          <div>
            <h2 style={{ margin: '0 0 6px', fontSize: '22px', fontWeight: '700', color: '#f8fafc' }}>
              DEEPSTATE — IPsec Security Intelligence Center
            </h2>
            <p style={{ margin: 0, fontSize: '14px', color: '#94a3b8' }}>
              Unified PCAP Ingestion & Analysis Workflow integrating Deterministic Protocol Parsing (Phase 3), Security Policy Scoring (Phase 4), and Encrypted Traffic ML Inference (Phase 5).
            </p>
          </div>

          <PcapSelector onAnalyze={handleAnalyze} analyzing={analyzing} />

          {apiError && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '16px',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '8px',
              color: '#f87171'
            }}>
              <AlertTriangle style={{ width: '20px', height: '20px', flexShrink: 0 }} />
              <div>
                <strong>Analysis Pipeline Failure:</strong> {apiError}
              </div>
            </div>
          )}

          {analysisResult && (
            <UnifiedResults result={analysisResult} />
          )}
        </main>
      </div>
    </div>
  );
}
