import React, { useEffect, useState, useRef } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import PcapSelector from './components/PcapSelector';
import UnifiedResults from './components/UnifiedResults';
import DemonstrationLab from './components/DemonstrationLab';
import { fetchBackendHealth, fetchAvailablePcaps, analyzePcap } from './api/client';
import { AlertTriangle } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview'); // Default to Main DEEPSTATE Dashboard for Phase 9.2
  const [health, setHealth] = useState(null);
  const [loadingHealth, setLoadingHealth] = useState(true);
  const [pcaps, setPcaps] = useState([]);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [apiError, setApiError] = useState('');
  const resultsRef = useRef(null);

  useEffect(() => {
    async function loadInitialData() {
      setLoadingHealth(true);
      const [healthData, pcapsData] = await Promise.all([
        fetchBackendHealth(),
        fetchAvailablePcaps()
      ]);
      setHealth(healthData);
      setPcaps(pcapsData);
      setLoadingHealth(false);
    }
    loadInitialData();
  }, []);

  const handleAnalyze = async (filePath) => {
    setAnalyzing(true);
    setApiError('');

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

  const scrollToResults = () => {
    if (resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', backgroundColor: '#F4F1E8', color: '#252525', fontFamily: "'Inter', sans-serif" }}>
      {/* Top 72px Navigation Header from Phase 9.1 */}
      <Header backendHealth={health} loading={loadingHealth} activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Content Area (Sidebar returns null, max 1480px centered) */}
      <div style={{ flex: 1, display: 'flex', justifyContent: 'center' }}>
        <Sidebar />

        <main style={{
          width: '100%',
          maxWidth: '1480px',
          padding: '32px 24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '24px',
          boxSizing: 'border-box'
        }}>

          {/* Failure Alert Box */}
          {apiError && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              padding: '16px 20px',
              backgroundColor: '#F3E2E0',
              border: '1px solid #E2B9B5',
              borderRadius: '10px',
              color: '#7D2822',
              boxShadow: '0 2px 8px rgba(37,37,37,0.04)'
            }}>
              <AlertTriangle style={{ width: '20px', height: '20px', flexShrink: 0, color: '#A94B43' }} />
              <div style={{ fontSize: '13px', fontWeight: '500' }}>
                <strong style={{ color: '#7D2822' }}>Analysis Pipeline Failure:</strong> {apiError}
              </div>
            </div>
          )}

          {/* TAB CONTENT VIEWS */}
          {activeTab === 'overview' && (
            <Dashboard
              analysisResult={analysisResult}
              onAnalyze={handleAnalyze}
              onNavigate={setActiveTab}
              health={health}
              pcaps={pcaps}
              onViewFullAnalysis={scrollToResults}
            />
          )}

          {activeTab === 'lab' && (
            <DemonstrationLab onAnalyzeResult={handleLabAnalysisResult} />
          )}

          {activeTab === 'analyze' && (
            <PcapSelector onAnalyze={handleAnalyze} analyzing={analyzing} />
          )}

          {activeTab === 'library' && (
            <PcapSelector onAnalyze={handleAnalyze} analyzing={analyzing} />
          )}

          {/* Unified 3-Tier Detailed Results Display (renders when an analysis result is present) */}
          {analysisResult && (
            <div ref={resultsRef} style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '12px' }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                backgroundColor: '#FFFFFF',
                padding: '14px 20px',
                borderRadius: '10px',
                border: '1px solid #D8D4C8',
                boxShadow: '0 2px 8px rgba(37,37,37,0.04)'
              }}>
                <span style={{ fontSize: '14px', fontWeight: '700', color: '#252525' }}>
                  Detailed Unified Analysis Report — Session <code style={{ backgroundColor: '#EDEAE1', padding: '2px 6px', borderRadius: '4px', fontFamily: 'monospace' }}>{analysisResult.analysis_id}</code>
                </span>
                <button
                  type="button"
                  onClick={() => setAnalysisResult(null)}
                  style={{ fontSize: '12px', color: '#9A7618', fontWeight: '600', background: 'none', border: 'none', cursor: 'pointer' }}
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
