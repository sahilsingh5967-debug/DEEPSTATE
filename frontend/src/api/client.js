/**
 * API Client module for backend communication and DEEPSTATE Demonstration Lab 2.0 integration.
 */
const API_BASE_URL = import.meta.env.VITE_API_URL || '';

export async function fetchBackendHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    if (!response.ok) {
      throw new Error(`Health check failed: HTTP ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('API Health check error:', error);
    return {
      status: 'offline',
      error: error.message,
    };
  }
}

export async function fetchAvailablePcaps() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/pcaps`);
    if (!response.ok) {
      throw new Error(`Failed to fetch PCAP list: HTTP ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Fetch PCAPs error:', error);
    return [];
  }
}

export async function analyzePcap(filePath) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        source_type: 'pcap_file',
        file_path: filePath,
      }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      const detailMsg = errData.detail || `Analysis request failed with status ${response.status}`;
      throw new Error(detailMsg);
    }

    return await response.json();
  } catch (error) {
    console.error('PCAP Analysis error:', error);
    throw error;
  }
}

// --- Demonstration Lab 2.0 Testbed API Functions ---

export async function fetchTestbedOptions() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/testbed/config/options`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error('Fetch testbed options error:', error);
    return null;
  }
}

export async function fetchTestbedStatus() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/testbed/status`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error('Fetch testbed status error:', error);
    return { docker_available: false, mode: 'synthetic_fallback' };
  }
}

export async function validateExperimentConfig(config) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/testbed/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    return await response.json();
  } catch (error) {
    console.error('Validate experiment error:', error);
    return { valid: false, errors: [error.message] };
  }
}

export async function executeExperimentRun(config) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/testbed/experiment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Experiment failed with status ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Execute experiment error:', error);
    throw error;
  }
}

export async function fetchExperimentHistory() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/testbed/experiments`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error('Fetch experiment history error:', error);
    return [];
  }
}

export async function analyzeExperimentRecord(experimentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/testbed/experiments/${experimentId}/analyze`, {
      method: 'POST',
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Experiment analysis failed with status ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Analyze experiment record error:', error);
    throw error;
  }
}
