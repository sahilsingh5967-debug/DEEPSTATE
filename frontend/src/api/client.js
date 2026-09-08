/**
 * API Client module for backend communication.
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
