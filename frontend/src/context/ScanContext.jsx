import { createContext, useContext, useState, useCallback } from 'react';

const ScanContext = createContext();

const HISTORY_KEY = 'cmu_scan_history';
const MAX_HISTORY = 100;

function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveHistory(history) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch {
    // storage full or unavailable — ignore
  }
}

export function ScanProvider({ children }) {
  const [hasScanned, setHasScanned] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [isShowingResults, setIsShowingResults] = useState(false);
  const [history, setHistory] = useState(loadHistory);

  /**
   * Called by Scanner.jsx after every successful scan.
   * Expects a result object with at least { url, riskScore, classification, details }
   */
  const recordScan = useCallback((result) => {
    if (!result) return;

    // Derive per-tool finding counts from the scan result
    const d = result.details || {};
    const tools = {
      SSL:      d.sslValid ? 1 : 0,
      WHOIS:    d.whoisAgeMonths != null ? 1 : 0,
      Headers:  (d.securityHeaders?.length ?? 0),
      Keywords: (d.keywords?.length ?? 0),
      Ports:    (d.openPorts?.length ?? 0),
      ML:       d.mlData ? 1 : 0,
    };

    const entry = {
      url:           result.url,
      riskScore:     typeof result.riskScore === 'number' ? result.riskScore : 0,
      classification: result.classification ?? 'Unknown',
      tools,
      userEmail:     localStorage.getItem('email') || undefined,
      scannedAt:     new Date().toISOString(),
    };

    setHistory((prev) => {
      const next = [...prev, entry].slice(-MAX_HISTORY);
      saveHistory(next);
      return next;
    });

    setHasScanned(true);
    setScanResult(result);
  }, []);

  /** Clear all scan history */
  const clearHistory = useCallback(() => {
    setHistory([]);
    localStorage.removeItem(HISTORY_KEY);
  }, []);

  return (
    <ScanContext.Provider value={{
      hasScanned,
      setHasScanned,
      isShowingResults,
      setIsShowingResults,
      history,
      recordScan,
      clearHistory,
    }}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
}