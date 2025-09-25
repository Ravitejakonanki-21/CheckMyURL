import { createContext, useContext, useMemo, useState } from "react";

const ScanContext = createContext();

export const ScanProvider = ({ children }) => {
  const [latest, setLatest] = useState(null);
  const [history, setHistory] = useState([]);

  const recordScan = (result) => {
    const entry = {
      url: result.url,
      riskScore: result.riskScore,
      classification: result.classification,
      tools: {
        SSL: result.details.sslValid ? 1 : 0,
        WHOIS: 1,
        Headers: result.details.securityHeaders.length,
        Keywords: result.details.keywords.length,
        Ports: result.details.openPorts.length,
        ML: Math.round(result.details.mlPhishingScore / 20),
      },
      ts: Date.now(),
    };
    setLatest(result);
    setHistory((prev) => [...prev, entry].slice(-50));
  };

  const value = useMemo(() => ({ latest, history, recordScan }), [latest, history]);

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
};

export const useScan = () => useContext(ScanContext);
