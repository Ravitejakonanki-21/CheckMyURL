// In your ScanContext file
import { createContext, useContext, useState } from 'react';

const ScanContext = createContext();

export function ScanProvider({ children }) {
  const [hasScanned, setHasScanned] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  return (
    <ScanContext.Provider value={{ 
      hasScanned, 
      setHasScanned, 
      scanResult, 
      setScanResult 
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