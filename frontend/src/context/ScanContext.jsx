import { createContext, useContext, useState } from 'react';

const ScanContext = createContext();

export function ScanProvider({ children }) {
  const [hasScanned, setHasScanned] = useState(() => {
    return localStorage.getItem('hasScanned') === 'true';
  });

  const updateScanStatus = (value) => {
    setHasScanned(value);
    localStorage.setItem('hasScanned', value.toString());
  };

  return (
    <ScanContext.Provider value={{ hasScanned, setHasScanned: updateScanStatus }}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  const context = useContext(ScanContext);
  if (context === undefined) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
}

export { ScanContext };