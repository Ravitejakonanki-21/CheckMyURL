import React from 'react';
import SummaryCard from '../components/SummaryCard';
import ModuleStatus from '../components/ModuleStatus';
import FindingsTable from '../components/FindingsTable';

const Dashboard = () => {
  return (
    <div style={styles.dashboard}>
      <div style={styles.scanSection}>
        <h2 style={styles.sectionTitle}>Enter URL to scan</h2>
        <div style={styles.urlInputContainer}>
          <input 
            type="text" 
            placeholder="https://example.com" 
            style={styles.urlInput}
          />
          <button style={styles.scanButton}>Scan Now</button>
        </div>
      </div>
      
      <SummaryCard />
      <ModuleStatus />
      <FindingsTable />
    </div>
  );
};

const styles = {
  dashboard: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2rem'
  },
  scanSection: {
    background: '#1a1a1a',
    padding: '2rem',
    borderRadius: '8px',
    border: '1px solid #333'
  },
  sectionTitle: {
    margin: '0 0 1rem 0',
    color: '#00ff88',
    fontSize: '1.5rem'
  },
  urlInputContainer: {
    display: 'flex',
    gap: '1rem',
    alignItems: 'center'
  },
  urlInput: {
    flex: 1,
    padding: '0.75rem',
    backgroundColor: '#2d2d2d',
    border: '1px solid #444',
    borderRadius: '4px',
    color: '#fff',
    fontSize: '1rem'
  },
  scanButton: {
    padding: '0.75rem 2rem',
    backgroundColor: '#00ff88',
    color: '#000',
    border: 'none',
    borderRadius: '4px',
    fontWeight: 'bold',
    cursor: 'pointer',
    fontSize: '1rem'
  }
};

export default Dashboard;