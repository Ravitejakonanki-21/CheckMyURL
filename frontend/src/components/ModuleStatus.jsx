import React from 'react';

const ModuleStatus = () => {
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>Module Status</h3>
      <div style={styles.module}>
        <div style={styles.moduleHeader}>
          <span style={styles.moduleName}>SSL/HTTPS</span>
          <span style={styles.statusPassed}>Passed</span>
        </div>
        <div style={styles.moduleDetails}>
          <div style={styles.detailItem}>
            <span style={styles.statusPassed}>✓ Passed:</span>
            <span>Valid until 2025</span>
          </div>
          <div style={styles.detailItem}>
            <span style={styles.statusPassed}>✓ Password:</span>
            <span>Open 80, 443, 22</span>
          </div>
        </div>
      </div>
    </div>
  );
};

const styles = {
  card: {
    background: '#1a1a1a',
    padding: '1.5rem',
    borderRadius: '8px',
    border: '1px solid #333'
  },
  cardTitle: {
    margin: '0 0 1rem 0',
    color: '#00ff88',
    fontSize: '1.25rem',
    borderBottom: '1px solid #333',
    paddingBottom: '0.5rem'
  },
  module: {
    background: '#2d2d2d',
    padding: '1rem',
    borderRadius: '4px'
  },
  moduleHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '0.5rem'
  },
  moduleName: {
    fontWeight: 'bold',
    color: '#fff'
  },
  statusPassed: {
    color: '#00ff88',
    fontWeight: 'bold'
  },
  moduleDetails: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem'
  },
  detailItem: {
    display: 'flex',
    gap: '0.5rem',
    alignItems: 'center',
    fontSize: '0.9rem',
    color: '#ccc'
  }
};

export default ModuleStatus;