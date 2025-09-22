import React from 'react';

const ScanPage = () => {
  return (
    <div style={styles.container}>
      <h2 style={styles.title}>New Security Scan</h2>
      <div style={styles.form}>
        <div style={styles.inputGroup}>
          <label style={styles.label}>Website URL:</label>
          <input 
            type="text" 
            placeholder="https://example.com" 
            style={styles.input}
          />
        </div>
        <div style={styles.inputGroup}>
          <label style={styles.label}>Scan Type:</label>
          <select style={styles.select}>
            <option>Full Security Scan</option>
            <option>SSL/TLS Scan</option>
            <option>Headers Analysis</option>
            <option>Vulnerability Scan</option>
          </select>
        </div>
        <button style={styles.scanButton}>Start Security Scan</button>
      </div>
    </div>
  );
};

const styles = {
  container: {
    background: '#1a1a1a',
    padding: '2rem',
    borderRadius: '8px',
    border: '1px solid #333'
  },
  title: {
    color: '#00ff88',
    marginBottom: '2rem',
    fontSize: '1.5rem'
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.5rem',
    maxWidth: '500px'
  },
  inputGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem'
  },
  label: {
    color: '#00ff88',
    fontWeight: 'bold'
  },
  input: {
    padding: '0.75rem',
    backgroundColor: '#2d2d2d',
    border: '1px solid #444',
    borderRadius: '4px',
    color: '#fff',
    fontSize: '1rem'
  },
  select: {
    padding: '0.75rem',
    backgroundColor: '#2d2d2d',
    border: '1px solid #444',
    borderRadius: '4px',
    color: '#fff',
    fontSize: '1rem'
  },
  scanButton: {
    padding: '1rem 2rem',
    backgroundColor: '#00ff88',
    color: '#000',
    border: 'none',
    borderRadius: '4px',
    fontWeight: 'bold',
    cursor: 'pointer',
    fontSize: '1rem',
    marginTop: '1rem'
  }
};

export default ScanPage;