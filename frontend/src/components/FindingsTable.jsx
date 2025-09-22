import React from 'react';

const FindingsTable = () => {
  const findings = [
    {
      severity: 'High',
      key: 'Strict-Transport-Security',
      whois: '',
      headers: '',
      keywords: 'Implement HTS header for secure connections.',
      phishingML: '',
      recommendation: ''
    },
    {
      severity: 'Medium',
      key: 'Content-Security-Policy',
      whois: '',
      headers: '',
      keywords: 'Add CSP to mitigate XSS.',
      phishingML: 'Not present',
      recommendation: ''
    },
    {
      severity: 'Low',
      key: 'X-Frame-Options',
      whois: '',
      headers: '',
      keywords: 'SAMEORIGIN',
      phishingML: 'Good',
      recommendation: ''
    }
  ];

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'High': return '#ff4444';
      case 'Medium': return '#ffaa00';
      case 'Low': return '#00ff88';
      default: return '#ccc';
    }
  };

  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>Details of Findings</h3>
      <div style={styles.tableContainer}>
        <table style={styles.table}>
          <thead>
            <tr style={styles.headerRow}>
              <th style={styles.th}>Severity</th>
              <th style={styles.th}>Key</th>
              <th style={styles.th}>WHOIS</th>
              <th style={styles.th}>Headers</th>
              <th style={styles.th}>Keywords</th>
              <th style={styles.th}>Phishing ML</th>
              <th style={styles.th}>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding, index) => (
              <tr key={index} style={styles.row}>
                <td style={{...styles.td, color: getSeverityColor(finding.severity), fontWeight: 'bold'}}>
                  {finding.severity}
                </td>
                <td style={styles.td}>{finding.key}</td>
                <td style={styles.td}>{finding.whois}</td>
                <td style={styles.td}>{finding.headers}</td>
                <td style={styles.td}>{finding.keywords}</td>
                <td style={styles.td}>{finding.phishingML}</td>
                <td style={styles.td}>{finding.recommendation}</td>
              </tr>
            ))}
          </tbody>
        </table>
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
  tableContainer: {
    overflowX: 'auto'
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    fontSize: '0.9rem'
  },
  headerRow: {
    backgroundColor: '#2d2d2d'
  },
  th: {
    padding: '0.75rem',
    textAlign: 'left',
    border: '1px solid #444',
    color: '#00ff88',
    fontWeight: 'bold'
  },
  row: {
    borderBottom: '1px solid #333'
  },
  td: {
    padding: '0.75rem',
    border: '1px solid #444',
    color: '#ccc'
  }
};

export default FindingsTable;