import React from 'react';

const SummaryCard = () => {
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>Summary</h3>
      <div style={styles.content}>
        <div style={styles.scoreSection}>
          <div style={styles.score}>75%</div>
          <div style={styles.scoreLabel}>Security Score</div>
        </div>
        <div style={styles.details}>
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
  content: {
    display: 'flex',
    alignItems: 'center',
    gap: '2rem'
  },
  scoreSection: {
    textAlign: 'center'
  },
  score: {
    fontSize: '3rem',
    fontWeight: 'bold',
    color: '#00ff88',
    lineHeight: 1
  },
  scoreLabel: {
    color: '#ccc',
    fontSize: '0.9rem'
  },
  details: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem'
  },
  detailItem: {
    display: 'flex',
    gap: '0.5rem',
    alignItems: 'center'
  },
  statusPassed: {
    color: '#00ff88',
    fontWeight: 'bold'
  }
};

export default SummaryCard;