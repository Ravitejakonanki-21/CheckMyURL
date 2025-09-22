import React from 'react';

const Layout = ({ children }) => {
  return (
    <div style={styles.layout}>
      <header style={styles.header}>
        <h1 style={styles.title}>THREATSCAN AI</h1>
        <nav style={styles.nav}>
          <a href="/" style={styles.navLink}>Dashboard</a>
          <a href="/scan" style={styles.navLink}>New Scan</a>
        </nav>
      </header>
      <main style={styles.main}>
        {children}
      </main>
    </div>
  );
};

const styles = {
  layout: {
    minHeight: '100vh',
    backgroundColor: '#0a0a0a',
    color: '#ffffff',
    fontFamily: 'Arial, sans-serif'
  },
  header: {
    background: 'linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%)',
    padding: '1rem 2rem',
    borderBottom: '2px solid #00ff88',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  title: {
    margin: 0,
    color: '#00ff88',
    fontSize: '2rem',
    fontWeight: 'bold'
  },
  nav: {
    display: 'flex',
    gap: '2rem'
  },
  navLink: {
    color: '#ffffff',
    textDecoration: 'none',
    padding: '0.5rem 1rem',
    borderRadius: '4px',
    transition: 'background-color 0.3s',
    fontWeight: '500'
  },
  main: {
    padding: '2rem',
    maxWidth: '1200px',
    margin: '0 auto'
  }
};

export default Layout;