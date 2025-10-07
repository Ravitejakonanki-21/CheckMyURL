import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ScanProvider } from './context/ScanContext';
import Navbar from './components/Navbar';
import Scanner from './pages/Scanner';
import Statistics from './pages/Statistics';
import Results from './pages/Results';
import Settings from './pages/Settings';

function App() {
  return (
    <ThemeProvider>
      <ScanProvider>
        <Router>
          <div className="min-h-screen bg-white dark:bg-black transition-colors">
            <Navbar />
            <Routes>
              <Route path="/" element={<Scanner />} />
              <Route path="/statistics" element={<Statistics />} />
              <Route path="/results" element={<Results />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </div>
        </Router>
      </ScanProvider>
    </ThemeProvider>
  );
}

export default App;