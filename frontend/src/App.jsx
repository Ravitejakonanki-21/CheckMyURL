import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ScanProvider } from './context/ScanContext';
import Navbar from './components/Navbar';
import Scanner from './pages/Scanner';
import Statistics from './pages/Statistics';

function App() {
  return (
    <ThemeProvider>
      <ScanProvider>
        <Router>
          <div className="min-h-screen bg-white dark:bg-gray-900 transition-colors duration-200">
            <Navbar />
            <Routes>
              <Route path="/" element={<Scanner />} />
              <Route path="/statistics" element={<Statistics />} />
            </Routes>
          </div>
        </Router>
      </ScanProvider>
    </ThemeProvider>
  );
}

export default App;