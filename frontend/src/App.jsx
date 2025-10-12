import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ScanProvider } from './context/ScanContext';
import Navbar from './components/Navbar';
import Scanner from './pages/Scanner';
import Statistics from './pages/Statistics';
import Login from './pages/Login';

function App() {
  const isAuthenticated = localStorage.getItem('isAuthenticated') === 'true';
  
  console.log('App - Authentication status:', isAuthenticated);

  return (
    <ThemeProvider>
      <ScanProvider>
        <Router>
          <div className="min-h-screen bg-white dark:bg-gray-900 transition-colors duration-200">
            {isAuthenticated && <Navbar />}
            <Routes>
              <Route path="/login" element={isAuthenticated ? <Scanner /> : <Login />} />
              <Route path="/" element={isAuthenticated ? <Scanner /> : <Login />} />
              <Route path="/statistics" element={isAuthenticated ? <Statistics /> : <Login />} />
            </Routes>
          </div>
        </Router>
      </ScanProvider>
    </ThemeProvider>
  );
}

export default App;