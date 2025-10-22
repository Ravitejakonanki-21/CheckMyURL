import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ScanProvider } from './context/ScanContext';
import Navbar from './components/Navbar';
import Scanner from './pages/Scanner';
import Statistics from './pages/Statistics';
import Login from './components/Login';
import Register from './components/Register';
import ForgotPassword from './components/ForgotPassword'; // <-- Added import
import ResetPassword from './components/ResetPassword';  // <-- Added import

function App() {
  const isAuthenticated = localStorage.getItem('isAuthenticated') === 'true';

  // Always show Navbar only if authenticated
  return (
    <ThemeProvider>
      <ScanProvider>
        <Router>
          <div className="min-h-screen bg-white dark:bg-gray-900 transition-colors duration-200">
            {isAuthenticated && <Navbar />}
            <Routes>
              {/* Always redirect / (home) to /login if not authenticated */}
              <Route path="/" element={
                isAuthenticated ? <Navigate to="/scanner" /> : <Navigate to="/login" />
              } />
              <Route path="/login" element={
                isAuthenticated ? <Navigate to="/scanner" /> : <Login />
              } />
              <Route path="/register" element={
                isAuthenticated ? <Navigate to="/scanner" /> : <Register />
              } />
              <Route path="/forgot-password" element={  // <-- Added route
                isAuthenticated ? <Navigate to="/scanner" /> : <ForgotPassword />
              } />
              <Route path="/reset-password/:token" element={  // <-- Added route
                isAuthenticated ? <Navigate to="/scanner" /> : <ResetPassword />
              } />
              <Route path="/scanner" element={
                isAuthenticated ? <Scanner /> : <Navigate to="/login" />
              } />
              <Route path="/statistics" element={
                isAuthenticated ? <Statistics /> : <Navigate to="/login" />
              } />
              {/* Add more protected routes as needed */}
            </Routes>
          </div>
        </Router>
      </ScanProvider>
    </ThemeProvider>
  );
}

export default App;
