import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ScanProvider } from './context/ScanContext';
import Navbar from './components/Navbar';
import ProtectedRoutes from './components/ProtectedRoutes';
import Scanner from './pages/Scanner';
import Statistics from './pages/Statistics';
import History from './pages/History';
import BulkScan from './pages/BulkScan';
import SOCDashboard from './pages/SOCDashboard';
import AdminPanel from './pages/AdminPanel';
import Login from './components/Login';
import Register from './components/Register';
import ForgotPassword from './components/ForgotPassword';
import ResetPassword from './components/ResetPassword';

function App() {
  const isAuthenticated = localStorage.getItem('isAuthenticated') === 'true';

  return (
    <ThemeProvider>
      <ScanProvider>
        <Router>
          <div className="min-h-screen bg-white dark:bg-gray-900 transition-colors duration-200">
            {isAuthenticated && <Navbar />}
            <Routes>
              {/* Public routes — redirect to scanner if already logged in */}
              <Route
                path="/"
                element={isAuthenticated ? <Navigate to="/scanner" /> : <Navigate to="/login" />}
              />
              <Route
                path="/login"
                element={isAuthenticated ? <Navigate to="/scanner" /> : <Login />}
              />
              <Route
                path="/register"
                element={isAuthenticated ? <Navigate to="/scanner" /> : <Register />}
              />
              <Route
                path="/forgot-password"
                element={isAuthenticated ? <Navigate to="/scanner" /> : <ForgotPassword />}
              />
              <Route
                path="/reset-password/:token"
                element={isAuthenticated ? <Navigate to="/scanner" /> : <ResetPassword />}
              />

              {/* Protected routes — ProtectedRoutes guards with real JWT check */}
              <Route element={<ProtectedRoutes />}>
                <Route path="/scanner" element={<Scanner />} />
                <Route path="/statistics" element={<Statistics />} />
                <Route path="/history" element={<History />} />
                <Route path="/bulk-scan" element={<BulkScan />} />
                <Route path="/soc" element={<SOCDashboard />} />
                <Route path="/admin" element={<AdminPanel />} />
              </Route>
            </Routes>
          </div>
        </Router>
      </ScanProvider>
    </ThemeProvider>
  );
}

export default App;
