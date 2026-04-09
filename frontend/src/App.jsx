import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ScanProvider, useScan } from './context/ScanContext';
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
          <InnerApp isAuthenticated={isAuthenticated} />
        </Router>
      </ScanProvider>
    </ThemeProvider>
  );
}

function InnerApp({ isAuthenticated }) {
  const { isShowingResults } = useScan();
  
  return (
    <div className="min-h-screen flex flex-col bg-[var(--bg-primary)] transition-colors duration-200">
      {!isShowingResults && <Navbar />}
      <main className="flex-1 flex flex-col">
        <Routes>
              {/* Public routes */}
              <Route path="/scanner" element={<Scanner />} />
              <Route
                path="/"
                element={<Navigate to="/scanner" replace />}
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

              {/* Protected routes — User level */}
              <Route element={<ProtectedRoutes allowedRoles={['USER', 'ADMIN']} />}>
                <Route path="/statistics" element={<Statistics />} />
                <Route path="/history" element={<History />} />
                <Route path="/bulk-scan" element={<BulkScan />} />
              </Route>

              {/* Protected routes — Analyst/Admin level */}
              <Route element={<ProtectedRoutes allowedRoles={['ADMIN']} />}>
                <Route path="/soc" element={<SOCDashboard />} />
              </Route>

              {/* Protected routes — Admin only */}
              <Route element={<ProtectedRoutes allowedRoles={['ADMIN']} />}>
                <Route path="/admin" element={<AdminPanel />} />
              </Route>
      </Routes>
      </main>
    </div>
  );
}

export default App;
