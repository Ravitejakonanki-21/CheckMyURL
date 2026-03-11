import { Navigate, Outlet } from 'react-router-dom';

/**
 * ProtectedRoutes — wraps routes that require authentication.
 * Reads the JWT token AND isAuthenticated flag from localStorage.
 * If absent, redirects to /login.
 *
 * Usage in App.jsx:
 *   <Route element={<ProtectedRoutes />}>
 *     <Route path="/scanner" element={<Scanner />} />
 *     <Route path="/statistics" element={<Statistics />} />
 *   </Route>
 */
export default function ProtectedRoutes() {
  const token = localStorage.getItem('token');
  const isAuthenticated = localStorage.getItem('isAuthenticated') === 'true';
  return token && isAuthenticated ? <Outlet /> : <Navigate to="/login" replace />;
}