import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';

function EyeIcon({ open }) {
  return open ? (
    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.477 0 8.268 2.943 9.542 7-1.274 4.057-5.065 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
    </svg>
  ) : (
    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.477 0-8.268-2.943-9.542-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18" />
    </svg>
  );
}

function PasswordField({ id, label, value, onChange, placeholder = "Enter your password", minLength }) {
  const [show, setShow] = useState(false);
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-gray-700 mb-3">{label}</label>
      <div className="relative">
        <input
          id={id}
          type={show ? "text" : "password"}
          value={value}
          onChange={onChange}
          className="w-full px-4 py-3 pr-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-gray-50"
          placeholder={placeholder}
          required
          minLength={minLength}
        />
        <button
          type="button"
          onClick={() => setShow(p => !p)}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
          tabIndex={-1}
          aria-label={show ? "Hide password" : "Show password"}
        >
          <EyeIcon open={show} />
        </button>
      </div>
    </div>
  );
}

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    setStatus('');

    if (password !== confirmPassword) {
      setStatus('Passwords do not match.');
      return;
    }
    if (password.length < 6) {
      setStatus('Password must be at least 6 characters.');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();
      if (response.ok) {
        setStatus('Registration successful! Please log in.');
        setTimeout(() => navigate('/login'), 1500);
      } else {
        setStatus(data.error || 'Registration failed');
      }
    } catch {
      setStatus('Network error');
    } finally {
      setLoading(false);
    }
  };

  const isSuccess = status.toLowerCase().includes('success');

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4"
      style={{ backgroundImage: 'url(/bg.png)', backgroundSize: 'cover', backgroundPosition: 'center' }}
    >
      <div className="max-w-md w-full">
        <div className="text-center mb-2">
          <div className="flex items-center justify-center gap-3 mb-2">
            <img src="/logo.png" alt="CheckMyURL logo" className="h-16 w-16" loading="eager" />
            <h1 className="text-3xl font-bold text-blue-500">CheckMyURL</h1>
          </div>
          <p className="text-gray-600 text-sm">Create your account</p>
        </div>

        <div className="bg-white rounded-2xl shadow-lg border border-gray-200 p-8">
          <form onSubmit={handleRegister} className="space-y-6">
            {/* Email */}
            <div>
              <label htmlFor="reg-email" className="block text-sm font-medium text-gray-700 mb-3">Email</label>
              <input
                id="reg-email" type="email" value={email}
                onChange={e => setEmail(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 bg-gray-50"
                placeholder="Enter your email" required
              />
            </div>

            {/* Password */}
            <PasswordField
              id="reg-password" label="Password"
              value={password} onChange={e => setPassword(e.target.value)}
              placeholder="Create a password" minLength={6}
            />

            {/* Confirm Password */}
            <PasswordField
              id="reg-confirm" label="Confirm Password"
              value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)}
              placeholder="Re-enter your password" minLength={6}
            />

            {/* Status */}
            {status && (
              <div className={`p-3 border rounded-lg ${isSuccess ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}`}>
                <p className={`text-sm text-center ${isSuccess ? 'text-green-700' : 'text-red-600'}`}>{status}</p>
              </div>
            )}

            <button type="submit" disabled={loading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors disabled:opacity-50 shadow-md">
              {loading ? 'REGISTERING...' : 'REGISTER'}
            </button>
          </form>
        </div>

        <div className="text-center mt-8">
          <p className="text-sm text-gray-600 mb-2">Students of IBM @ 2025</p>
          <div className="mt-4 text-sm">
            Already have an account?{' '}
            <Link to="/login" className="text-blue-600 underline">Login here</Link>
          </div>
        </div>
      </div>
    </div>
  );
}
