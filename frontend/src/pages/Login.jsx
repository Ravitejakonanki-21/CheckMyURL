import { useState } from 'react';

function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [isFirstTimeLogin, setIsFirstTimeLogin] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    if (!email || !password) {
      setError('Please fill in all fields');
      setLoading(false);
      return;
    }

    try {
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Login logic
      if ((email === 'demo@gmail.com') && password === 'test') {
        localStorage.setItem('isAuthenticated', 'true');
        localStorage.setItem('user', email);
        if (rememberMe) {
          localStorage.setItem('rememberMe', 'true');
        }
        console.log('Login successful, redirecting...');
        // Force page reload to update authentication state
        window.location.href = '/';
      } else {
        setError('Invalid email or password. Use: demo@gmail.com / test');
      }
    } catch (err) {
      setError('An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = () => {
    alert('Forgot password functionality would be implemented here. Please contact administrator.');
  };

  const handleFirstTimeLogin = () => {
    setIsFirstTimeLogin(true);
  };

  const handleForgotOrFirstTime = () => {
    const isFirstTime = window.confirm('Are you a first time user? Click OK for first time login, Cancel for forgot password.');
    if (isFirstTime) {
      handleFirstTimeLogin();
    } else {
      handleForgotPassword();
    }
  };

  // First Time Login / Registration Form
  if (isFirstTimeLogin) {
    return <FirstTimeRegistration onBack={() => setIsFirstTimeLogin(false)} />;
  }

  return (
    <div 
      className="min-h-screen flex items-center justify-center px-4"
      style={{
        backgroundImage: 'url(/bg.jpg)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat'
      }}
    >
      <div className="max-w-md w-full">
        {/* Logo and Welcome Section - Properly centered and aligned */}
        <div className="text-center mb-2">
          <div className="flex items-center justify-center gap-3 mb-2">
            <img
              src="/logo.png"
              alt="CheckMyURL logo"
              className="h-16 w-16"
              loading="eager"
            />
            <h1 className="text-3xl font-bold text-blue-500">
              CheckMyURL
            </h1>
          </div>
          <p className="text-gray-600 text-sm">
            Sign in to your account
          </p>
        </div>

        {/* Login Form */}
        <div className="bg-white rounded-2xl shadow-lg border border-gray-200 p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Email Input */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-3">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-gray-50"
                placeholder="deanacademics@admin.com"
                required
              />
            </div>

            {/* Password Input */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-3">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-gray-50"
                placeholder="Enter your password"
                required
              />
            </div>

            {/* Remember Me & Forgot Password */}
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="rememberMe"
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <label htmlFor="rememberMe" className="ml-2 block text-sm text-gray-700">
                  Remember me
                </label>
              </div>
              <button
                type="button"
                onClick={handleForgotOrFirstTime}
                className="text-sm text-blue-600 hover:text-blue-800 font-medium"
              >
                First Time Login/Forgot password?
              </button>
            </div>

            {/* Error Message */}
            {error && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-red-600 text-sm text-center">{error}</p>
              </div>
            )}

            {/* Sign In Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-md"
            >
              {loading ? 'SIGNING IN...' : 'SIGN IN'}
            </button>
          </form>
        </div>

        {/* Footer */}
        <div className="text-center mt-8">
          <p className="text-sm text-gray-600 mb-2">
            Students of IBM @ 2025
          </p>
        </div>
      </div>
    </div>
  );
}

// First Time Registration Component
function FirstTimeRegistration({ onBack }) {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [otpSent, setOtpSent] = useState(false);

  const handleSendOtp = async (e) => {
    e.preventDefault();
    setError('');

    if (!email) {
      setError('Please enter your email address');
      return;
    }

    setLoading(true);
    try {
      // Simulate OTP sending
      await new Promise(resolve => setTimeout(resolve, 1500));
      setOtpSent(true);
      setError('OTP has been sent to your email address');
    } catch (err) {
      setError('Failed to send OTP. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!email || !otp || !newPassword || !confirmPassword) {
      setError('Please fill in all fields');
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (newPassword.length < 6) {
      setError('Password must be at least 6 characters long');
      return;
    }

    setLoading(true);
    try {
      // Simulate registration process
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Registration successful
      localStorage.setItem('isAuthenticated', 'true');
      localStorage.setItem('user', email);
      alert('Registration successful! You can now login with your new credentials.');
      window.location.href = '/';
    } catch (err) {
      setError('Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div 
      className="min-h-screen flex items-center justify-center px-4"
      style={{
        backgroundImage: 'url(/bg.png)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat'
      }}
    >
      <div className="max-w-md w-full">
        {/* Logo and Title - Properly centered and aligned */}
        <div className="text-center mb-2">
          <div className="flex items-center justify-center gap-3 mb-2">
            <img
              src="/logo.png"
              alt="CheckMyURL logo"
              className="h-16 w-16"
              loading="eager"
            />
            <h1 className="text-3xl font-bold text-gray-800">
              First Time Registration
            </h1>
          </div>
          <p className="text-gray-600 mb-6">Create your account</p>
        </div>

        {/* Registration Form */}
        <div className="bg-white rounded-2xl shadow-lg border border-gray-200 p-8">
          <button
            onClick={onBack}
            className="mb-4 text-blue-600 hover:text-blue-800 font-medium flex items-center gap-2"
          >
            ← Back to Login
          </button>

          <form onSubmit={otpSent ? handleSubmit : handleSendOtp} className="space-y-6">
            {/* Email Input */}
            <div>
              <label htmlFor="regEmail" className="block text-sm font-medium text-gray-700 mb-3">
                Email Address
              </label>
              <input
                id="regEmail"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-gray-50"
                placeholder="Enter your email address"
                required
                disabled={otpSent}
              />
            </div>

            {/* OTP Input (only show after email is sent) */}
            {otpSent && (
              <div>
                <label htmlFor="otp" className="block text-sm font-medium text-gray-700 mb-3">
                  OTP (Sent to your email)
                </label>
                <input
                  id="otp"
                  type="text"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-gray-50"
                  placeholder="Enter OTP"
                  required
                  maxLength="6"
                />
              </div>
            )}

            {/* New Password Input (only show after OTP is sent) */}
            {otpSent && (
              <div>
                <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700 mb-3">
                  New Password
                </label>
                <input
                  id="newPassword"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-gray-50"
                  placeholder="Enter new password"
                  required
                />
              </div>
            )}

            {/* Confirm Password Input (only show after OTP is sent) */}
            {otpSent && (
              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-3">
                  Confirm Password
                </label>
                <input
                  id="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-gray-50"
                  placeholder="Confirm your password"
                  required
                />
              </div>
            )}

            {/* Error Message */}
            {error && (
              <div className={`p-3 rounded-lg ${
                error.includes('OTP has been sent') 
                  ? 'bg-green-50 border border-green-200 text-green-600'
                  : 'bg-red-50 border border-red-200 text-red-600'
              }`}>
                <p className="text-sm text-center">{error}</p>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-md"
            >
              {loading 
                ? 'PLEASE WAIT...' 
                : otpSent 
                  ? 'COMPLETE REGISTRATION' 
                  : 'SEND OTP'
              }
            </button>
          </form>
        </div>

        {/* Footer */}
        <div className="text-center mt-8">
          <p className="text-sm text-gray-600 mb-2">
            Student of IBM @ 2025
          </p>
        </div>
      </div>
    </div>
  );
}

export default Login;