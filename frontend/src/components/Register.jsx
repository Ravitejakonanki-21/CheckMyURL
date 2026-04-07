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
      <label htmlFor={id} className="block text-sm font-medium text-[var(--text-primary)] mb-3">{label}</label>
      <div className="relative">
        <input
          id={id}
          type={show ? "text" : "password"}
          value={value}
          onChange={onChange}
          className="w-full px-4 py-3 pr-12 border border-gray-300 dark:border-[#333] rounded-lg focus:ring-2 focus:ring-[#00e5ff] focus:border-[#00e5ff] bg-gray-50 dark:bg-[#0e0e0e] text-[var(--text-primary)]"
          placeholder={placeholder}
          required
          minLength={minLength}
        />
        <button
          type="button"
          onClick={(e) => { e.preventDefault(); e.stopPropagation(); setShow(p => !p); }}
          className="absolute right-3 top-1/2 -translate-y-1/2 z-10 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 cursor-pointer"
          tabIndex={-1}
          aria-label={show ? "Hide password" : "Show password"}
          style={{ pointerEvents: 'auto' }}
        >
          <EyeIcon open={show} />
        </button>
      </div>
    </div>
  );
}

// Step indicator component
function StepIndicator({ currentStep }) {
  const steps = [
    { num: 1, label: 'Email' },
    { num: 2, label: 'Verify OTP' },
    { num: 3, label: 'Password' },
  ];
  return (
    <div className="flex items-center justify-center gap-2 mb-6">
      {steps.map((step, i) => (
        <React.Fragment key={step.num}>
          <div className="flex flex-col items-center">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all duration-300 ${
              currentStep === step.num
                ? 'bg-[#00e5ff] text-[#0e0e0e] shadow-lg shadow-[#00e5ff]/30'
                : currentStep > step.num
                  ? 'bg-green-500 text-white'
                  : 'bg-gray-200 dark:bg-[#333] text-gray-500 dark:text-gray-400'
            }`}>
              {currentStep > step.num ? (
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                </svg>
              ) : step.num}
            </div>
            <span className={`text-[10px] mt-1 font-medium ${
              currentStep >= step.num ? 'text-[#00e5ff]' : 'text-gray-400'
            }`}>{step.label}</span>
          </div>
          {i < steps.length - 1 && (
            <div className={`flex-1 h-0.5 mb-4 rounded transition-all duration-300 ${
              currentStep > step.num ? 'bg-green-500' : 'bg-gray-200 dark:bg-[#333]'
            }`} style={{ minWidth: '40px', maxWidth: '80px' }} />
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

export default function Register() {
  const [step, setStep] = useState(1); // 1: Email, 2: OTP, 3: Password
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [verificationToken, setVerificationToken] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [status, setStatus] = useState('');
  const [isSuccess, setIsSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // Step 1: Send OTP
  const handleSendOTP = async (e) => {
    e.preventDefault();
    setStatus(''); setIsSuccess(false); setLoading(true);
    try {
      const response = await fetch('/api/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      if (response.ok) {
        setIsSuccess(true);
        setStatus(data.message || 'OTP sent to your email!');
        setStep(2);
      } else {
        setIsSuccess(false);
        setStatus(data.error || 'Failed to send OTP.');
      }
    } catch {
      setStatus('Network error — make sure the server is running.');
    } finally {
      setLoading(false);
    }
  };

  // Step 2: Verify OTP
  const handleVerifyOTP = async (e) => {
    e.preventDefault();
    setStatus(''); setIsSuccess(false); setLoading(true);
    try {
      const response = await fetch('/api/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp }),
      });
      const data = await response.json();
      if (response.ok) {
        setIsSuccess(true);
        setStatus(data.message || 'OTP verified!');
        setVerificationToken(data.verification_token);
        setStep(3);
      } else {
        setIsSuccess(false);
        setStatus(data.error || 'Invalid OTP.');
      }
    } catch {
      setStatus('Network error — make sure the server is running.');
    } finally {
      setLoading(false);
    }
  };

  // Step 3: Complete Registration
  const handleRegister = async (e) => {
    e.preventDefault();
    setStatus(''); setIsSuccess(false);

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
      const response = await fetch('/api/register-with-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verification_token: verificationToken, password }),
      });
      const data = await response.json();
      if (response.ok) {
        setIsSuccess(true);
        setStatus('Registration successful! Redirecting to login...');
        setTimeout(() => navigate('/login'), 2000);
      } else {
        setIsSuccess(false);
        setStatus(data.error || 'Registration failed.');
      }
    } catch {
      setStatus('Network error.');
    } finally {
      setLoading(false);
    }
  };

  // Resend OTP
  const handleResendOTP = async () => {
    setStatus(''); setIsSuccess(false); setLoading(true);
    try {
      const response = await fetch('/api/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      if (response.ok) {
        setIsSuccess(true);
        setStatus('New OTP sent to your email!');
      } else {
        setIsSuccess(false);
        setStatus(data.error || 'Failed to resend OTP.');
      }
    } catch {
      setStatus('Network error.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] flex items-center justify-center px-4 transition-colors duration-300">
      <div className="max-w-md w-full">
        <div className="text-center mb-2">
          <div className="flex items-center justify-center gap-2 sm:gap-3 mb-2">
            <img src="/logo.png" alt="CheckMyURL logo" className="h-12 w-12 sm:h-16 sm:w-16" loading="eager" />
            <h1 className="text-2xl sm:text-3xl font-bold text-[#00e5ff]">CYBERSHIELD</h1>
          </div>
          <p className="text-[var(--text-secondary)] text-sm">Create your account</p>
        </div>

        <div className="bg-white dark:bg-[#181818] rounded-2xl shadow-lg border border-gray-200 dark:border-[#333] p-8">
          <StepIndicator currentStep={step} />

          {/* Step 1: Enter Email */}
          {step === 1 && (
            <form onSubmit={handleSendOTP} className="space-y-6">
              <div>
                <label htmlFor="reg-email" className="block text-sm font-medium text-[var(--text-primary)] mb-3">Email</label>
                <input
                  id="reg-email" type="email" value={email}
                  onChange={e => setEmail(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 dark:border-[#333] rounded-lg focus:ring-2 focus:ring-[#00e5ff] bg-gray-50 dark:bg-[#0e0e0e] text-[var(--text-primary)]"
                  placeholder="Enter your email" required autoFocus
                />
              </div>

              {status && (
                <div className={`p-3 border rounded-lg ${isSuccess ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800' : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'}`}>
                  <p className={`text-sm text-center ${isSuccess ? 'text-green-700 dark:text-green-300' : 'text-red-600 dark:text-red-400'}`}>{status}</p>
                </div>
              )}

              <button type="submit" disabled={loading}
                className="w-full py-3 bg-[#00e5ff] hover:bg-[#00ccf0] text-[#0e0e0e] font-semibold rounded-lg transition-colors disabled:opacity-50 shadow-md">
                {loading ? 'SENDING OTP...' : 'SEND OTP'}
              </button>
            </form>
          )}

          {/* Step 2: Verify OTP */}
          {step === 2 && (
            <form onSubmit={handleVerifyOTP} className="space-y-6">
              <div className="text-center mb-2">
                <p className="text-sm text-[var(--text-secondary)]">
                  OTP sent to <span className="font-semibold text-[#00e5ff]">{email}</span>
                </p>
              </div>

              <div>
                <label htmlFor="reg-otp" className="block text-sm font-medium text-[var(--text-primary)] mb-3">Enter OTP</label>
                <input
                  id="reg-otp" type="text" value={otp}
                  onChange={e => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full px-4 py-4 border border-gray-300 dark:border-[#333] rounded-lg focus:ring-2 focus:ring-[#00e5ff] bg-gray-50 dark:bg-[#0e0e0e] text-[var(--text-primary)] text-center text-2xl font-bold tracking-[0.5em]"
                  placeholder="••••••" required maxLength={6} autoFocus
                />
              </div>

              {status && (
                <div className={`p-3 border rounded-lg ${isSuccess ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800' : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'}`}>
                  <p className={`text-sm text-center ${isSuccess ? 'text-green-700 dark:text-green-300' : 'text-red-600 dark:text-red-400'}`}>{status}</p>
                </div>
              )}

              <button type="submit" disabled={loading || otp.length < 6}
                className="w-full py-3 bg-[#00e5ff] hover:bg-[#00ccf0] text-[#0e0e0e] font-semibold rounded-lg transition-colors disabled:opacity-50 shadow-md">
                {loading ? 'VERIFYING...' : 'VERIFY OTP'}
              </button>

              <div className="flex items-center justify-between text-sm">
                <button type="button" onClick={() => { setStep(1); setStatus(''); setOtp(''); }}
                  className="text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
                  ← Change email
                </button>
                <button type="button" onClick={handleResendOTP} disabled={loading}
                  className="text-[#00e5ff] hover:text-[#00ccf0] font-medium disabled:opacity-50">
                  Resend OTP
                </button>
              </div>
            </form>
          )}

          {/* Step 3: Set Password */}
          {step === 3 && (
            <form onSubmit={handleRegister} className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center gap-2 px-3 py-1 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-full">
                  <svg className="w-4 h-4 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  <span className="text-xs font-medium text-green-700 dark:text-green-300">Email verified: {email}</span>
                </div>
              </div>

              <PasswordField
                id="reg-password" label="Password"
                value={password} onChange={e => setPassword(e.target.value)}
                placeholder="Create a password" minLength={6}
              />

              <PasswordField
                id="reg-confirm" label="Confirm Password"
                value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)}
                placeholder="Re-enter your password" minLength={6}
              />

              {status && (
                <div className={`p-3 border rounded-lg ${isSuccess ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800' : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'}`}>
                  <p className={`text-sm text-center ${isSuccess ? 'text-green-700 dark:text-green-300' : 'text-red-600 dark:text-red-400'}`}>{status}</p>
                </div>
              )}

              <button type="submit" disabled={loading}
                className="w-full py-3 bg-[#00e5ff] hover:bg-[#00ccf0] text-[#0e0e0e] font-semibold rounded-lg transition-colors disabled:opacity-50 shadow-md">
                {loading ? 'REGISTERING...' : 'COMPLETE REGISTRATION'}
              </button>
            </form>
          )}
        </div>

        <div className="text-center mt-8">
          <p className="text-sm text-[var(--text-secondary)] mb-2">Students of IBM @ 2025</p>
          <div className="mt-4 text-sm">
            Already have an account?{' '}
            <Link to="/login" className="text-[#00e5ff] underline">Login here</Link>
          </div>
        </div>
      </div>
    </div>
  );
}
