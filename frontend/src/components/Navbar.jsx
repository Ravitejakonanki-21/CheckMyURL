import { NavLink, useNavigate } from "react-router-dom";
import ThemeToggle from "./ThemeToggle";
import { useState, useRef, useEffect } from "react";

function navClass({ isActive }) {
  return `text-sm font-bold px-4 py-2 rounded-full transition-all duration-300 ${isActive
    ? "text-[#00e5ff]"
    : "text-[#b3b3b3] hover:text-white"
    }`;
}

const Navbar = () => {
  const isAuthenticated = localStorage.getItem("isAuthenticated") === "true";
  const userEmail = localStorage.getItem("userEmail");
  const userRole = (localStorage.getItem("role") ?? "USER").toUpperCase();
  const [menuOpen, setMenuOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const username = userEmail ? userEmail.split("@")[0] : "";
  const isAdmin = userRole === "ADMIN";
  const dropdownRef = useRef(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handler = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("isAuthenticated");
    localStorage.removeItem("userEmail");
    localStorage.removeItem("token");
    localStorage.removeItem("access_token");
    localStorage.removeItem("role");
    setMenuOpen(false);
    setMobileMenuOpen(false);
    window.location.href = "/login";
  };

  return (
    <header className="sticky top-0 z-50 bg-white/80 dark:bg-[#0e0e0e]/80 backdrop-blur-xl border-b border-gray-200 dark:border-[#333]">
      <nav className="mx-auto max-w-7xl px-4 sm:px-6 py-4 flex items-center justify-between">
        {/* Left Side: Hamburger (Mobile) + Logo */}
        <div className="flex items-center gap-2 md:gap-3">
          <button 
            className="md:hidden p-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-[#181818] rounded-lg"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {mobileMenuOpen ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              )}
            </svg>
          </button>
          
          <div className="flex items-center gap-2 md:gap-3">
            <img src="/logo.png" alt="CYBERSHIELD Logo" className="h-8 w-8 md:h-10 md:w-10 object-contain" />
            <span className="text-lg md:text-xl font-black text-gray-900 dark:text-white tracking-tighter uppercase">
              CYBER<span className="text-[#00e5ff]">SHIELD</span>
            </span>
          </div>
        </div>

        {/* Desktop Nav Links (Center) */}
        <div className="hidden md:flex items-center gap-4 lg:gap-6 absolute left-1/2 transform -translate-x-1/2">
          <NavLink to="/scanner" className={navClass}>Explore</NavLink>
          {isAuthenticated && (
            <>
              <NavLink to="/history" className={navClass}>History</NavLink>
              <NavLink to="/statistics" className={navClass}>Statistics</NavLink>
              <NavLink to="/bulk-scan" className={navClass}>Bulk Scan</NavLink>
            </>
          )}
          {isAdmin && (
            <>
              <NavLink to="/soc" className={navClass}>SOC</NavLink>
              <NavLink to="/admin" className={navClass}>Admin</NavLink>
            </>
          )}
        </div>

        {/* Right Side: Theme + Auth */}
        <div className="flex items-center gap-2 md:gap-4">
          <ThemeToggle />

          {!isAuthenticated ? (
            <div className="flex items-center gap-2 md:gap-3">
              <NavLink
                to="/login"
                className="px-4 md:px-6 py-2 text-xs md:text-sm font-bold text-white bg-[#181818] border border-[#333] hover:border-[#444] rounded-full transition-all"
              >
                Sign In
              </NavLink>
              <NavLink
                to="/register"
                className="hidden sm:block px-6 py-2 text-sm font-bold text-[#0e0e0e] bg-[#00e5ff] hover:bg-[#00ccf0] rounded-full shadow-lg shadow-[#00e5ff]/20 transition-all"
              >
                Sign Up
              </NavLink>
            </div>
          ) : (
            /* User Avatar Dropdown (Desktop/Mobile) */
            <div className="relative" ref={dropdownRef}>
              <button
                className="flex items-center gap-2 px-2 md:px-3 py-1.5 bg-[#181818] border border-[#333] rounded-full hover:border-[#00e5ff]/50 transition-all"
                onClick={() => setMenuOpen(prev => !prev)}
              >
                <div className="h-6 w-6 md:h-7 md:w-7 rounded-full bg-[#00e5ff] text-[#0e0e0e] flex items-center justify-center font-bold text-[10px] md:text-sm">
                  {username.charAt(0).toUpperCase()}
                </div>
                <span className="hidden lg:block text-sm font-bold text-white uppercase tracking-tight">{username}</span>
              </button>

              {menuOpen && (
                <div className="absolute right-0 mt-3 w-64 rounded-2xl bg-white dark:bg-[#181818] shadow-2xl border border-gray-200 dark:border-[#333] z-50 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                  <div className="p-5 border-b border-gray-200 dark:border-[#333] bg-gray-50 dark:bg-[#0e0e0e]">
                    <div className="font-black text-gray-900 dark:text-white uppercase tracking-tighter text-sm">Account Info</div>
                    <div className="text-[10px] text-gray-500 dark:text-[#b3b3b3] truncate mt-1">{userEmail}</div>
                    <div className="mt-3 inline-block px-2 py-0.5 rounded bg-[#00e5ff]/10 text-[#00e5ff] text-[9px] font-black uppercase tracking-widest border border-[#00e5ff]/20">
                      {userRole}
                    </div>
                  </div>
                  <div className="p-2">
                    <button
                      onClick={handleLogout}
                      className="w-full flex items-center justify-center gap-2 px-4 py-3 text-xs font-black text-white bg-red-600/10 hover:bg-red-600 text-red-600 hover:text-white transition-all rounded-xl uppercase tracking-widest"
                    >
                      Logout
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </nav>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-gray-200 dark:border-[#333] bg-white dark:bg-[#0e0e0e] animate-in slide-in-from-top-4 duration-300">
          <div className="flex flex-col p-4 space-y-1">
            <NavLink to="/scanner" onClick={() => setMobileMenuOpen(false)} className={navClass}>Explore</NavLink>
            {isAuthenticated && (
              <>
                <NavLink to="/history" onClick={() => setMobileMenuOpen(false)} className={navClass}>History</NavLink>
                <NavLink to="/statistics" onClick={() => setMobileMenuOpen(false)} className={navClass}>Statistics</NavLink>
                <NavLink to="/bulk-scan" onClick={() => setMobileMenuOpen(false)} className={navClass}>Bulk Scan</NavLink>
              </>
            )}
            {isAdmin && (
              <>
                <NavLink to="/soc" onClick={() => setMobileMenuOpen(false)} className={navClass}>SOC Dashboard</NavLink>
                <NavLink to="/admin" onClick={() => setMobileMenuOpen(false)} className={navClass}>Admin Panel</NavLink>
              </>
            )}
            {!isAuthenticated && (
              <NavLink to="/register" onClick={() => setMobileMenuOpen(false)} className={navClass}>Register</NavLink>
            )}
          </div>
        </div>
      )}
    </header>
  );
};

export default Navbar;
