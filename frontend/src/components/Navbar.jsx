import { Link, useLocation } from 'react-router-dom';
import { Moon, Sun, Search, BarChart3, FileText, Settings } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { useScan } from '../context/ScanContext';

function Navbar() {
  const { theme, toggleTheme } = useTheme();
  const { hasScanned } = useScan();
  const location = useLocation();

  const navItems = [
    { path: '/', label: 'Scanner', icon: Search },
    { path: '/statistics', label: 'Statistics', icon: BarChart3 },
    { path: '/results', label: 'Results', icon: FileText },
    { path: '/settings', label: 'Settings', icon: Settings },
  ];

  const isActive = (path) => location.pathname === path;

  if (!hasScanned && location.pathname === '/') {
    return (
      <div className="fixed top-6 right-6 z-50">
        <button
          onClick={toggleTheme}
          className="p-3 rounded-lg bg-white/80 dark:bg-gray-900/80 backdrop-blur-md text-gray-700 dark:text-[#00d4ff] hover:bg-white dark:hover:bg-gray-800 transition-colors border border-gray-300 dark:border-[#00d4ff]/30 shadow-lg"
          aria-label="Toggle theme"
        >
          {theme === 'light' ? <Moon size={20} /> : <Sun size={20} />}
        </button>
      </div>
    );
  }

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-white/80 dark:bg-black/80 backdrop-blur-md border-b border-gray-200 dark:border-[#00d4ff]/30 transition-colors">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          <Link to="/" className="flex items-center gap-2">
            <Search className="text-blue-600 dark:text-[#00d4ff]" size={28} />
            <span className="text-xl font-bold text-gray-900 dark:text-white">
              URL<span className="text-blue-600 dark:text-[#00d4ff]">Scanner</span>
            </span>
          </Link>

          <div className="flex items-center gap-8">
            <div className="hidden md:flex items-center gap-6">
              {navItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-2 text-sm font-medium transition-colors ${
                    isActive(item.path)
                      ? 'text-blue-600 dark:text-[#00d4ff]'
                      : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                  }`}
                >
                  <item.icon size={18} />
                  {item.label}
                </Link>
              ))}
            </div>

            <button
              onClick={toggleTheme}
              className="p-2 rounded-lg bg-gray-100 dark:bg-gray-900 text-gray-700 dark:text-[#00d4ff] hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors border border-gray-300 dark:border-[#00d4ff]/30"
              aria-label="Toggle theme"
            >
              {theme === 'light' ? <Moon size={20} /> : <Sun size={20} />}
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
export default Navbar;