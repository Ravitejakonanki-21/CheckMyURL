// src/components/ThemeToggle.jsx
import React, { useContext } from 'react';
import { ThemeContext } from '../context/ThemeContext';

const ThemeToggle = () => {
  const { darkMode, toggleTheme } = useContext(ThemeContext);

  return (
    <button
      onClick={toggleTheme}
      className={`relative inline-flex h-7 w-14 items-center rounded-full transition-all duration-500 focus:outline-none focus:ring-2 focus:ring-offset-2 ${
        darkMode
          ? 'bg-gradient-to-r from-blue-500 to-purple-600 focus:ring-blue-500 focus:ring-offset-gray-900'
          : 'bg-gradient-to-r from-blue-400 to-blue-500 focus:ring-blue-500 focus:ring-offset-white'
      } shadow-lg`}
      aria-label="Toggle theme"
    >
      {/* Track */}
      <span className="sr-only">Toggle theme</span>
      
      {/* Thumb */}
      <span
        className={`inline-flex h-5 w-5 transform items-center justify-center rounded-full bg-white shadow-lg transition-all duration-500 ${
          darkMode ? 'translate-x-8' : 'translate-x-1'
        }`}
      >
        {/* Icons that fade in/out */}
        <svg
          className={`h-3 w-3 transition-all duration-500 ${
            darkMode
              ? 'text-yellow-300 opacity-100 rotate-180'
              : 'text-gray-700 opacity-0 rotate-0'
          }`}
          fill="currentColor"
          viewBox="0 0 20 20"
        >
          <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
        </svg>
        <svg
          className={`absolute h-3 w-3 transition-all duration-500 ${
            darkMode
              ? 'text-gray-700 opacity-0 -rotate-180'
              : 'text-yellow-500 opacity-100 rotate-0'
          }`}
          fill="currentColor"
          viewBox="0 0 20 20"
        >
          <path
            fillRule="evenodd"
            d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z"
            clipRule="evenodd"
          />
        </svg>
      </span>
    </button>
  );
};

export default ThemeToggle;