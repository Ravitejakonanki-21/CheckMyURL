import { createContext, useContext, useEffect, useState } from 'react';

// The createContext function does not need a type parameter in JavaScript
const ThemeContext = createContext(undefined);

export function ThemeProvider({ children }) {
  // 1. Initialize state, checking localStorage
  // The type assertion is removed, as it's not needed in JS
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('theme');
    // Default to 'dark' if no saved theme is found
    return saved || 'dark';
  });

  // 2. Side effect to save theme and apply CSS class
  useEffect(() => {
    localStorage.setItem('theme', theme);
    // document.documentElement is the <html> tag
    document.documentElement.classList.toggle('dark', theme === 'dark');
  }, [theme]); // Rerun effect whenever 'theme' changes

  // 3. Function to toggle the theme state
  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  // 4. Provide the state and toggle function to the component tree
  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  // 5. Custom hook to consume the context
  const context = useContext(ThemeContext);
  
  // 6. Check for valid context value (error handling)
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
}