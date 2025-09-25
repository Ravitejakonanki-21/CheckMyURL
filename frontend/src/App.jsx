import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ThemeProvider } from "./context/ThemeContext";
import { ScanProvider } from "./context/ScanContext";
import Navbar from "./components/Navbar";
import Scanner from "./pages/Scanner";
import Statistics from "./pages/Statistics";

function App() {
  return (
    <ThemeProvider>
      <ScanProvider>
        <BrowserRouter>
          <div className="min-h-screen bg-gray-50 text-gray-900 dark:bg-gray-950 dark:text-gray-100">
            <Navbar />
            <main className="mx-auto max-w-6xl px-4 py-6">
              <Routes>
                <Route path="/" element={<Scanner />} />
                <Route path="/statistics" element={<Statistics />} />
              </Routes>
            </main>
          </div>
        </BrowserRouter>
      </ScanProvider>
    </ThemeProvider>
  );
}
export default App;
