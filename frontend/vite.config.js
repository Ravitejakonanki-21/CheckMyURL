import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5001',
        changeOrigin: true,
      },
      '/analyze': 'http://127.0.0.1:5001',
      '/whois_check': 'http://127.0.0.1:5001',
      '/health': 'http://127.0.0.1:5001',
    }
  }
})
