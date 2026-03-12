// Use VITE_API_URL environment variable if it exists, otherwise fallback to standard local development URL
// Since the app uses a unified Docker setup in production where static files are served by Flask, 
// the API is on the same host (relative path '/')
export const API_BASE_URL = import.meta.env.VITE_API_URL || (import.meta.env.PROD ? '' : 'http://localhost:5001');
