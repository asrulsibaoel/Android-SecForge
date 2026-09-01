import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// The frontend is a pure presentation layer. All data comes from the backend
// REST API under /api/v1; in dev we proxy it to the FastAPI server (default
// http://localhost:8000). The backend remains the single source of truth.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
});
