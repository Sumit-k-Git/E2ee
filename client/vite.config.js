import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],

  server: {
    port: 5173,
    proxy: {
      // Forward /api/* to the backend
      '/api': {
        target: 'http://localhost:4000',
        changeOrigin: true,
      },
      // Forward WebSocket /ws to the backend
      '/ws': {
        target: 'ws://localhost:4000',
        ws: true,
        changeOrigin: true,
      },
    },
  },

  build: {
    outDir: 'dist',
    // Split vendor chunks for better caching
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom'],
          crypto: ['tweetnacl', 'tweetnacl-util'],
        },
      },
    },
    // Minify + strip console logs in production
    minify: 'esbuild',
    sourcemap: false, // never expose source maps in production
  },

  // Env prefix — only vars starting with VITE_ are exposed to the browser
  envPrefix: 'VITE_',
});
