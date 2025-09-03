import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/scans': 'http://localhost:3333',
      '/projects': 'http://localhost:3333'
    }
  },
  // Reduce noisy dev console sourcemap warnings from prebundled deps
  optimizeDeps: {
    esbuildOptions: {
      sourcemap: false,
    },
  },
  esbuild: { sourcemap: false },
  css: { devSourcemap: false },
  build: { sourcemap: false },
})
