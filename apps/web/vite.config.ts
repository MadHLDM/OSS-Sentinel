import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [],
  server: {
    port: 5173,
    proxy: {
      '/scans': 'http://localhost:3333',
      '/projects': 'http://localhost:3333'
    }
  }
})
