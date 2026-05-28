import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/dashboard/',
  server: {
    host: true,
    allowedHosts: true,
    proxy: {
      '/dashboard-api': {
        target: 'http://localhost:6001',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/dashboard-api/, '')
      }
    }
  }
})
