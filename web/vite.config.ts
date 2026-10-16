import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The browser only ever talks to the platform API; in dev it is proxied so no CORS or tokens in URLs.
const api = process.env.AISW_API_URL ?? 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': { target: api, changeOrigin: false } } },
})
