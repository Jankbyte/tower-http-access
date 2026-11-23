import react from '@vitejs/plugin-react'
import basicSsl from '@vitejs/plugin-basic-ssl'
import { defineConfig } from 'vite'
import checker from 'vite-plugin-checker'

// https://vite.dev/config/
export default defineConfig({
  base: '/ui/',
  plugins: [
    react(),
    basicSsl(),
    checker({
      typescript: { buildMode: true },
      oxlint: true,
      terminal: true,
      overlay: { initialIsOpen: true },
      // The build script already runs tsc; these checks are for development.
      enableBuild: false,
    }),
  ],
  clearScreen: false,
  server: {
    proxy: {
      '/v1': 'http://127.0.0.1:3001',
    },
  },
})
