import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [react()],
  server: { proxy: {
    '/api': 'http://127.0.0.1:5000',
    '/login': { target: 'http://127.0.0.1:5000', bypass: (request) => request.method === 'GET' ? request.url : undefined },
    '/register': { target: 'http://127.0.0.1:5000', bypass: (request) => request.method === 'GET' ? request.url : undefined },
    '/logout': 'http://127.0.0.1:5000', '/password-reset': 'http://127.0.0.1:5000', '/mfa/recovery': 'http://127.0.0.1:5000',
  } },
  test: { environment: 'jsdom', setupFiles: './src/test-setup.ts', clearMocks: true },
});
