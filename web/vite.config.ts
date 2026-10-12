import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// base './' + HashRouter：构建产物可直接 embed 进 Go 二进制（§12.5）
export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:9443', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: { index: 'index.html', portal: 'portal.html' },
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          antd: ['antd', '@ant-design/icons', '@ant-design/pro-components'],
          echarts: ['echarts', 'echarts-for-react'],
        },
      },
    },
  },
});
