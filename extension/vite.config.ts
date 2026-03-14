import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'
import { copyFileSync } from 'fs'

const copyManifest = {
  name: 'copy-manifest',
  closeBundle() { copyFileSync('manifest.json', 'dist/manifest.json') }
}

export default defineConfig({
  plugins: [react(), copyManifest],
  define: {
    __dirname: JSON.stringify('/'),
    __filename: JSON.stringify('/index.js'),
    'process.env': '{}',
    'process.browser': 'true',
    'process.version': JSON.stringify('v18.0.0'),
    global: 'globalThis',
  },
  resolve: {
    conditions: ['browser', 'module', 'import', 'default'],
    alias: {
      // Force stellar-sdk browser bundle (avoids require/Node.js internals)
      '@stellar/stellar-sdk': resolve(
        __dirname,
        'node_modules/@stellar/stellar-sdk/dist/stellar-sdk.min.js'
      ),
    },
  },
  optimizeDeps: {
    include: ['@stellar/stellar-sdk'],
  },
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        background: resolve(__dirname, 'src/background.ts'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: '[name].js',
        assetFileNames: '[name].[ext]',
      },
    },
  },
})
