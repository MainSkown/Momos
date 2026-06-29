import { fileURLToPath, URL } from "node:url";

import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import vueDevTools from "vite-plugin-vue-devtools";

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue(), vueDevTools()],
  server: {
    host: "0.0.0.0",
    port: 5173,

    proxy: {
      // Typical HTTP requests
      "/api": {
        target: "http://momos-backend:8000",
        changeOrigin: true,
      },

      // Websockets
      "/ws": {
        target: "http://momos-backend:8000",
        changeOrigin: true,
        ws: true, 
      },
    },
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
});
