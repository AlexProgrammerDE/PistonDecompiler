import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"
export default defineConfig({
  resolve: { tsconfigPaths: true },
  plugins: [tailwindcss(), react()],
  server: {
    proxy: {
      "/piston.v1.PistonService": {
        target: "http://127.0.0.1:7070",
        changeOrigin: true,
      },
      "/healthz": { target: "http://127.0.0.1:7070", changeOrigin: true },
    },
  },
  build: { target: "es2022" },
})
