import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"
export default defineConfig({
  resolve: { tsconfigPaths: true },
  plugins: [tailwindcss(), react()],
  server: {
    proxy: {
      "/piston.v1.PistonService": "http://127.0.0.1:7070",
      "/healthz": "http://127.0.0.1:7070",
    },
  },
  build: { target: "es2022" },
})
