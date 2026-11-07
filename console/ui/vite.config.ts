import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Relative base so the built bundle loads from file:// inside Electron.
  base: "./",
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  // Bind v4 explicitly: `localhost` resolves to ::1 here, which the Electron
  // dev window's 127.0.0.1 URL cannot reach.
  server: { host: "127.0.0.1", port: 5319, strictPort: true },
  build: { outDir: "dist", emptyOutDir: true },
});
