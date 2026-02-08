import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],

  // Apache でサブディレクトリ配信する場合に備える
  // 例: https://www.sakimura.org/sd-jwt-decoder/
  base: "./",

  build: {
    target: "es2020",   // 不要な古い構文を出さない
    sourcemap: false    // 本番では source map を出さない
  }
});
