import type { Config } from "tailwindcss";

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        display: ["\"Space Grotesk\"", "ui-sans-serif", "system-ui", "sans-serif"],
        body: ["\"IBM Plex Sans\"", "ui-sans-serif", "system-ui", "sans-serif"]
      },
      colors: {
        ink: {
          50: "#f7f8fb",
          100: "#edf1f7",
          200: "#dbe5f0",
          300: "#bfd0e2",
          400: "#8ba4c1",
          500: "#607e9f",
          600: "#496582",
          700: "#35485f",
          800: "#223044",
          900: "#121b2a"
        },
        ember: "#f59e0b",
        tide: "#0ea5e9",
        mint: "#10b981",
        rose: "#f43f5e"
      },
      boxShadow: {
        haze: "0 18px 40px rgba(15, 23, 42, 0.18)"
      }
    }
  },
  plugins: []
} satisfies Config;
