import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        bg: "var(--ts-bg)",
        "bg-1": "var(--ts-bg-1)",
        "bg-2": "var(--ts-bg-2)",
        "bg-3": "var(--ts-bg-3)",
        line: "var(--ts-line)",
        "line-2": "var(--ts-line-2)",
        text: "var(--ts-text)",
        "text-2": "var(--ts-text-2)",
        "text-3": "var(--ts-text-3)",
        "text-4": "var(--ts-text-4)",
        ok: "var(--ts-ok)",
        warn: "var(--ts-warn)",
        bad: "var(--ts-bad)",
        info: "var(--ts-info)",
        accent: "var(--ts-accent)",
        "accent-ink": "var(--ts-accent-ink)",
      },
      fontFamily: {
        sans: [
          '"Inter Tight Variable"',
          '"Inter Tight"',
          "ui-sans-serif",
          "system-ui",
          "sans-serif",
        ],
        mono: [
          '"JetBrains Mono"',
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
      },
      fontSize: {
        kicker: ["10px", { letterSpacing: "0.14em", lineHeight: "1.3" }],
        "table-h": ["10px", { letterSpacing: "0.08em", lineHeight: "1.3" }],
        kpi: ["30px", { letterSpacing: "-0.02em", lineHeight: "1.1" }],
        "kpi-unit": ["11px", { lineHeight: "1.3" }],
        log: ["11px", { lineHeight: "1.55" }],
        status: ["11px", { lineHeight: "1.2" }],
        title: ["26px", { letterSpacing: "-0.01em", lineHeight: "1.1" }],
      },
      letterSpacing: {
        kicker: "0.14em",
        tableh: "0.08em",
      },
    },
  },
  plugins: [],
} satisfies Config;
