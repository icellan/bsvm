import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";

export type Theme = "dark" | "light";

type ThemeState = {
  theme: Theme;
  setTheme: (t: Theme) => void;
  toggle: () => void;
};

// Theme store: persisted in localStorage and reflected on <body> as
// `.light`. Dark is the default; the BSVM Console design is built
// around the mission-control dark palette and light is a documented
// override.
export const useTheme = create<ThemeState>()(
  persist(
    (set, get) => ({
      theme: "dark",
      setTheme: (t) => {
        applyThemeClass(t);
        set({ theme: t });
      },
      toggle: () => {
        const next: Theme = get().theme === "dark" ? "light" : "dark";
        applyThemeClass(next);
        set({ theme: next });
      },
    }),
    {
      name: "bsvm-console-theme",
      storage: createJSONStorage(() => localStorage),
      onRehydrateStorage: () => (state) => {
        if (state?.theme) applyThemeClass(state.theme);
      },
    }
  )
);

function applyThemeClass(t: Theme) {
  if (typeof document === "undefined") return;
  document.body.classList.toggle("light", t === "light");
}
