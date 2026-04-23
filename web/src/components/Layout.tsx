import { Outlet } from "react-router-dom";
import { useEffect } from "react";

import Chrome from "@/components/Chrome";
import StatusBar from "@/components/StatusBar";
import FreezeBanner from "@/components/FreezeBanner";
import { useTheme } from "@/state/theme";

// Layout composes the persistent chrome (freeze banner, top bar,
// fixed status footer) around every route's <Outlet />.
export default function Layout() {
  const theme = useTheme((s) => s.theme);

  useEffect(() => {
    document.body.classList.toggle("light", theme === "light");
  }, [theme]);

  return (
    <div
      className="flex min-h-full flex-col"
      style={{ paddingBottom: 28, background: "var(--ts-bg)" }}
    >
      <FreezeBanner />
      <Chrome />
      <main
        className="flex-1"
        style={{ padding: "20px", maxWidth: 1400, width: "100%", margin: "0 auto" }}
      >
        <Outlet />
      </main>
      <StatusBar />
    </div>
  );
}
