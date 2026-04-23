import { Outlet, useLocation, Navigate } from "react-router-dom";

import { useSession } from "@/state/session";
import AdminShell from "@/components/AdminShell";

// AdminLayout gates every /admin/* route. Unauthenticated visitors
// are redirected to /admin/session (with the attempted path preserved
// so the sign-in can round-trip them back). Authenticated sessions
// land in the shared AdminShell.
export default function AdminLayout() {
  const session = useSession((s) => s.session);
  const loc = useLocation();

  if (!session) {
    return (
      <Navigate
        to="/admin/session"
        replace
        state={{ returnTo: loc.pathname + loc.search }}
      />
    );
  }

  return (
    <AdminShell>
      <Outlet />
    </AdminShell>
  );
}
