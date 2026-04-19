import { useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

// Search is a resolver-only page. It sniffs the query, redirects to
// the right detail view, and returns a 0-size render when it can't
// classify. Avoids implementing a universal fuzzy search — explorer
// inputs are always one of: block number / tx hash / address.
export default function Search() {
  const [sp] = useSearchParams();
  const navigate = useNavigate();
  const q = sp.get("q")?.trim() ?? "";

  useEffect(() => {
    if (!q) return;
    if (/^[0-9]+$/.test(q)) {
      navigate(`/block/${q}`, { replace: true });
      return;
    }
    if (/^0x[0-9a-fA-F]{64}$/.test(q)) {
      navigate(`/tx/${q}`, { replace: true });
      return;
    }
    if (/^0x[0-9a-fA-F]{40}$/.test(q)) {
      navigate(`/address/${q}`, { replace: true });
      return;
    }
  }, [q, navigate]);

  return (
    <div className="mx-auto max-w-lg text-sm text-muted">
      <p>Could not classify "{q}". Expected a block number, tx hash (0x + 64 hex), or address (0x + 40 hex).</p>
    </div>
  );
}
