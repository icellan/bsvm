import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div
      className="flex flex-col items-center justify-center"
      style={{ padding: "80px 20px", gap: 12 }}
    >
      <div
        className="mono"
        style={{
          fontSize: 10,
          letterSpacing: "0.14em",
          textTransform: "uppercase",
          color: "var(--ts-text-3)",
        }}
      >
        404 · not found
      </div>
      <h1
        className="mono"
        style={{
          fontSize: 48,
          fontWeight: 500,
          letterSpacing: "-0.02em",
          color: "var(--ts-accent)",
        }}
      >
        0x404
      </h1>
      <p
        style={{ color: "var(--ts-text-2)", fontSize: 14, maxWidth: 420, textAlign: "center" }}
      >
        We couldn't find a block, transaction, or address at this path. The
        explorer URL may have been truncated.
      </p>
      <Link
        to="/"
        className="mono"
        style={{
          marginTop: 10,
          fontSize: 11,
          padding: "6px 12px",
          border: "1px solid var(--ts-accent)",
          color: "var(--ts-accent)",
          borderRadius: 4,
        }}
      >
        ← back to overview
      </Link>
    </div>
  );
}
