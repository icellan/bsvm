import { PropsWithChildren, ReactNode } from "react";

// Panel is the shared card shell used across every explorer view.
// Kept in one place so dashboard rewrites / theme tweaks don't
// require editing every page.
export default function Panel({
  title,
  subtitle,
  children,
  className,
}: PropsWithChildren<{
  title?: string;
  subtitle?: ReactNode;
  className?: string;
}>) {
  return (
    <section className={`panel p-4 ${className ?? ""}`}>
      {title ? (
        <header className="mb-3 flex items-baseline justify-between">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-muted">
            {title}
          </h2>
          {subtitle ? (
            <span className="font-mono text-xs text-muted">{subtitle}</span>
          ) : null}
        </header>
      ) : null}
      {children}
    </section>
  );
}
