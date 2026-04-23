import { useEffect, useRef, useState } from "react";

// useRingBuffer samples `value` whenever it changes and keeps the
// last `length` samples. Backend has no per-metric history surface,
// so every sparkline on the dashboard uses a client-side ring
// populated from live query results. Cold page loads show a single
// point until enough ticks accumulate — documented behavior.
export function useRingBuffer(
  value: number | null | undefined,
  length = 60
): number[] {
  const [buf, setBuf] = useState<number[]>([]);
  const lastRef = useRef<number | null>(null);

  useEffect(() => {
    if (value === null || value === undefined || Number.isNaN(value)) return;
    if (lastRef.current === value) return;
    lastRef.current = value;
    setBuf((prev) => {
      const next = prev.length >= length ? prev.slice(1) : prev.slice();
      next.push(value);
      return next;
    });
  }, [value, length]);

  return buf;
}
