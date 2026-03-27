import clsx from "clsx";

import { severityTone } from "../lib/format";
import type { Severity } from "../lib/types";

export function SeverityPill({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <span className={clsx("inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide", severityTone(severity))}>
      {severity}
      {typeof count === "number" ? <span className="rounded-full bg-white/70 px-1.5 py-0.5 text-[10px] dark:bg-black/25">{count}</span> : null}
    </span>
  );
}
