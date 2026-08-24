import { cx } from "../lib";

interface StatusPillProps {
  label: string;
  tone?: string;
  dot?: boolean;
  className?: string;
}

export function StatusPill({ label, tone = "neutral", dot = true, className }: StatusPillProps) {
  return (
    <span className={cx("status-pill", `status-pill--${tone}`, className)}>
      {dot && <span className="status-pill__dot" aria-hidden="true" />}
      {label}
    </span>
  );
}
