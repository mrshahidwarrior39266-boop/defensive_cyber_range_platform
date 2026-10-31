import type { ReactNode } from "react";
import { useId } from "react";

const ICONS = {
  "arrow-right": (
    <>
      <path d="M4 12h15" />
      <path d="M13 6l6 6-6 6" />
    </>
  ),
  "arrow-left": (
    <>
      <path d="M20 12H5" />
      <path d="M11 6l-6 6 6 6" />
    </>
  ),
  "arrow-up-right": (
    <>
      <path d="M7 17L17 7" />
      <path d="M8 7h9v9" />
    </>
  ),
  "arrow-down-right": (
    <>
      <path d="M7 7l10 10" />
      <path d="M17 8v9H8" />
    </>
  ),
  "chevron-right": <path d="M9 6l6 6-6 6" />,
  "chevron-down": <path d="M6 9l6 6 6-6" />,
  "chevron-up": <path d="M6 15l6-6 6 6" />,
  close: (
    <>
      <path d="M6 6l12 12" />
      <path d="M18 6L6 18" />
    </>
  ),
  menu: (
    <>
      <path d="M4 7h16" />
      <path d="M4 12h16" />
      <path d="M4 17h16" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="6.5" />
      <path d="M16 16l4 4" />
    </>
  ),
  play: <path d="M8 5.5v13l10-6.5z" />,
  pause: (
    <>
      <path d="M9 5v14" />
      <path d="M15 5v14" />
    </>
  ),
  stop: <rect x="6" y="6" width="12" height="12" rx="2.5" />,
  shield: <path d="M12 3l7 3v5.5c0 4.2-2.8 7.7-7 9.5-4.2-1.8-7-5.3-7-9.5V6l7-3z" />,
  "shield-check": (
    <>
      <path d="M12 3l7 3v5.5c0 4.2-2.8 7.7-7 9.5-4.2-1.8-7-5.3-7-9.5V6l7-3z" />
      <path d="M9 11.5l2 2 4-4.5" />
    </>
  ),
  scan: (
    <>
      <path d="M4 8V5a1 1 0 011-1h3" />
      <path d="M16 4h3a1 1 0 011 1v3" />
      <path d="M20 16v3a1 1 0 01-1 1h-3" />
      <path d="M8 20H5a1 1 0 01-1-1v-3" />
      <path d="M4 12h16" />
    </>
  ),
  terminal: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="3" />
      <path d="M7 9l3 3-3 3" />
      <path d="M13 15h4" />
    </>
  ),
  folder: (
    <>
      <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
    </>
  ),
  tool: (
    <>
      <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z" />
    </>
  ),
  upload: (
    <>
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
      <path d="M17 8l-5-5-5 5" />
      <path d="M12 3v12" />
    </>
  ),
  "file-code": (
    <>
      <path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z" />
      <path d="M14 3v5h5" />
      <path d="M10 12l-2 2 2 2" />
      <path d="M14 12l2 2-2 2" />
    </>
  ),
  database: (
    <>
      <ellipse cx="12" cy="5.5" rx="7.5" ry="2.8" />
      <path d="M4.5 5.5v6c0 1.55 3.36 2.8 7.5 2.8s7.5-1.25 7.5-2.8v-6" />
      <path d="M4.5 11.5v6c0 1.55 3.36 2.8 7.5 2.8s7.5-1.25 7.5-2.8v-6" />
    </>
  ),
  activity: <path d="M3 13h4l2.5-7 4 13 2.5-6H21" />,
  layers: (
    <>
      <path d="M12 3l9 5-9 5-9-5 9-5z" />
      <path d="M3 12l9 5 9-5" />
      <path d="M3 16l9 5 9-5" />
    </>
  ),
  target: (
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3.5" />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
    </>
  ),
  check: <path d="M5 12.5l4.5 4.5L19 6.5" />,
  "check-circle": (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M8.5 12l2.5 2.5 4.5-5" />
    </>
  ),
  "x-circle": (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M9 9l6 6M15 9l-6 6" />
    </>
  ),
  alert: (
    <>
      <path d="M12 4l9 15.5H3L12 4z" />
      <path d="M12 10v4.5" />
      <path d="M12 17.5v.1" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </>
  ),
  lock: (
    <>
      <rect x="4.5" y="10" width="15" height="10" rx="2.5" />
      <path d="M8 10V7.5a4 4 0 018 0V10" />
      <path d="M12 14v2.5" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="8" r="4" />
      <path d="M11 11l9 9" />
      <path d="M16 16l2-2M19 19l2-2" />
    </>
  ),
  bug: (
    <>
      <rect x="7" y="8" width="10" height="11" rx="5" />
      <path d="M9 8V6a3 3 0 016 0v2" />
      <path d="M3.5 12H7M17 12h3.5M4.5 7.5L7 9M19.5 7.5L17 9M4.5 17l2.5-1.5M19.5 17L17 15.5" />
    </>
  ),
  "git-branch": (
    <>
      <circle cx="6" cy="5" r="2.2" />
      <circle cx="6" cy="19" r="2.2" />
      <circle cx="18" cy="7" r="2.2" />
      <path d="M6 7.2v9.6" />
      <path d="M18 9.2c0 4-4 4.8-6 6.2" />
    </>
  ),
  zap: <path d="M13 2L5 13h6l-1 9 8-11h-6l1-9z" />,
  eye: (
    <>
      <path d="M2.5 12s3.4-6 9.5-6 9.5 6 9.5 6-3.4 6-9.5 6-9.5-6-9.5-6z" />
      <circle cx="12" cy="12" r="2.6" />
    </>
  ),
  link: (
    <>
      <path d="M10.5 13.5a4 4 0 005.66 0l2.84-2.84a4 4 0 00-5.66-5.66l-1.2 1.2" />
      <path d="M13.5 10.5a4 4 0 00-5.66 0L5 13.34a4 4 0 005.66 5.66l1.2-1.2" />
    </>
  ),
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M15 9V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7a2 2 0 002 2h3" />
    </>
  ),
  download: (
    <>
      <path d="M12 3v12" />
      <path d="M7 10l5 5 5-5" />
      <path d="M4 20h16" />
    </>
  ),
  refresh: (
    <>
      <path d="M20 11a8 8 0 10-2.34 5.66" />
      <path d="M20 5v6h-6" />
    </>
  ),
  power: (
    <>
      <path d="M12 3v9" />
      <path d="M6.5 7a8 8 0 1011 0" />
    </>
  ),
  sliders: (
    <>
      <path d="M4 7h10M18 7h2" />
      <path d="M4 17h4M12 17h8" />
      <circle cx="16" cy="7" r="2" />
      <circle cx="10" cy="17" r="2" />
    </>
  ),
  users: (
    <>
      <circle cx="9" cy="8" r="3.2" />
      <path d="M3.5 20v-1.5a5.5 5.5 0 0111 0V20" />
      <path d="M16 5.2a3.2 3.2 0 010 5.6" />
      <path d="M17.5 14.4a5.5 5.5 0 013 4.1V20" />
    </>
  ),
  book: (
    <>
      <path d="M4 5.5A2.5 2.5 0 016.5 3H20v16H6.5A2.5 2.5 0 004 21.5v-16z" />
      <path d="M4 18.5A2.5 2.5 0 016.5 16H20" />
    </>
  ),
  command: (
    <>
      <path d="M8.5 8.5h7v7h-7z" />
      <path d="M8.5 3.5v5M15.5 3.5v5M8.5 15.5v5M15.5 15.5v5M3.5 8.5h5M3.5 15.5h5M15.5 8.5h5M15.5 15.5h5" />
    </>
  ),
  gauge: (
    <>
      <path d="M4 17a8.5 8.5 0 1116 0" />
      <path d="M12 12l4-4" />
      <circle cx="12" cy="16.5" r="1.2" />
    </>
  ),
  fingerprint: (
    <>
      <path d="M12 3.5a8.5 8.5 0 018.5 8.5v2" />
      <path d="M3.5 12A8.5 8.5 0 0112 3.5" />
      <path d="M6.5 12a5.5 5.5 0 0111 0v4" />
      <path d="M9.5 12a2.5 2.5 0 015 0v6.5" />
      <path d="M6 16.5V18" />
    </>
  ),
  sparkles: (
    <>
      <path d="M12 3l1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6L12 3z" />
      <path d="M18.5 14l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2z" />
    </>
  ),
  code: (
    <>
      <path d="M8.5 8L4 12l4.5 4" />
      <path d="M15.5 8L20 12l-4.5 4" />
      <path d="M13.5 5l-3 14" />
    </>
  ),
  server: (
    <>
      <rect x="3.5" y="4" width="17" height="7" rx="2" />
      <rect x="3.5" y="13" width="17" height="7" rx="2" />
      <path d="M7 7.5h.1M7 16.5h.1" />
      <path d="M11 7.5h6M11 16.5h6" />
    </>
  ),
  boxes: (
    <>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="8.5" y="13.5" width="7" height="7" rx="1.5" />
    </>
  ),
  cpu: (
    <>
      <rect x="6" y="6" width="12" height="12" rx="2" />
      <rect x="9.5" y="9.5" width="5" height="5" rx="1" />
      <path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" />
    </>
  ),
  network: (
    <>
      <circle cx="12" cy="5" r="2.3" />
      <circle cx="5" cy="18" r="2.3" />
      <circle cx="19" cy="18" r="2.3" />
      <path d="M12 7.3v4.2M12 11.5L6 16M12 11.5l6 4.5" />
    </>
  ),
  message: (
    <>
      <path d="M20 15.5a2.5 2.5 0 01-2.5 2.5H8l-4 3V6.5A2.5 2.5 0 016.5 4h11A2.5 2.5 0 0120 6.5v9z" />
      <path d="M8 9h8M8 12.5h5" />
    </>
  ),
  list: (
    <>
      <path d="M8 6h13M8 12h13M8 18h13" />
      <path d="M3.5 6h.1M3.5 12h.1M3.5 18h.1" />
    </>
  ),
  filter: (
    <>
      <path d="M3 5h18l-7 8v6l-4 2v-8L3 5z" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5" />
      <path d="M12 8v.1" />
    </>
  ),
  calendar: (
    <>
      <rect x="3.5" y="5" width="17" height="16" rx="2.5" />
      <path d="M3.5 10h17M8 3v4M16 3v4" />
    </>
  ),
  box: (
    <>
      <path d="M12 3l8.5 4.5v9L12 21l-8.5-4.5v-9L12 3z" />
      <path d="M3.5 7.5L12 12l8.5-4.5M12 12v9" />
    </>
  ),
  workflow: (
    <>
      <rect x="3" y="3.5" width="7" height="6" rx="1.5" />
      <rect x="14" y="14.5" width="7" height="6" rx="1.5" />
      <path d="M10 6.5h4a3 3 0 013 3v5" />
      <path d="M14 12l3 3 3-3" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  minus: <path d="M5 12h14" />,
  external: (
    <>
      <path d="M14 4h6v6" />
      <path d="M20 4L11 13" />
      <path d="M18 14v4.5a2.5 2.5 0 01-2.5 2.5h-9A2.5 2.5 0 014 18.5v-9A2.5 2.5 0 016.5 7H11" />
    </>
  ),
  "play-circle": (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M10 8.8l5 3.2-5 3.2z" />
    </>
  ),
  dot: <circle cx="12" cy="12" r="3" fill="currentColor" stroke="none" />,
} as const;

export type IconName = keyof typeof ICONS;

export function Icon({
  name,
  size = 16,
  strokeWidth = 1.5,
  className,
}: {
  name: IconName;
  size?: number;
  strokeWidth?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {ICONS[name] as ReactNode}
    </svg>
  );
}

export function BrandMark({ size = 30 }: { size?: number }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={`${id}-a`} x1="6" y1="3" x2="34" y2="37">
          <stop stopColor="#f7f2e8" />
          <stop offset="0.4" stopColor="#dfba89" />
          <stop offset="1" stopColor="#ad2c54" />
        </linearGradient>
        <linearGradient id={`${id}-b`} x1="10" y1="6" x2="30" y2="34">
          <stop stopColor="#f7f2e8" stopOpacity="0.95" />
          <stop offset="0.5" stopColor="#9baa97" stopOpacity="0.85" />
          <stop offset="1" stopColor="#ad2c54" stopOpacity="0.3" />
        </linearGradient>
      </defs>
      <rect
        x="1"
        y="1"
        width="38"
        height="38"
        rx="12"
        fill="rgba(45, 12, 28, 0.45)"
        stroke="rgba(224, 213, 196, 0.22)"
      />
      <path
        d="M13 11h4.1l2.9 5.2 2.9-5.2H27l-5 8.8 5.3 8.2h-4.2L20 23l-3.1 5h-4.2l5.3-8.2L13 11z"
        fill={`url(#${id}-a)`}
      />
      <path
        d="M13 11h4.1l2.9 5.2"
        stroke={`url(#${id}-b)`}
        strokeWidth="1.25"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function Wordmark({ compact = false }: { compact?: boolean }) {
  return (
    <span className="wordmark">
      <span className="wordmark__name">CITADEL</span>
      {!compact && <span className="wordmark__tag">CYBER RANGE</span>}
    </span>
  );
}
