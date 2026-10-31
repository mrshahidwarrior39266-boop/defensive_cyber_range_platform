import { useId } from "react";
import type { ReactNode } from "react";
import { AnimatedNumber } from "./primitives";
import { cn } from "../../lib/utils";
import type { Severity } from "../../lib/simulation/types";

/* -------------------------------------------------------------------------- */

export function Gauge({
  value,
  size = 188,
  label,
  caption,
  children,
}: {
  value: number;
  size?: number;
  label?: string;
  caption?: ReactNode;
  children?: ReactNode;
}) {
  const id = useId().replace(/:/g, "");
  const stroke = 8;
  const r = 88;
  const cx = 110;
  const cy = 110;
  const circumference = (3 * Math.PI * r) / 2;
  const offset = circumference * (1 - Math.max(0, Math.min(100, value)) / 100);
  const cos45 = Math.SQRT1_2 * r;

  return (
    <div className="gauge" style={{ width: size, height: size }}>
      <svg viewBox="0 0 220 220" className="gauge__svg" aria-hidden="true">
        <defs>
          <linearGradient id={`${id}-stroke`} x1="0" y1="0" x2="1" y2="1">
            <stop stopColor="#dfba89" />
            <stop offset="0.5" stopColor="#a8bba4" />
            <stop offset="1" stopColor="#ad2c54" />
          </linearGradient>
          <filter id={`${id}-glow`} x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <path
          d={`M ${cx - cos45} ${cy + cos45} A ${r} ${r} 0 1 1 ${cx + cos45} ${cy + cos45}`}
          fill="none"
          stroke="rgba(224, 213, 196, 0.12)"
          strokeWidth={stroke}
          strokeLinecap="round"
        />
        <path
          d={`M ${cx - cos45} ${cy + cos45} A ${r} ${r} 0 1 1 ${cx + cos45} ${cy + cos45}`}
          fill="none"
          stroke={`url(#${id}-stroke)`}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${circumference} ${circumference}`}
          strokeDashoffset={offset}
          filter={`url(#${id}-glow)`}
          style={{
            transition: "stroke-dashoffset 900ms cubic-bezier(0.22,0.8,0.22,1)",
          }}
        />
        <circle cx={cx} cy={cy} r={62} fill="rgba(247, 242, 232, 0.02)" />
        <circle
          cx={cx}
          cy={cy}
          r={62}
          fill="none"
          stroke="rgba(224, 213, 196, 0.08)"
        />
      </svg>
      <div className="gauge__center">
        <span className="gauge__value">
          <AnimatedNumber
            value={value}
            format={(n) => n.toFixed(1).replace(/\.0$/, "")}
          />
          <span className="gauge__pct">%</span>
        </span>
        {label && <span className="gauge__label">{label}</span>}
        {children}
      </div>
      {caption && <div className="gauge__caption">{caption}</div>}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function Sparkline({
  values,
  width = 120,
  height = 36,
  color = "#a8bba4",
  fill = true,
  className,
}: {
  values: number[];
  width?: number;
  height?: number;
  color?: string;
  fill?: boolean;
  className?: string;
}) {
  const id = useId().replace(/:/g, "");
  if (values.length < 2) {
    return <div className={className} style={{ height }} />;
  }
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const pad = 2;
  const points = values.map((value, index) => {
    const x = pad + (index / (values.length - 1)) * (width - pad * 2);
    const y =
      height - pad - ((value - min) / span) * (height - pad * 2);
    return [x, y] as const;
  });
  const line = points.map(([x, y]) => `${x.toFixed(2)},${y.toFixed(2)}`).join(" ");
  const area = `M ${points[0][0]},${height} L ${line.replace(/,/g, " ")} L ${points[points.length - 1][0]},${height} Z`;

  return (
    <svg
      className={cn("sparkline", className)}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={`${id}-f`} x1="0" y1="0" x2="0" y2="1">
          <stop stopColor={color} stopOpacity="0.24" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <path d={area} fill={`url(#${id}-f)`} />}
      <polyline
        points={line}
        fill="none"
        stroke={color}
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle
        cx={points[points.length - 1][0]}
        cy={points[points.length - 1][1]}
        r="2.1"
        fill={color}
      />
    </svg>
  );
}

/* -------------------------------------------------------------------------- */

export function LineChart({
  values,
  labels,
  height = 132,
  suffix = "%",
}: {
  values: number[];
  labels?: string[];
  height?: number;
  suffix?: string;
}) {
  const id = useId().replace(/:/g, "");
  const width = 520;
  const padX = 18;
  const padY = 18;
  const min = Math.min(0, ...values);
  const max = Math.max(100, ...values);
  const span = max - min || 1;
  const points = values.map((value, index) => {
    const x =
      values.length === 1
        ? width / 2
        : padX + (index / (values.length - 1)) * (width - padX * 2);
    const y = padY + (1 - (value - min) / span) * (height - padY * 2);
    return { x, y, value };
  });
  const line = points.map((p) => `${p.x},${p.y}`).join(" ");
  const area = points.length
    ? `M ${points[0].x},${height} L ${points
        .map((p) => `${p.x},${p.y}`)
        .join(" L ")} L ${points[points.length - 1].x},${height} Z`
    : "";

  return (
    <div className="line-chart">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        style={{ height }}
        aria-hidden="true"
      >
        <defs>
          <linearGradient id={`${id}-area`} x1="0" y1="0" x2="0" y2="1">
            <stop stopColor="#a8bba4" stopOpacity="0.22" />
            <stop offset="1" stopColor="#a8bba4" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75].map((ratio) => (
          <line
            key={ratio}
            x1={0}
            x2={width}
            y1={height * ratio}
            y2={height * ratio}
            stroke="rgba(224, 213, 196, 0.08)"
            strokeDasharray="2 5"
          />
        ))}
        {area && <path d={area} fill={`url(#${id}-area)`} />}
        <polyline
          points={line}
          fill="none"
          stroke="#a8bba4"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
        {points.map((point, index) => (
          <circle
            key={index}
            cx={point.x}
            cy={point.y}
            r="2.6"
            fill="#1c0e18"
            stroke="#a8bba4"
            strokeWidth="1.4"
          />
        ))}
      </svg>
      <div className="line-chart__axis">
        {(labels ?? values.map((_, index) => `Round ${index + 1}`)).map(
          (label, index) => (
            <span key={label}>
              {label}
              <b>
                {values[index]}
                {suffix}
              </b>
            </span>
          ),
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function SeverityBar({
  counts,
  total,
}: {
  counts: Record<Severity, number>;
  total: number;
}) {
  const order: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const colors: Record<Severity, string> = {
    CRITICAL: "var(--critical)",
    HIGH: "var(--high)",
    MEDIUM: "var(--medium)",
    LOW: "var(--low)",
  };
  return (
    <div className="severity-bar">
      <div className="severity-bar__track">
        {order.map((severity) => (
          <span
            key={severity}
            style={{
              width: `${total ? (counts[severity] / total) * 100 : 0}%`,
              background: colors[severity],
            }}
            title={`${severity}: ${counts[severity]}`}
          />
        ))}
      </div>
      <div className="severity-bar__legend">
        {order.map((severity) => (
          <span key={severity}>
            <i style={{ background: colors[severity] }} />
            {severity.toLowerCase()}
            <b>{counts[severity]}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function Meter({
  label,
  value,
  max = 100,
  suffix = "%",
  tone = "sage",
}: {
  label: string;
  value: number;
  max?: number;
  suffix?: string;
  tone?: "ice" | "violet" | "mint" | "amber" | "rose" | "sage" | "burgundy" | "cream";
}) {
  const pct = max ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div className="meter" data-tone={tone}>
      <div className="meter__row">
        <span>{label}</span>
        <b>
          {value}
          {suffix}
        </b>
      </div>
      <div className="meter__track">
        <span style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function MiniBars({
  values,
  labels,
  active,
}: {
  values: number[];
  labels: string[];
  active?: number;
}) {
  const max = Math.max(1, ...values);
  return (
    <div className="mini-bars">
      {values.map((value, index) => (
        <div
          key={index}
          className={cn("mini-bars__item", active === index && "is-active")}
        >
          <div className="mini-bars__track">
            <span style={{ height: `${Math.max(4, (value / max) * 100)}%` }} />
          </div>
          <span className="mini-bars__label">{labels[index]}</span>
        </div>
      ))}
    </div>
  );
}
