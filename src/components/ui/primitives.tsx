import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { useReveal } from "../../lib/hooks";
import {
  beginViewTransition,
  cn,
  copyText,
  formatNumber,
  severityClass,
} from "../../lib/utils";
import type { Severity } from "../../lib/simulation/types";
import "./ui.css";

/* -------------------------------------------------------------------------- */

export function Button({
  children,
  variant = "ghost",
  size = "md",
  icon,
  iconRight,
  to,
  href,
  onClick,
  disabled,
  loading,
  block,
  type = "button",
  className,
  transition = false,
  ariaLabel,
  title,
}: {
  children?: ReactNode;
  variant?: "primary" | "ghost" | "quiet" | "danger";
  size?: "sm" | "md" | "lg";
  icon?: IconName;
  iconRight?: IconName;
  to?: string;
  href?: string;
  onClick?: () => void;
  disabled?: boolean;
  loading?: boolean;
  block?: boolean;
  type?: "button" | "submit" | "reset";
  className?: string;
  transition?: boolean;
  ariaLabel?: string;
  title?: string;
}) {
  const navigate = useNavigate();
  const classes = cn(
    "btn",
    `btn--${variant}`,
    size !== "md" && `btn--${size}`,
    block && "btn--block",
    className,
  );
  const content = (
    <>
      {loading ? (
        <span className="spinner" />
      ) : icon ? (
        <Icon name={icon} size={15} />
      ) : null}
      {children !== undefined && children !== null && (
        <span>{children}</span>
      )}
      {iconRight && <Icon name={iconRight} size={15} />}
    </>
  );

  if (to) {
    return (
      <Link
        to={to}
        className={classes}
        aria-label={ariaLabel}
        title={title}
        onClick={(event) => {
          if (transition) {
            event.preventDefault();
            onClick?.();
            beginViewTransition(() => navigate(to));
          } else {
            onClick?.();
          }
        }}
      >
        {content}
      </Link>
    );
  }

  if (href) {
    return (
      <a
        href={href}
        className={classes}
        target="_blank"
        rel="noreferrer"
        aria-label={ariaLabel}
        title={title}
      >
        {content}
      </a>
    );
  }

  return (
    <button
      type={type}
      className={classes}
      onClick={onClick}
      disabled={disabled || loading}
      aria-label={ariaLabel}
      title={title}
    >
      {content}
    </button>
  );
}

/* -------------------------------------------------------------------------- */

export function Pill({
  children,
  tone = "neutral",
  icon,
  className,
}: {
  children: ReactNode;
  tone?: "neutral" | "live" | "critical" | "high" | "medium" | "low" | "violet";
  icon?: IconName;
  className?: string;
}) {
  return (
    <span className={cn("pill", `pill--${tone}`, className)}>
      {icon && <Icon name={icon} size={11} />}
      {children}
    </span>
  );
}

export function SeverityPill({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span className={cn("pill", severityClass(severity), className)}>
      <span
        className="score-dot"
        style={{
          background:
            severity === "CRITICAL"
              ? "var(--critical)"
              : severity === "HIGH"
                ? "var(--high)"
                : severity === "MEDIUM"
                  ? "var(--medium)"
                  : "var(--low)",
        }}
      />
      {severity}
    </span>
  );
}

/* -------------------------------------------------------------------------- */

export function Panel({
  title,
  subtitle,
  actions,
  children,
  flush,
  className,
  bodyClassName,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("panel", className)}>
      {(title || actions) && (
        <header className="panel__head">
          <div className="panel__title">
            {title && (typeof title === "string" ? <h3>{title}</h3> : title)}
            {subtitle && <span>{subtitle}</span>}
          </div>
          {actions && <div className="row gap-8">{actions}</div>}
        </header>
      )}
      <div
        className={cn(
          flush ? "panel__body panel__body--flush" : "panel__body",
          bodyClassName,
        )}
      >
        {children}
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  meta,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <header className="page-head">
      <div className="page-head__main">
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
        {meta && <div className="page-head__meta">{meta}</div>}
      </div>
      {actions && <div className="page-head__actions">{actions}</div>}
    </header>
  );
}

/* -------------------------------------------------------------------------- */

export function Tabs({
  tabs,
  active,
  onChange,
  className,
}: {
  tabs: Array<{ id: string; label: string; count?: number; icon?: IconName }>;
  active: string;
  onChange: (id: string) => void;
  className?: string;
}) {
  return (
    <div className={cn("tabs", className)} role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={active === tab.id}
          className={cn("tabs__tab", active === tab.id && "is-active")}
          onClick={() => onChange(tab.id)}
        >
          {tab.icon && <Icon name={tab.icon} size={13} />}
          {tab.label}
          {tab.count !== undefined && (
            <span className="tabs__count">{tab.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function Stat({
  label,
  value,
  suffix,
  hint,
  icon,
  accent = "ice",
  children,
}: {
  label: string;
  value: ReactNode;
  suffix?: string;
  hint?: ReactNode;
  icon?: IconName;
  accent?: "ice" | "violet" | "mint" | "amber" | "rose";
  children?: ReactNode;
}) {
  return (
    <div className="stat" data-accent={accent}>
      <div className="stat__top">
        <span className="stat__label">{label}</span>
        {icon && (
          <span className="stat__icon">
            <Icon name={icon} size={14} />
          </span>
        )}
      </div>
      <div className="stat__value">
        {value}
        {suffix && <span className="stat__suffix">{suffix}</span>}
      </div>
      {hint && <div className="stat__hint">{hint}</div>}
      {children}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function EmptyState({
  icon = "scan",
  title,
  description,
  action,
}: {
  icon?: IconName;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty__icon">
        <Icon name={icon} size={20} />
      </div>
      <h4>{title}</h4>
      <p>{description}</p>
      {action && <div className="mt-8">{action}</div>}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function AnimatedNumber({
  value,
  format = (n: number) => formatNumber(Math.round(n)),
  duration = 900,
}: {
  value: number;
  format?: (value: number) => string;
  duration?: number;
}) {
  const [display, setDisplay] = useState(value);
  const previous = useRef(value);
  const frame = useRef(0);

  useEffect(() => {
    const from = previous.current;
    const to = value;
    previous.current = value;
    if (
      window.matchMedia("(prefers-reduced-motion: reduce)").matches ||
      from === to
    ) {
      setDisplay(to);
      return;
    }
    const start = performance.now();
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(from + (to - from) * eased);
      if (progress < 1) frame.current = requestAnimationFrame(tick);
    };
    frame.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame.current);
  }, [value, duration]);

  return <>{format(display)}</>;
}

/* -------------------------------------------------------------------------- */

export function Reveal({
  children,
  delay = 0,
  className,
  as = "div",
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
  as?: "div" | "section" | "article" | "li";
}) {
  const ref = useReveal<HTMLDivElement>(delay);
  const Tag = as as "div";
  return (
    <Tag ref={ref} className={cn("reveal", className)}>
      {children}
    </Tag>
  );
}

/* -------------------------------------------------------------------------- */

export function CopyButton({
  value,
  label = "Copy",
  className,
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className={cn("btn btn--quiet btn--sm", className)}
      onClick={async () => {
        const ok = await copyText(value);
        if (ok) {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1600);
        }
      }}
      aria-label={copied ? "Copied" : label}
    >
      <Icon name={copied ? "check" : "copy"} size={12} />
      {copied ? "Copied" : label}
    </button>
  );
}

export function IconButton({
  icon,
  label,
  onClick,
  className,
}: {
  icon: IconName;
  label: string;
  onClick?: () => void;
  className?: string;
}) {
  return (
    <button
      type="button"
      className={cn("btn--icon", className)}
      onClick={onClick}
      aria-label={label}
      title={label}
    >
      <Icon name={icon} size={15} />
    </button>
  );
}
