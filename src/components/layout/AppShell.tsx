import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { BrandMark, Icon, Wordmark } from "../ui/Icon";
import type { IconName } from "../ui/Icon";
import { Button, Pill } from "../ui/primitives";
import { useToast } from "../ui/overlays";
import { useRange } from "../../lib/simulation/store";
import { pendingApprovals } from "../../lib/simulation/engine";
import { cn, relativeTime } from "../../lib/utils";
import "../../styles/console.css";

const ROUTE_TITLES: Record<string, string> = {
  "/console": "Mission control",
  "/console/simulation": "Campaign runner",
  "/console/live": "Live folder remediation",
  "/console/findings": "Finding registry",
  "/console/incidents": "Incident response",
  "/console/memory": "Shared memory",
  "/console/safety": "Safety & governance",
  "/console/enterprise": "Mock enterprise",
};

const NAV_GROUPS: Array<{
  label: string;
  items: Array<{ to: string; label: string; icon: IconName; end?: boolean }>;
}> = [
  {
    label: "Mode 1 · Synthetic Range",
    items: [
      { to: "/console", label: "Mission control", icon: "gauge", end: true },
      {
        to: "/console/simulation",
        label: "Campaign runner",
        icon: "play-circle",
      },
      { to: "/console/findings", label: "Range findings", icon: "scan" },
      { to: "/console/incidents", label: "Incident response", icon: "git-branch" },
      { to: "/console/enterprise", label: "Mock enterprise", icon: "server" },
    ],
  },
  {
    label: "Mode 2 · Live Codebase",
    items: [
      {
        to: "/console/live",
        label: "Live folder remediation",
        icon: "folder",
      },
    ],
  },
  {
    label: "Governance & Specs",
    items: [
      { to: "/console/memory", label: "Shared memory", icon: "database" },
      { to: "/console/safety", label: "Safety & audit", icon: "fingerprint" },
      { to: "/architecture", label: "Architecture", icon: "book" },
    ],
  },
];

function KillSwitchControl() {
  const { state, tripKillSwitch, resetKillSwitch } = useRange();
  const { push } = useToast();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("Emergency halt requested by operator");
  const wrapper = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (!wrapper.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (state.killSwitch.tripped) {
    return (
      <button
        type="button"
        className="kill-reset"
        onClick={() => {
          resetKillSwitch();
          push({
            title: "Kill switch reset",
            message: "The range is ready for a new campaign.",
            tone: "success",
          });
        }}
      >
        <span className="kill-reset__dot" />
        Reset range
      </button>
    );
  }

  return (
    <div className="kill-control" ref={wrapper}>
      <button
        type="button"
        className="btn btn--danger btn--sm"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <Icon name="power" size={13} />
        Kill switch
      </button>
      {open && (
        <div className="kill-pop glass-strong" role="dialog" aria-label="Kill switch">
          <div className="kill-pop__head">
            <span className="kill-pop__icon">
              <Icon name="power" size={16} />
            </span>
            <div>
              <h4>Halt every agent</h4>
              <p>
                Stops the active campaign immediately. The sandbox and audit
                ledger are preserved; nothing is deleted.
              </p>
            </div>
          </div>
          <label className="field">
            <span>Reason</span>
            <input
              className="input"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Reason for halt"
            />
          </label>
          <div className="kill-pop__actions">
            <Button variant="quiet" size="sm" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              size="sm"
              icon="power"
              onClick={() => {
                tripKillSwitch(reason || "Emergency halt requested by operator");
                setOpen(false);
                push({
                  title: "Kill switch tripped",
                  message:
                    "All agent activity has been halted. Reset from Safety & governance.",
                  tone: "error",
                });
              }}
            >
              Trip switch
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function Sidebar({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const { state } = useRange();
  const pending = pendingApprovals(state).length;
  const location = useLocation();
  const isLiveMode = location.pathname.startsWith("/console/live");

  useEffect(() => {
    onClose();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  return (
    <>
      <button
        type="button"
        className={cn("console-scrim", open && "is-open")}
        onClick={onClose}
        aria-label="Close navigation"
        tabIndex={open ? 0 : -1}
      />
      <aside className={cn("sidebar", open && "is-open")}>
        <div className="sidebar__top">
          <Link to="/" className="sidebar__brand" aria-label="Citadel home">
            <BrandMark size={30} />
            <Wordmark />
          </Link>
          <button
            type="button"
            className="sidebar__close"
            onClick={onClose}
            aria-label="Close navigation"
          >
            <Icon name="close" size={16} />
          </button>
        </div>

        {isLiveMode ? (
          <Link to="/console/live" className="workspace-card workspace-card--live">
            <div className="workspace-card__top">
              <span className="lab" style={{ color: "var(--ice)" }}>Mode 2 · Live Codebase</span>
              <Icon name="chevron-right" size={12} />
            </div>
            <div className="workspace-card__name">Local Codebase Engine</div>
            <div className="workspace-card__meta">
              <span className="mono">Interactive Target</span>
              <span className="tag tag--live">STANDALONE</span>
            </div>
          </Link>
        ) : (
          <Link to="/console/enterprise" className="workspace-card">
            <div className="workspace-card__top">
              <span className="lab">Mode 1 · Synthetic Range</span>
              <Icon name="chevron-right" size={12} />
            </div>
            <div className="workspace-card__name">AcmeCorp Internal Portal</div>
            <div className="workspace-card__meta">
              <span className="mono">v1.0.0-vulnerable</span>
              <span className="tag">SEEDED MOCK</span>
            </div>
          </Link>
        )}

        <nav className="sidebar__nav" aria-label="Console">
          {NAV_GROUPS.map((group) => (
            <div className="sidebar__group" key={group.label}>
              <span className="sidebar__group-label">{group.label}</span>
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    cn("sidebar__link", isActive && "is-active")
                  }
                >
                  <Icon name={item.icon} size={15} />
                  <span>{item.label}</span>
                  {item.to === "/console/findings" &&
                    state.findings.length > 0 && (
                      <span className="sidebar__badge">
                        {state.findings.length}
                      </span>
                    )}
                  {item.to === "/console/incidents" && pending > 0 && (
                    <span className="sidebar__badge sidebar__badge--warn">
                      {pending}
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar__foot">
          <div className="sidebar__status">
            <div className="spread">
              <span className="lab">Range status</span>
              <span
                className={cn(
                  "score-dot",
                  state.killSwitch.tripped
                    ? "bg-rose"
                    : state.status === "running"
                      ? "bg-mint"
                      : "bg-ice",
                )}
              />
            </div>
            <div className="sidebar__status-main">
              {state.killSwitch.tripped
                ? "Halted"
                : state.status === "running"
                  ? "Campaign running"
                  : state.status === "complete"
                    ? "Verified"
                    : "Ready"}
            </div>
            <div className="sidebar__status-meta">
              <span>
                <Icon name="shield-check" size={10} />
                {state.remediatedCwes.length}/4 closed
              </span>
              <span>{state.audit.length} sealed</span>
            </div>
          </div>
          <div className="operator">
            <span className="operator__avatar">RO</span>
            <div>
              <b>Range operator</b>
              <span>Isolated session</span>
            </div>
            <Icon name="chevron-up" size={13} />
          </div>
        </div>
      </aside>
    </>
  );
}

export function ConsoleLayout() {
  const [menuOpen, setMenuOpen] = useState(false);
  const { state } = useRange();
  const location = useLocation();
  const isLiveMode = location.pathname.startsWith("/console/live");
  const title = ROUTE_TITLES[location.pathname] ?? "Console";
  const posture = state.rounds.length
    ? state.rounds[state.rounds.length - 1].scorecard.securityPostureScore
    : (state.remediatedCwes.length / 4) * 100;

  const status =
    state.killSwitch.tripped
      ? { label: "Range halted", tone: "critical" as const }
      : state.status === "running"
        ? { label: "Campaign running", tone: "live" as const }
        : state.status === "complete"
          ? { label: "Campaign complete", tone: "live" as const }
          : state.status === "halted"
            ? { label: "Campaign halted", tone: "critical" as const }
            : { label: "Range ready", tone: "neutral" as const };

  return (
    <div className="console">
      <Sidebar open={menuOpen} onClose={() => setMenuOpen(false)} />

      <div className="console__main">
        <header className="topbar">
          <div className="topbar__left">
            <button
              type="button"
              className="topbar__menu"
              onClick={() => setMenuOpen(true)}
              aria-label="Open navigation"
            >
              <Icon name="menu" size={17} />
            </button>
            <div className="topbar__crumb">
              <span>Console</span>
              <Icon name="chevron-right" size={11} />
              <span className="topbar__mode-badge mono">
                {isLiveMode ? "Mode 2: Codebase" : "Mode 1: Range"}
              </span>
              <Icon name="chevron-right" size={11} />
              <b>{title}</b>
            </div>
          </div>

          <div className="topbar__right">
            <Pill tone={status.tone} className="topbar__status">
              {state.status === "running" && <span className="dot" />}
              {status.label}
            </Pill>
            <div className="topbar__posture" title="Current security posture">
              <Icon name="shield-check" size={13} />
              <span>{posture.toFixed(0)}%</span>
              <em>posture</em>
            </div>
            <KillSwitchControl />
            <Link
              to="/"
              className="topbar__site-btn"
              aria-label="View public site overview"
              title="Return to Public Site"
            >
              <Icon name="external" size={13} />
              <span>Public site</span>
            </Link>
            <span className="topbar__avatar" title="Range Operator session">RO</span>
          </div>
        </header>

        {state.status === "running" && (
          <div className="range-progress" aria-hidden="true">
            <span style={{ width: `${Math.round(state.progress * 100)}%` }} />
            <em>{state.phaseLabel}</em>
          </div>
        )}

        <main className="console__content">
          <Outlet />
        </main>

        <footer className="console__foot">
          <span>
            <span className="score-dot bg-mint" /> citadel range · isolated
            workspace
          </span>
          <span className="mono">
            last sealed {state.audit.length ? relativeTime(state.audit[state.audit.length - 1].timestamp) : "—"}
            {" · "}
            {state.audit.length} entries
          </span>
        </footer>
      </div>
    </div>
  );
}
