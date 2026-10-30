import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { cn } from "../../lib/utils";
import "./ui.css";

/* -------------------------------------------------------------------------- */

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  eyebrow,
  children,
  footer,
  width = 560,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  eyebrow?: string;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
}) {
  const closeRef = useRef<HTMLButtonElement | null>(null);
  const lastFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    lastFocus.current = document.activeElement as HTMLElement;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
      lastFocus.current?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div className="drawer-root">
      <button
        type="button"
        className="drawer__scrim"
        onClick={onClose}
        aria-label="Close panel"
        tabIndex={-1}
      />
      <aside
        className="drawer"
        style={{ width: `min(${width}px, 100vw)` }}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === "string" ? title : "Detail panel"}
      >
        <header className="drawer__head">
          <div className="drawer__titles">
            {eyebrow && <span className="eyebrow">{eyebrow}</span>}
            <h2>{title}</h2>
            {subtitle && <div className="drawer__sub">{subtitle}</div>}
          </div>
          <button
            ref={closeRef}
            type="button"
            className="btn--icon"
            onClick={onClose}
            aria-label="Close detail panel"
          >
            <Icon name="close" size={16} />
          </button>
        </header>
        <div className="drawer__body">{children}</div>
        {footer && <footer className="drawer__foot">{footer}</footer>}
      </aside>
    </div>,
    document.body,
  );
}

/* -------------------------------------------------------------------------- */

type ToastTone = "success" | "error" | "info";
interface ToastItem {
  id: number;
  title: string;
  message: string;
  tone: ToastTone;
}

const ToastContext = createContext<{
  push: (toast: Omit<ToastItem, "id">) => void;
} | null>(null);

let toastId = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const timers = useRef<number[]>([]);

  const push = useCallback((toast: Omit<ToastItem, "id">) => {
    const id = ++toastId;
    setToasts((current) => [...current.slice(-2), { ...toast, id }]);
    const timer = window.setTimeout(() => {
      setToasts((current) => current.filter((item) => item.id !== id));
    }, 5200);
    timers.current.push(timer);
  }, []);

  useEffect(() => {
    const handles = timers.current;
    return () => handles.forEach((timer) => window.clearTimeout(timer));
  }, []);

  const icons: Record<ToastTone, IconName> = {
    success: "check-circle",
    error: "alert",
    info: "info",
  };

  return (
    <ToastContext.Provider value={{ push }}>
      {children}
      <div className="toast-stack" aria-live="polite" aria-atomic="false">
        {toasts.map((toast) => (
          <div className="toast" key={toast.id}>
            <span
              className={cn(
                "toast__icon",
                toast.tone === "error" && "toast__icon--warn",
                toast.tone === "info" && "toast__icon--info",
              )}
            >
              <Icon name={icons[toast.tone]} size={14} />
            </span>
            <div>
              <strong>{toast.title}</strong>
              <p>{toast.message}</p>
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    return { push: () => undefined };
  }
  return context;
}
