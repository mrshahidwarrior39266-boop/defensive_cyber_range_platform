import { lazy, Suspense, useEffect } from "react";
import {
  BrowserRouter,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";
import Landing from "./pages/Landing";
import { ConsoleLayout } from "./components/layout/AppShell";
import { RangeProvider } from "./lib/simulation/store";
import { ToastProvider } from "./components/ui/overlays";
import { BrandMark, Icon } from "./components/ui/Icon";
import { Button } from "./components/ui/primitives";
import { useDocumentTitle } from "./lib/hooks";

const Dashboard = lazy(() => import("./pages/console/Dashboard"));
const Findings = lazy(() => import("./pages/console/Findings"));
const Incidents = lazy(() => import("./pages/console/Incidents"));
const Simulation = lazy(() => import("./pages/console/Simulation"));
const LiveFolder = lazy(() => import("./pages/console/LiveFolder"));
const MemoryPage = lazy(() => import("./pages/console/Memory"));
const Safety = lazy(() => import("./pages/console/Safety"));
const Enterprise = lazy(() => import("./pages/console/Enterprise"));
const Architecture = lazy(() => import("./pages/Architecture"));

function PageLoading() {
  return (
    <div className="page-loading">
      <div className="page-loading__card">
        <BrandMark size={38} />
        <span className="spinner-lg" />
        <span className="mono page-loading__text">Loading range console…</span>
      </div>
    </div>
  );
}

function ScrollManager() {
  const { pathname, hash } = useLocation();

  useEffect(() => {
    let timer = 0;
    const scroll = () => {
      if (hash) {
        const target = document.getElementById(hash.replace("#", ""));
        if (target) {
          target.scrollIntoView({ behavior: "smooth", block: "start" });
          return;
        }
      }
      window.scrollTo({ top: 0, behavior: "auto" });
    };
    if (hash) {
      timer = window.setTimeout(scroll, 90);
    } else {
      scroll();
    }
    return () => window.clearTimeout(timer);
  }, [pathname, hash]);

  return null;
}

function NotFound() {
  useDocumentTitle("Page not found — Citadel");
  return (
    <div className="not-found">
      <div className="not-found__orb" aria-hidden="true" />
      <div className="not-found__inner">
        <BrandMark size={42} />
        <span className="eyebrow">Error 404 · outside the range</span>
        <h1>This route left the sandbox.</h1>
        <p>
          The page you asked for is not part of the isolated workspace. Return
          to the console, or read the system architecture before heading back in.
        </p>
        <div className="not-found__actions">
          <Button to="/console" variant="primary" iconRight="arrow-right">
            Return to console
          </Button>
          <Button to="/" variant="ghost" icon="arrow-left">
            Public site
          </Button>
        </div>
        <div className="not-found__meta">
          <Icon name="lock" size={11} />
          No path escapes the sandbox
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <RangeProvider>
        <ToastProvider>
          <ScrollManager />
          <Suspense fallback={<PageLoading />}>
            <Routes>
              <Route path="/" element={<Landing />} />
              <Route path="/architecture" element={<Architecture />} />
              <Route path="/console" element={<ConsoleLayout />}>
                <Route index element={<Dashboard />} />
                <Route path="simulation" element={<Simulation />} />
                <Route path="live" element={<LiveFolder />} />
                <Route path="findings" element={<Findings />} />
                <Route path="incidents" element={<Incidents />} />
                <Route path="memory" element={<MemoryPage />} />
                <Route path="safety" element={<Safety />} />
                <Route path="enterprise" element={<Enterprise />} />
              </Route>
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </ToastProvider>
      </RangeProvider>
    </BrowserRouter>
  );
}
