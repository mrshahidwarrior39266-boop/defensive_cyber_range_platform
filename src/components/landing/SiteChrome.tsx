import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { BrandMark, Icon, Wordmark } from "../ui/Icon";
import { Button } from "../ui/primitives";
import { useScrolled } from "../../lib/hooks";
import { cn } from "../../lib/utils";

const NAV_LINKS = [
  { label: "Platform", to: "/#overview" },
  { label: "Agents", to: "/#swarms" },
  { label: "Governance", to: "/#governance" },
  { label: "Live Folder", to: "/console/live" },
  { label: "Architecture", to: "/architecture" },
];

export function SiteNav({ solid = false }: { solid?: boolean }) {
  const scrolled = useScrolled(14);
  const [open, setOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setOpen(false);
  }, [location.pathname, location.hash]);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  // Lock body scroll when mobile menu is open
  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [open]);

  return (
    <header
      className={cn(
        "site-nav",
        (scrolled || solid) && "is-solid",
        open && "is-open",
      )}
    >
      <div className="site-nav__inner">
        <Link to="/" className="site-nav__brand" aria-label="Citadel home">
          <BrandMark size={30} />
          <Wordmark />
        </Link>

        <nav className="site-nav__links" aria-label="Primary">
          {NAV_LINKS.map((link) => (
            <Link key={link.to} to={link.to} className="site-nav__link">
              {link.label}
            </Link>
          ))}
        </nav>

        <div className="site-nav__actions">
          <span className="site-nav__status">
            <span className="dot" />
            Range online
          </span>
          <Button
            to="/console"
            variant="primary"
            size="sm"
            iconRight="arrow-right"
            transition
            className="site-nav__cta"
          >
            Open console
          </Button>
          <button
            type="button"
            className="site-nav__menu"
            aria-label={open ? "Close menu" : "Open menu"}
            aria-expanded={open}
            onClick={() => setOpen((value) => !value)}
          >
            <Icon name={open ? "close" : "menu"} size={17} />
          </button>
        </div>
      </div>

      {open && (
        <>
          {/* Backdrop */}
          <div
            className="site-nav__backdrop"
            onClick={() => setOpen(false)}
            aria-hidden="true"
          />
          <div className="site-nav__sheet">
            <nav aria-label="Mobile">
              {NAV_LINKS.map((link) => (
                <Link key={link.to} to={link.to} className="site-nav__sheet-link">
                  {link.label}
                  <Icon name="arrow-up-right" size={13} />
                </Link>
              ))}
            </nav>
            <Button
              to="/console"
              variant="primary"
              block
              iconRight="arrow-right"
              transition
            >
              Open console
            </Button>
          </div>
        </>
      )}
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="site-foot">
      <div className="container">
        <div className="site-foot__grid">
          <div className="site-foot__brand">
            <Link to="/" className="site-foot__mark" aria-label="Citadel home">
              <BrandMark size={30} />
              <Wordmark />
            </Link>
            <p>
              A closed-loop defensive cyber range. Static analysis, synthesized
              patches, and independent verification — all inside a sealed sandbox.
            </p>
            <div className="site-foot__badges">
              <span className="pill">
                <Icon name="shield-check" size={11} /> Non-destructive
              </span>
              <span className="pill">
                <Icon name="lock" size={11} /> Isolated
              </span>
            </div>
          </div>

          <div className="site-foot__col">
            <h4>Platform</h4>
            <Link to="/console">Mission control</Link>
            <Link to="/console/simulation">Run simulation</Link>
            <Link to="/console/findings">Finding registry</Link>
            <Link to="/console/incidents">Patch ledger</Link>
          </div>

          <div className="site-foot__col">
            <h4>Governance</h4>
            <Link to="/console/safety">Safety controls</Link>
            <Link to="/console/safety">Audit chain</Link>
            <Link to="/console/enterprise">Mock enterprise</Link>
            <Link to="/architecture">System design</Link>
          </div>

          <div className="site-foot__col">
            <h4>Reference</h4>
            <a href="https://cwe.mitre.org/" target="_blank" rel="noreferrer">
              CWE database
            </a>
            <a
              href="https://www.python.org/dev/peps/pep-0008/"
              target="_blank"
              rel="noreferrer"
            >
              PEP 8
            </a>
            <a
              href="https://owasp.org/www-project-top-ten/"
              target="_blank"
              rel="noreferrer"
            >
              OWASP Top 10
            </a>
            <a
              href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
              target="_blank"
              rel="noreferrer"
            >
              CISA KEV
            </a>
          </div>
        </div>

        <div className="site-foot__bottom">
          <span>© {new Date().getFullYear()} Citadel Range · Research platform</span>
          <span>No live exploits · No external egress · Hash-chained by design</span>
        </div>
      </div>
    </footer>
  );
}
