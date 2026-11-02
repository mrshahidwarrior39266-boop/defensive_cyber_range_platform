import { useSearchParams } from "react-router-dom";
import {
  Button,
  PageHeader,
  Panel,
  Pill,
  SeverityPill,
} from "../../components/ui/primitives";
import { CodeBlock } from "../../components/ui/code";
import { Icon } from "../../components/ui/Icon";
import { useDocumentTitle } from "../../lib/hooks";
import {
  BLUEPRINTS,
  CWE_LABELS,
  CWE_ORDER,
  GROUND_TRUTH,
  PROJECT_FILES,
  SURFACES,
  fileSourceFor,
  locateLine,
} from "../../lib/simulation/project";
import { useRange } from "../../lib/simulation/store";
import { cn, formatMs } from "../../lib/utils";
import "../../styles/pages.css";

const SURFACE_CWE: Record<string, "CWE-89" | "CWE-79" | "CWE-862"> = {
  search_directory: "CWE-89",
  render_search_banner: "CWE-79",
  export_confidential_documents: "CWE-862",
};

export default function Enterprise() {
  useDocumentTitle("Mock enterprise — Citadel");
  const { state } = useRange();
  const [params, setParams] = useSearchParams();

  const requested = params.get("file");
  const file =
    PROJECT_FILES.find((item) => item.path === requested) ??
    PROJECT_FILES.find((item) => item.path === "mock_enterprise/service.py")!;
  const requestedLine = Number(params.get("line"));
  const source = fileSourceFor(file.path, state.remediatedCwes);
  const lineCount = source.split("\n").length;

  const seeded = CWE_ORDER.map((cwe) => BLUEPRINTS[cwe]).filter(
    (blueprint) => blueprint.filePath === file.path,
  );
  const marks = seeded.map((blueprint) =>
    locateLine(source, blueprint.evidenceLocator ?? blueprint.locator, 1),
  );
  if (file.path === requested && Number.isFinite(requestedLine)) {
    marks.push(requestedLine);
  }

  const openCwes = file.seededCwes.filter(
    (cwe) => !state.remediatedCwes.includes(cwe),
  );

  const guardedSurfaces = SURFACES.filter((surface) => {
    const surfaceCwe = SURFACE_CWE[surface.functionName];
    return (
      surface.hasAuthGuard ||
      Boolean(surfaceCwe && state.remediatedCwes.includes(surfaceCwe))
    );
  }).length;

  const selectFile = (path: string) => {
    const next = new URLSearchParams();
    next.set("file", path);
    setParams(next, { replace: true });
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Target environment"
        title="Mock enterprise"
        description="A deliberately vulnerable corporate portal, isolated on an internal bridge network. Inspect every module the swarm audits, including the judge's ground truth."
        actions={
          <>
            <Button
              to="/console/findings"
              variant="quiet"
              size="sm"
              icon="scan"
            >
              View findings
            </Button>
            <Button
              to="/console/simulation"
              variant="primary"
              size="sm"
              icon="play"
            >
              Run campaign
            </Button>
          </>
        }
        meta={
          <>
            <Pill tone="live" icon="server">
              {GROUND_TRUTH.application}
            </Pill>
            <Pill icon="lock">{GROUND_TRUTH.version}</Pill>
            <Pill tone={openCwes.length ? "critical" : "live"} icon={openCwes.length ? "alert" : "shield-check"}>
              {openCwes.length} open classes in this file
            </Pill>
          </>
        }
      />

      <section className="enterprise-banner">
        <div className="enterprise-banner__mark">
          <Icon name="server" size={22} />
        </div>
        <div className="enterprise-banner__copy">
          <span className="eyebrow">AcmeCorp Internal Portal</span>
          <h2>
            {PROJECT_FILES.length} modules, {CWE_ORDER.length} seeded weakness
            classes, zero external egress.
          </h2>
          <p>
            The workspace source below is live: after a campaign deploys and
            verifies a patch, the remediated file is what you see here.
          </p>
        </div>
        <dl className="enterprise-banner__facts">
          <div>
            <dt>Network</dt>
            <dd className="mono">isolated_range_net · internal</dd>
          </div>
          <div>
            <dt>Service alias</dt>
            <dd className="mono">mock-enterprise</dd>
          </div>
          <div>
            <dt>Detection SLA</dt>
            <dd className="mono">{formatMs(1500)}</dd>
          </div>
        </dl>
      </section>

      <div className="enterprise-layout">
        <Panel
          className="file-tree"
          title="Workspace"
          subtitle="simulation_artifacts/workspace"
          actions={
            <span className="mono registry-count">{PROJECT_FILES.length} files</span>
          }
        >
          <div className="file-list">
            {PROJECT_FILES.map((item) => {
              const active = item.path === file.path;
              const fixed =
                item.seededCwes.length > 0 &&
                item.seededCwes.every((cwe) =>
                  state.remediatedCwes.includes(cwe),
                );
              return (
                <button
                  type="button"
                  key={item.path}
                  className={cn("file-row", active && "is-active")}
                  onClick={() => selectFile(item.path)}
                >
                  <span className="file-row__icon">
                    <Icon
                      name={item.language === "json" ? "box" : "file-code"}
                      size={15}
                    />
                  </span>
                  <span className="file-row__body">
                    <b>{item.name}</b>
                    <span className="mono">
                      {item.seededCwes.length
                        ? item.seededCwes.join(" · ")
                        : "no seeded CWE"}
                    </span>
                  </span>
                  {item.seededCwes.length > 0 ? (
                    <span
                      className={cn(
                        "file-row__dot",
                        fixed ? "is-fixed" : "is-open",
                      )}
                      title={fixed ? "Remediated" : "Open weakness"}
                    />
                  ) : (
                    <span className="file-row__dot is-clean" title="Clean" />
                  )}
                </button>
              );
            })}
          </div>
          <div className="file-tree__foot">
            <Icon name="info" size={12} />
            <span>
              Source is rendered from the staging workspace, not a static
              snapshot.
            </span>
          </div>
        </Panel>

        <Panel
          className="source-panel"
          flush
          title={file.path}
          subtitle={file.summary}
          actions={
            <div className="row gap-8">
              <Pill tone={openCwes.length ? "critical" : "live"}>
                {openCwes.length ? `${openCwes.length} seeded` : "remediated"}
              </Pill>
              <span className="mono registry-count">
                {lineCount} lines · {file.language}
              </span>
            </div>
          }
        >
          {seeded.length > 0 && (
            <div className="seed-callouts">
              {seeded.map((blueprint) => {
                const fixed = state.remediatedCwes.includes(blueprint.cweId);
                return (
                  <div
                    key={blueprint.cweId}
                    className={cn("seed-callout", fixed && "is-fixed")}
                  >
                    <div className="seed-callout__head">
                      <SeverityPill severity={blueprint.severity} />
                      <b>
                        {blueprint.cweId} · {blueprint.title}
                      </b>
                      <Pill tone={fixed ? "live" : "high"}>
                        {fixed ? "verified fix" : "seeded"}
                      </Pill>
                    </div>
                    <p>
                      {fixed
                        ? "A validated patch has been deployed and independently re-audited in this workspace."
                        : blueprint.description}
                    </p>
                    <div className="seed-callout__meta mono">
                      <span>{blueprint.endpoint}</span>
                      <span>CVSS {blueprint.cvssScore.toFixed(1)}</span>
                      <span>{blueprint.nodeType}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          <div className="source-shell">
            <CodeBlock
              filename={`${file.path}:1`}
              language={file.language}
              code={source}
              markLines={marks}
              maxHeight={620}
            />
          </div>
        </Panel>
      </div>

      <div className="enterprise-bottom">
        <Panel
          title="Seeded vulnerability classes"
          subtitle="The ground truth the judge scores against"
          actions={
            <span className="mono registry-count">
              {state.remediatedCwes.length}/{CWE_ORDER.length} remediated
            </span>
          }
        >
          <div className="seeded-grid">
            {CWE_ORDER.map((cwe) => {
              const blueprint = BLUEPRINTS[cwe];
              const fixed = state.remediatedCwes.includes(cwe);
              return (
                <div
                  key={cwe}
                  className={cn("seeded-card", fixed && "is-fixed")}
                >
                  <header>
                    <span className="tag">{cwe}</span>
                    <span
                      className={cn(
                        "state-chip",
                        fixed ? "is-fixed" : "is-open",
                      )}
                    >
                      {fixed ? "remediated" : "seeded"}
                    </span>
                  </header>
                  <b>{CWE_LABELS[cwe]}</b>
                  <p>{blueprint.remediationGuidance}</p>
                  <div className="seeded-card__meta mono">
                    <span>{blueprint.filePath.replace("mock_enterprise/", "")}</span>
                    <span>{blueprint.endpoint}</span>
                  </div>
                  <div className="seeded-card__sev">
                    <SeverityPill severity={blueprint.severity} />
                    <span className="mono">{blueprint.cvssScore.toFixed(1)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel
          flush
          title="Attack surface"
          subtitle="Functions mapped by the AST surface scan"
          actions={
            <Pill
              tone={guardedSurfaces === SURFACES.length ? "live" : "critical"}
              icon={guardedSurfaces === SURFACES.length ? "shield-check" : "alert"}
            >
              {guardedSurfaces}/{SURFACES.length} surfaces guarded
            </Pill>
          }
        >
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Handler</th>
                  <th>Parameters</th>
                  <th>Guard</th>
                </tr>
              </thead>
              <tbody>
                {SURFACES.map((surface) => {
                  const surfaceCwe = SURFACE_CWE[surface.functionName];
                  const isGuarded =
                    surface.hasAuthGuard ||
                    Boolean(surfaceCwe && state.remediatedCwes.includes(surfaceCwe));
                  return (
                    <tr key={`${surface.endpoint}-${surface.functionName}`}>
                      <td className="cell-mono strong">{surface.endpoint}</td>
                      <td className="cell-mono">{surface.functionName}</td>
                      <td className="cell-mono muted">
                        {surface.parameters.length
                          ? surface.parameters.join(", ")
                          : "—"}
                      </td>
                      <td>
                        <span
                          className={cn(
                            "state-chip",
                            isGuarded ? "is-fixed" : "is-blocked",
                          )}
                        >
                          {isGuarded ? "guarded" : "missing"}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}
