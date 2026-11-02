import { useMemo } from "react";
import {
  Button,
  EmptyState,
  PageHeader,
  Panel,
  Pill,
  Stat,
} from "../../components/ui/primitives";
import { Meter } from "../../components/ui/viz";
import { Icon } from "../../components/ui/Icon";
import { useToast } from "../../components/ui/overlays";
import { useActionLock, useDocumentTitle } from "../../lib/hooks";
import {
  latestRound,
} from "../../lib/simulation/engine";
import {
  BLUEPRINTS,
  CWE_LABELS,
  CWE_ORDER,
  GROUND_TRUTH,
} from "../../lib/simulation/project";
import { useRange } from "../../lib/simulation/store";
import { cn, formatDateTime, formatPct } from "../../lib/utils";
import "../../styles/pages.css";

function downloadSnapshot(payload: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export default function Memory() {
  useDocumentTitle("Shared memory — Citadel");
  const { state, verifyChain } = useRange();
  const { push } = useToast();
  const exportLock = useActionLock();

  const latest = latestRound(state);
  const openCwes = useMemo(
    () => Array.from(new Set((latest?.findings ?? []).map((item) => item.cweId))),
    [latest],
  );
  const fixedCwes = state.remediatedCwes;
  const lessons = state.lessons;
  const episodes = state.memoryRounds;
  const chain = verifyChain();

  const lessonRecall = lessons.length
    ? (lessons.filter((lesson) => lesson.remediated).length / lessons.length) * 100
    : 0;
  const coverage = (fixedCwes.length / CWE_ORDER.length) * 100;

  const recalledForOpen = openCwes.map((cwe) => ({
    cwe,
    lesson: lessons.find((lesson) => lesson.cweId === cwe),
    blueprint: BLUEPRINTS[cwe],
  }));

  const handleExport = () => {
    downloadSnapshot(
      {
        application: GROUND_TRUTH.application,
        exported_at: new Date().toISOString(),
        store: "simulation_artifacts/simulation_memory.db",
        rounds: episodes,
        lessons_learned: lessons,
        remediated_cwes: fixedCwes,
        audit_entries: state.audit.length,
      },
      "simulation-memory-snapshot.json",
    );
    push({
      title: "Memory snapshot exported",
      message: `${episodes.length} episodes and ${lessons.length} lessons written to JSON.`,
      tone: "success",
    });
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Cross-round learning"
        title="Shared memory"
        description="The range remembers. Every round writes findings, applied patches and verification outcomes into a persistent store, then recalls those lessons when the same weakness resurfaces."
        actions={
          <>
            <Button
              variant="quiet"
              size="sm"
              icon="download"
              onClick={() => void exportLock.run(handleExport)}
            >
              Export memory
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
            <Pill icon="clock">{episodes.length} recorded episodes</Pill>
            <Pill icon="book">{lessons.length} lessons retained</Pill>
            <Pill tone={chain.valid ? "live" : "critical"} icon="shield-check">
              audit continuity {chain.valid ? "verified" : "broken"}
            </Pill>
          </>
        }
      />

      <div className="memory-layout">
        <Panel
          className="memory-episodes"
          title="Episodic memory"
          subtitle="One record per completed round, written after verification"
          actions={<span className="mono registry-count">simulation_memory.db</span>}
        >
          {episodes.length ? (
            <ol className="episode-list">
              {episodes.map((episode) => (
                <li key={episode.roundNum} className="episode">
                  <span className="episode__rail">
                    <span className="episode__dot" />
                  </span>
                  <div className="episode__body">
                    <div className="episode__head">
                      <b>Round {String(episode.roundNum).padStart(2, "0")}</b>
                      <span className="mono muted">
                        {formatDateTime(episode.recordedAt)}
                      </span>
                    </div>
                    <div className="episode__stats">
                      <span>
                        <em>{episode.findingsDiscovered}</em> findings
                      </span>
                      <span>
                        <em>{episode.patchesDeployed}</em> deployed
                      </span>
                      <span>
                        <em>{episode.verifiedRemediated}</em> verified fixed
                      </span>
                    </div>
                    <div className="episode__score">
                      <div className="episode__bar">
                        <span style={{ width: `${episode.postureScore}%` }} />
                      </div>
                      <b>{formatPct(episode.postureScore, 0)}</b>
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <EmptyState
              icon="clock"
              title="No episodes recorded"
              description="Memory is written when a round completes verification."
              action={
                <Button to="/console/simulation" variant="primary" size="sm" icon="play">
                  Launch campaign
                </Button>
              }
            />
          )}

          <div className="memory-note">
            <Icon name="lock" size={13} />
            <span>
              {chain.valid
                ? `All ${state.audit.length} audit entries hash-chain from genesis. Memory records are only written after staging validation and post-deploy verification.`
                : `Audit chain failed at entry ${chain.brokenAt}. Memory contents cannot be trusted until the ledger is restored.`}
            </span>
          </div>
        </Panel>

        <div className="memory-side">
          <Panel title="Recall quality" subtitle="How usable the memory is right now">
            <div className="recall">
              <span className="recall__value">{formatPct(lessonRecall, 0)}</span>
              <span className="recall__label">
                of retained lessons ended in a verified fix
              </span>
            </div>
            <div className="recall__meters">
              <Meter
                label="Known CWE classes remediated"
                value={Math.round(coverage)}
                tone="mint"
              />
              <Meter
                label="Lessons with verified outcome"
                value={Math.round(lessonRecall)}
                tone="ice"
              />
              <Meter
                label="Ledger chain continuity"
                value={chain.valid ? 100 : 0}
                tone={chain.valid ? "violet" : "rose"}
              />
            </div>
          </Panel>

          <Panel title="Store profile" subtitle="Runtime configuration">
            <dl className="store-facts">
              <div>
                <dt>Engine</dt>
                <dd>SharedMemoryStore · SQLite</dd>
              </div>
              <div>
                <dt>Location</dt>
                <dd className="mono">simulation_artifacts/simulation_memory.db</dd>
              </div>
              <div>
                <dt>Target</dt>
                <dd>{GROUND_TRUTH.application}</dd>
              </div>
              <div>
                <dt>Baseline version</dt>
                <dd className="mono">{GROUND_TRUTH.version}</dd>
              </div>
              <div>
                <dt>Scope</dt>
                <dd>Round outcomes · lessons · patch history</dd>
              </div>
              <div>
                <dt>Egress</dt>
                <dd>None — loopback only</dd>
              </div>
            </dl>
          </Panel>
        </div>

        <div className="memory-stats">
          <Stat
            label="Episodes"
            value={episodes.length}
            hint="Completed, verified rounds"
            icon="clock"
          />
          <Stat
            label="Patches deployed"
            value={episodes.reduce(
              (sum, item) => sum + item.patchesDeployed,
              0,
            )}
            hint="Applied to the sandbox workspace"
            icon="git-branch"
            accent="violet"
          />
          <Stat
            label="Verified fixes"
            value={episodes.reduce(
              (sum, item) => sum + item.verifiedRemediated,
              0,
            )}
            hint="Confirmed by independent re-audit"
            icon="shield-check"
            accent="mint"
          />
          <Stat
            label="Open classes"
            value={openCwes.length}
            hint={`In round ${String(latest?.roundNum ?? 0).padStart(2, "0")}`}
            icon="alert"
            accent={openCwes.length ? "amber" : "mint"}
          />
        </div>
      </div>

      <Panel
        flush
        title="Lessons learned"
        subtitle="What prior rounds taught the swarm"
        actions={
          <span className="mono registry-count">{lessons.length} entries</span>
        }
      >
        {lessons.length ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Round</th>
                  <th>Class</th>
                  <th>Lesson</th>
                  <th>File</th>
                  <th>Patch</th>
                  <th>Outcome</th>
                </tr>
              </thead>
              <tbody>
                {lessons.map((lesson) => (
                  <tr key={`${lesson.roundNum}-${lesson.id}`}>
                    <td className="cell-mono">
                      {String(lesson.roundNum).padStart(2, "0")}
                    </td>
                    <td>
                      <span className="tag">{lesson.cweId}</span>
                    </td>
                    <td className="cell-wrap">{lesson.lessonSummary}</td>
                    <td className="cell-mono">
                      {lesson.filePath.replace("mock_enterprise/", "")}
                    </td>
                    <td className="cell-mono">{lesson.patchId}</td>
                    <td>
                      <span
                        className={cn(
                          "state-chip",
                          lesson.remediated ? "is-fixed" : "is-blocked",
                        )}
                      >
                        {lesson.remediated ? "verified" : "residual"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon="book"
            title="No lessons retained"
            description="Lessons are recorded when a round reaches verification."
          />
        )}
      </Panel>

      <div className="memory-bottom">
        <Panel
          title="Carry-forward plan"
          subtitle="What memory recommends for the next campaign"
        >
          {openCwes.length ? (
            <div className="recall-list">
              {recalledForOpen.map(({ cwe, lesson, blueprint }) => (
                <div className="recall-item" key={cwe}>
                  <span className="recall-item__icon">
                    <Icon name={lesson ? "book" : "alert"} size={15} />
                  </span>
                  <div>
                    <div className="recall-item__head">
                      <b>
                        {cwe} · {CWE_LABELS[cwe]}
                      </b>
                      <Pill tone={lesson ? "live" : "high"}>
                        {lesson ? "memory hit" : "no prior lesson"}
                      </Pill>
                    </div>
                    <p>
                      {lesson
                        ? lesson.lessonSummary
                        : blueprint.remediationGuidance}
                    </p>
                    <span className="mono muted">{blueprint.filePath}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="memory-converged">
              <span className="memory-converged__icon">
                <Icon name="shield-check" size={22} />
              </span>
              <div>
                <b>Memory is converged</b>
                <p>
                  Round {String(latest?.roundNum ?? 0).padStart(2, "0")} returned
                  no findings, and every known class has a verified fix on record.
                  Carry-forward guidance is regression-focused:
                </p>
                <ul>
                  <li>Re-run the same campaign to prove the fixes are stable.</li>
                  <li>Keep strict manual approval for any change to auth paths.</li>
                  <li>Rotate in a new seeded workspace before the next exercise.</li>
                </ul>
              </div>
            </div>
          )}
        </Panel>

        <Panel
          title="Remediation memory"
          subtitle="State of each seeded CWE class"
        >
          <div className="cwe-memory">
            {CWE_ORDER.map((cwe) => {
              const isOpen = openCwes.includes(cwe);
              const timeline = lessons.filter((lesson) => lesson.cweId === cwe);
              return (
                <div
                  className={cn("cwe-memory__row", isOpen ? "is-open" : "is-fixed")}
                  key={cwe}
                >
                  <span className="tag">{cwe}</span>
                  <div className="cwe-memory__body">
                    <b>{CWE_LABELS[cwe]}</b>
                    <span className="mono">
                      {BLUEPRINTS[cwe].filePath.replace("mock_enterprise/", "")}
                    </span>
                  </div>
                  <span className="mono muted">{timeline.length} lessons</span>
                  <span className={cn("state-chip", isOpen ? "is-review" : "is-fixed")}>
                    {isOpen ? "open" : "fixed"}
                  </span>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>
    </div>
  );
}
