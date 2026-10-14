import { useState, useCallback, useMemo } from "react";
import type { PhaseExecution, TaskExecution, PhaseStatus } from "@/types";
import { STATUS_ICONS } from "@/types";
import PhaseRow from "./PhaseRow";
import SubPhaseRow from "./SubPhaseRow";

interface PhaseWaterfallProps {
  phases: PhaseExecution[];
  tasks: TaskExecution[];
}

interface MergedPhaseGroup {
  label: string;
  phaseNumber: number;
  status: PhaseStatus;
  iterations: number;
  durationS: number;
  tokensIn: number;
  tokensOut: number;
  qualityScore: number;
  qualityLabel: string;
  sourcePhases: PhaseExecution[];
  subPhases: PhaseExecution[];
  isMerged: true;
}

interface SinglePhaseGroup {
  phase: PhaseExecution;
  subPhases: PhaseExecution[];
  isMerged: false;
}

type PhaseGroup = MergedPhaseGroup | SinglePhaseGroup;

function deriveMergedStatus(sources: PhaseExecution[], subs: PhaseExecution[]): PhaseStatus {
  const all = [...sources, ...subs];
  if (all.some((p) => p.status === "failed")) return "failed";
  if (all.some((p) => p.status === "running")) return "running";
  if (all.some((p) => p.status === "waiting")) return "waiting";
  if (all.length > 0 && all.every((p) => p.status === "passed" || p.status === "skipped"))
    return "passed";
  return "running";
}

function sumField(phases: PhaseExecution[], field: "tokens_in" | "tokens_out"): number {
  return phases.reduce((s, p) => s + p[field], 0);
}

export default function PhaseWaterfall({ phases, tasks }: PhaseWaterfallProps) {
  const groups: PhaseGroup[] = useMemo(() => {
    const parentPhases = phases.filter((p) => p.plan_phase === null || p.plan_phase === undefined);
    const subPhases = phases.filter((p) => p.plan_phase !== null && p.plan_phase !== undefined);

    const result: PhaseGroup[] = [];
    const stage4 = parentPhases.find((p) => p.phase_number === 4);
    const stage5 = parentPhases.find((p) => p.phase_number === 5);
    const hasStage4or5 = stage4 || stage5;

    for (const parent of parentPhases) {
      if (parent.phase_number === 4 || parent.phase_number === 5) continue;
      const children = subPhases
        .filter((s) => s.phase_number === parent.phase_number)
        .sort((a, b) => (a.plan_phase ?? 0) - (b.plan_phase ?? 0));
      result.push({ phase: parent, subPhases: children, isMerged: false });
    }

    if (hasStage4or5) {
      const sources = [stage4, stage5].filter(Boolean) as PhaseExecution[];
      const allSubs = subPhases
        .filter((s) => s.phase_number === 4 || s.phase_number === 5)
        .sort((a, b) => (a.plan_phase ?? 0) - (b.plan_phase ?? 0));
      const status = deriveMergedStatus(sources, allSubs);
      const maxIter = Math.max(...sources.map((s) => s.iteration_count), 1);
      const totalDuration = sources.reduce((s, p) => s + p.duration_s, 0);

      result.push({
        label: "SubTask Generation & Code Generation",
        phaseNumber: 4,
        status,
        iterations: maxIter,
        durationS: totalDuration,
        tokensIn: sumField(sources, "tokens_in"),
        tokensOut: sumField(sources, "tokens_out"),
        qualityScore: Math.max(...sources.map((s) => s.quality_score)),
        qualityLabel: sources.map((s) => s.quality_label).filter(Boolean).join("; ") || "",
        sourcePhases: sources,
        subPhases: allSubs,
        isMerged: true,
      });
    }

    result.sort((a, b) => {
      const aNum = a.isMerged ? a.phaseNumber : a.phase.phase_number;
      const bNum = b.isMerged ? b.phaseNumber : b.phase.phase_number;
      return aNum - bNum;
    });

    return result;
  }, [phases]);

  const [expandedStages, setExpandedStages] = useState<Set<number>>(() => new Set());
  const [expandedSubPhases, setExpandedSubPhases] = useState<Set<string>>(() => new Set());

  const expandedStagesRef = useMemo(() => {
    const running = groups.find(
      (g) => (g.isMerged ? g.status : g.phase.status) === "running"
    );
    if (running) {
      const num = running.isMerged ? running.phaseNumber : running.phase.phase_number;
      if (!expandedStages.has(num)) {
        const next = new Set(expandedStages);
        next.add(num);
        return next;
      }
    }
    return expandedStages;
  }, [groups, expandedStages]);

  const toggleStage = useCallback((phaseNumber: number) => {
    setExpandedStages((prev) => {
      const next = new Set(prev);
      if (next.has(phaseNumber)) next.delete(phaseNumber);
      else next.add(phaseNumber);
      return next;
    });
  }, []);

  const toggleSubPhase = useCallback((subPhaseId: string) => {
    setExpandedSubPhases((prev) => {
      const next = new Set(prev);
      if (next.has(subPhaseId)) next.delete(subPhaseId);
      else next.add(subPhaseId);
      return next;
    });
  }, []);

  const currentlyRunningSubPhase = useMemo(() => {
    const running = phases.find(
      (s) => s.plan_phase != null && s.status === "running"
    );
    return running?.id ?? null;
  }, [phases]);

  const expandedSubRef = useMemo(() => {
    if (currentlyRunningSubPhase && !expandedSubPhases.has(currentlyRunningSubPhase)) {
      const next = new Set(expandedSubPhases);
      next.add(currentlyRunningSubPhase);
      return next;
    }
    return expandedSubPhases;
  }, [currentlyRunningSubPhase, expandedSubPhases]);

  const tasksByPhaseId = useMemo(() => {
    const map = new Map<string, TaskExecution[]>();
    for (const t of tasks) {
      const list = map.get(t.phase_id) ?? [];
      list.push(t);
      map.set(t.phase_id, list);
    }
    return map;
  }, [tasks]);

  return (
    <section className="px-6 py-4 border-b border-terminal-border">
      <div className="text-terminal-muted text-xs uppercase tracking-wider mb-3 font-bold">
        Phase-by-Phase Telemetry &amp; Iteration Waterfall
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b-2 border-terminal-border text-terminal-muted text-xs uppercase">
              <th className="px-4 py-2">Phase</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2 text-center">Loops / Iter.</th>
              <th className="px-4 py-2 text-center">Time Taken</th>
              <th className="px-4 py-2 text-center">Tokens In / Out</th>
              <th className="px-4 py-2">Quality / Eval Output</th>
            </tr>
          </thead>
          <tbody>
            {phases.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-8 text-center text-terminal-muted text-sm"
                >
                  No phase data available.
                </td>
              </tr>
            ) : (
              groups.map((group) => {
                if (group.isMerged) {
                  const isExpanded = expandedStagesRef.has(group.phaseNumber);
                  const hasSubs = group.subPhases.length > 0;
                  return (
                    <MergedStageSection
                      key={`merged-${group.phaseNumber}`}
                      group={group}
                      isExpanded={isExpanded}
                      hasSubs={hasSubs}
                      onToggle={() => toggleStage(group.phaseNumber)}
                      expandedSubPhases={expandedSubRef}
                      onToggleSubPhase={toggleSubPhase}
                      tasksByPhaseId={tasksByPhaseId}
                    />
                  );
                } else {
                  return (
                    <PhaseRow
                      key={group.phase.id}
                      phase={group.phase}
                      subPhases={group.subPhases.length > 0 ? group.subPhases : undefined}
                    />
                  );
                }
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function MergedStageSection({
  group,
  isExpanded,
  hasSubs,
  onToggle,
  expandedSubPhases,
  onToggleSubPhase,
  tasksByPhaseId,
}: {
  group: MergedPhaseGroup;
  isExpanded: boolean;
  hasSubs: boolean;
  onToggle: () => void;
  expandedSubPhases: Set<string>;
  onToggleSubPhase: (id: string) => void;
  tasksByPhaseId: Map<string, TaskExecution[]>;
}) {
  return (
    <>
      <tr
        className="border-b border-terminal-border hover:bg-terminal-surface/50 transition-colors cursor-pointer"
        onClick={hasSubs ? onToggle : undefined}
      >
        <td className="px-4 py-2.5 text-sm">
          <span className="text-terminal-muted mr-1">4/5.</span>
          {group.label}
          {hasSubs && (
            <span className="text-terminal-muted ml-2 text-xs select-none">
              {isExpanded ? "▼" : "▶"}
            </span>
          )}
        </td>
        <td className="px-4 py-2.5 text-sm">
          {STATUS_ICONS[group.status]}{" "}
          <span
            className={
              group.status === "passed"
                ? "text-terminal-green"
                : group.status === "failed"
                ? "text-terminal-red"
                : group.status === "waiting"
                ? "text-terminal-yellow"
                : "text-terminal-text"
            }
          >
            {group.status.toUpperCase()}
          </span>
        </td>
        <td className="px-4 py-2.5 text-sm text-center">
          {group.iterations} {group.iterations > 1 ? "Iterations" : "Iteration"}
        </td>
        <td className="px-4 py-2.5 text-sm text-center">
          {formatDuration(group.durationS)}
        </td>
        <td className="px-4 py-2.5 text-sm text-center font-mono">
          {formatTokens(group.tokensIn)} / {formatTokens(group.tokensOut)}
        </td>
        <td className="px-4 py-2.5 text-sm">
          {group.qualityLabel || `Score: ${group.qualityScore}/100`}
        </td>
      </tr>
      {isExpanded &&
        group.subPhases.map((sp) => {
          const spTasks = tasksByPhaseId.get(sp.id) ?? [];
          const isSubExpanded = expandedSubPhases.has(sp.id);
          const hasTasks = spTasks.length > 0;
          return (
            <SubPhaseRow
              key={sp.id}
              phase={sp}
              tasks={spTasks}
              isExpanded={isSubExpanded}
              hasTasks={hasTasks}
              onToggle={() => onToggleSubPhase(sp.id)}
            />
          );
        })}
    </>
  );
}

function formatTokens(n: number): string {
  if (n >= 1_000) return `${Math.round(n / 1_000)}k`;
  return String(n);
}

function formatDuration(seconds: number): string {
  if (seconds === 60) return "~1m (est.)";
  if (seconds === 0) return "\u2014";
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}m ${s.toString().padStart(2, "0")}s`;
}
