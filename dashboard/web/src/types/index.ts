export type RunStatus = "running" | "waiting_for_human" | "completed" | "failed";

export type PhaseName =
  | "spec_understanding"
  | "repo_assessment"
  | "arch_planning"
  | "subtask_creation"
  | "code_generation";

export type PhaseStatus =
  | "running"
  | "passed"
  | "failed"
  | "waiting"
  | "skipped";

export type TaskStatus =
  | "pending"
  | "running"
  | "passed"
  | "failed"
  | "waiting"
  | "skipped";

export type EventType =
  | "tool_call"
  | "harness_alert"
  | "self_correction"
  | "state_machine";

export interface PipelineRun {
  id: string;
  change_name: string;
  jira_key: string;
  branch: string;
  status: RunStatus;
  total_tokens_in: number;
  total_tokens_out: number;
  total_cost_usd: number;
  started_at: string;
  completed_at: string | null;
  created_at: string;
}

export interface PhaseExecution {
  id: string;
  run_id: string;
  phase_number: number;
  phase_name: PhaseName;
  status: PhaseStatus;
  iteration_count: number;
  duration_s: number;
  tokens_in: number;
  tokens_out: number;
  model_id: string;
  quality_score: number;
  quality_label: string;
  plan_phase: number | null;
  started_at: string;
  completed_at: string | null;
}

export interface TaskExecution {
  id: string;
  run_id: string;
  phase_id: string;
  task_id: string;
  task_title: string;
  agent_id: string;
  status: TaskStatus;
  self_correction_loops: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
  token_attribution?: string | null;
  metadata_json?: Record<string, unknown> | null;
  started_at: string | null;
  completed_at: string | null;
}

export interface AgentEvent {
  id: string;
  run_id: string;
  task_id: string | null;
  timestamp: string;
  agent_id: string;
  event_type: EventType;
  message: string;
  metadata_json: Record<string, unknown> | null;
}

export interface GlobalHealthMetrics {
  total_tokens_consumed: number;
  total_run_cost_usd: number;
  cumulative_wall_time_s: number;
  compliance_index: number;
  gate_passing_rate: number;
  human_rejection_rate: number;
  total_refinement_iterations: number;
  agent_success_rate: number;
  tasks_passed: number;
  tasks_total: number;
}

export interface TokenBurnEntry {
  agent_id: string;
  tokens: number;
  cost_usd: number;
}

export interface TokenBurnOut {
  entries: TokenBurnEntry[];
  total_tokens: number;
  total_cost_usd: number;
}

export interface ArtifactEditEntry {
  artifact_id: string;
  phase_name: string;
  eval_refinements: number;
  feedback_rounds: number;
  total_edits: number;
}

export interface ArtifactEditsOut {
  artifacts: ArtifactEditEntry[];
  total_edits: number;
}

export interface RunReportOut {
  exported_at: string;
  run: PipelineRun;
  phases: PhaseExecution[];
  tasks: TaskExecution[];
  events: AgentEvent[];
  global_health: GlobalHealthMetrics;
  token_burn: TokenBurnOut;
  artifact_edits: ArtifactEditsOut;
}

export interface SSEEvent {
  event: string;
  data: Record<string, unknown>;
}

export const PHASE_DISPLAY_NAMES: Record<PhaseName, string> = {
  spec_understanding: "Spec Understanding",
  repo_assessment: "Repo Assessment (MCP)",
  arch_planning: "Architectural Planning",
  subtask_creation: "Sub-Tasks Creation (DAG)",
  code_generation: "Code Generation / Harness",
};

export const STATUS_ICONS: Record<PhaseStatus, string> = {
  passed: "✅",
  failed: "❌",
  running: "🔄",
  waiting: "🟡",
  skipped: "⏭️",
};
