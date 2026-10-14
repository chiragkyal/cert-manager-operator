from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.json"


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    log_level: str = "info"


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///data/dashboard.db"
    echo: bool = False


class SSEConfig(BaseModel):
    retry_ms: int = 3000
    heartbeat_interval_s: int = 15
    max_connections: int = 50


class VertexAIConfig(BaseModel):
    enabled: bool = False
    project_id: str = "your-gcp-project"
    location: str = "us-central1"
    model_id: str = "gemini-2.5-pro"
    max_output_tokens: int = 2048
    temperature: float = 0.1
    credentials_path: str | None = None


class TelemetryConfig(BaseModel):
    endpoint: str = "http://localhost:8000/api/v1/events"
    batch_size: int = 10
    flush_interval_s: int = 5
    bus_dir: str = "openspec/changes"
    poll_interval_s: float = 3.0


class TokenCost(BaseModel):
    input: float = 2.0
    output: float = 8.0


class MetricsConfig(BaseModel):
    token_cost_per_million: dict[str, TokenCost] = Field(default_factory=dict)
    max_self_correction_loops: int = 5
    phase_timeout_s: int = 600
    phase5_close_on: str = "implementation_report"

    def cost_for_model(self, model_id: str) -> TokenCost:
        return self.token_cost_per_million.get(
            model_id,
            self.token_cost_per_million.get("default", TokenCost()),
        )


class FallbacksConfig(BaseModel):
    default_compliance_index: float = 0
    default_agent_success_rate: float = 0
    default_gate_pass_rate: float = 0
    default_fidelity_score: float = 0
    empty_state_message: str = "No pipeline runs yet. Start a change with /opsx-new."
    sse_reconnect_ms: int = 5000
    max_log_entries: int = 500


class OpenSpecConfig(BaseModel):
    changes_dir: str = "openspec/changes"
    schemas_dir: str = "schemas/openspec-agile-workflow"
    eval_results_pattern: str = "eval-results/*.yaml"


class AppConfig(BaseModel):
    workspace: str = ""
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    sse: SSEConfig = Field(default_factory=SSEConfig)
    vertex_ai: VertexAIConfig = Field(default_factory=VertexAIConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    fallbacks: FallbacksConfig = Field(default_factory=FallbacksConfig)
    openspec: OpenSpecConfig = Field(default_factory=OpenSpecConfig)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: Path | None = None) -> AppConfig:
    config_path = path or _CONFIG_PATH
    if config_path.exists():
        with open(config_path) as f:
            raw = json.load(f)
        return AppConfig.model_validate(raw)
    return AppConfig()


_settings: AppConfig | None = None


def get_settings() -> AppConfig:
    global _settings
    if _settings is None:
        _settings = load_config()
    return _settings
