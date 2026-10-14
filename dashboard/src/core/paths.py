"""Workspace-aware path resolution for the dashboard backend.

When installed via ``install.sh``, the dashboard lives at
``<project-root>/dashboard/`` and OpenSpec data lives at
``<project-root>/openspec/changes/``.  All path helpers resolve
relative ``changes_dir`` segments against the workspace root so
the backend works regardless of its working directory.
"""
from __future__ import annotations

import os
from pathlib import Path

from src.core.config import AppConfig

_DASHBOARD_DIR = Path(__file__).resolve().parents[2]


def get_workspace(cfg: AppConfig) -> Path:
    """Resolve the operator/project workspace root.

    Priority:
    1. ``OPSX_WORKSPACE`` environment variable
    2. ``config.json`` ``workspace`` field (if a real path, not a template)
    3. Parent of the dashboard directory (works for both the distribution
       repo and an installed operator repo)
    """
    env = os.environ.get("OPSX_WORKSPACE")
    if env:
        return Path(env).resolve()

    cfg_val = cfg.workspace
    if cfg_val and "${" not in cfg_val:
        p = Path(cfg_val)
        if p.is_absolute():
            return p.resolve()

    return _DASHBOARD_DIR.parent


def get_changes_dir(cfg: AppConfig) -> Path:
    """Absolute path to ``openspec/changes/``."""
    workspace = get_workspace(cfg)
    return workspace / cfg.openspec.changes_dir


def get_change_dir(cfg: AppConfig, change: str) -> Path:
    """Absolute path to a single change directory."""
    return get_changes_dir(cfg) / change
