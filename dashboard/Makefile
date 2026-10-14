.PHONY: dev backend frontend seed scan install-backend install-frontend help

OPSX_WORKSPACE ?= $(shell cd .. && pwd)
export OPSX_WORKSPACE
export PYTHONPATH := $(OPSX_WORKSPACE):$(PYTHONPATH)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install-backend: ## Install Python backend dependencies
	pip install -r requirements.txt

install-frontend: ## Install frontend npm dependencies
	cd web && npm install

install: install-backend install-frontend ## Install all dependencies

backend: ## Start FastAPI backend with hot reload
	uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

frontend: ## Start Vite dev server
	cd web && npm run dev

dev: ## Start both backend and frontend concurrently
	@echo "Starting backend on :8000 and frontend on :5173"
	@echo "Workspace: $(OPSX_WORKSPACE)"
	@(uvicorn src.main:app --reload --host 0.0.0.0 --port 8000 &) && cd web && npm run dev

seed: ## Seed database with CM-830 demo data
	python -m src.db.seed

scan: ## Scan openspec/changes/ for existing pipeline data
	@echo "Scanning existing changes..."
	python -c "import asyncio; from src.services.pipeline_scanner import scan_changes; from src.db.engine import get_session_factory, init_db; from src.core.config import get_settings; asyncio.run(init_db()); print('Use POST /api/v1/runs/scan instead')"

build-frontend: ## Build frontend for production
	cd web && npm run build
