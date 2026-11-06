# Secureddy developer entry points. `make` or `make help` lists them.

SHELL := /bin/bash
.DEFAULT_GOAL := help

PYTHON        ?= python3.13
VENV          ?= .venv
PIP           := $(VENV)/bin/pip
PY            := $(VENV)/bin/python
PYTEST        := $(VENV)/bin/pytest
RUFF          := $(VENV)/bin/ruff
PIP_CONSTRAINT := .github/constraints.txt

COMPOSE       := docker compose -f docker/docker-compose.yml
IMAGE_TAG     ?= local

# bicep: use the one on PATH, else the az CLI's copy, else /tmp/bicep (CI download)
BICEP         ?= $(shell command -v bicep 2>/dev/null || (command -v az >/dev/null 2>&1 && echo "az bicep") || echo /tmp/bicep)
BICEP_FILES   := infra/azure/main.bicep $(wildcard infra/azure/modules/*.bicep)
BICEP_PARAMS  := $(wildcard infra/azure/*.bicepparam)

.PHONY: help dev test test-integration lint fmt cov compose-up compose-down compose-logs bicep-build images clean

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

dev: $(VENV)/bin/activate ## venv + editable install + Chromium for Playwright
	PIP_CONSTRAINT=$(PIP_CONSTRAINT) $(PIP) install -e ".[dev,azure]"
	$(PY) -m playwright install --with-deps chromium
	@test -f .env || cp .env.example .env
	@echo "ok: source $(VENV)/bin/activate && reddysec init-db && reddysec web"

test: ## unit + functional tests
	$(PYTEST) -m "not integration"

test-integration: ## tests that drive a real Chromium / local servers
	$(PYTEST) -m integration

lint: ## ruff check + format check
	$(RUFF) check src tests
	$(RUFF) format --check src tests

fmt: ## ruff format + autofix
	$(RUFF) format src tests
	$(RUFF) check --fix src tests

cov: ## coverage report (fails under 85%)
	$(PYTEST) -m "not integration" --cov=reddysec --cov-branch --cov-report=term-missing --cov-report=html:htmlcov --cov-fail-under=85

compose-up: ## full local stack (postgres, web, worker, deadman) + chamber image
	@test -f .env || cp .env.example .env
	$(COMPOSE) --profile build build
	$(COMPOSE) up -d
	@echo "web: http://localhost:8000   logs: make compose-logs"

compose-down: ## stop the local stack (keeps volumes; add -v yourself to wipe)
	$(COMPOSE) down

compose-logs: ## follow logs of the local stack
	$(COMPOSE) logs -f --tail=100

bicep-build: ## compile every Bicep template and parameter file; warnings fail
	@set -euo pipefail; status=0; \
	for f in $(BICEP_FILES); do \
	  out="$$($(BICEP) build $$f --stdout 2>&1 >/dev/null || true)"; \
	  if [[ -n "$$out" ]]; then echo "$$out"; status=1; else echo "ok  $$f"; fi; \
	done; \
	for p in $(BICEP_PARAMS); do \
	  out="$$($(BICEP) build-params $$p --stdout 2>&1 >/dev/null || true)"; \
	  if [[ -n "$$out" ]]; then echo "$$out"; status=1; else echo "ok  $$p"; fi; \
	done; \
	exit $$status

images: ## build both container images locally (reddysec-app, reddysec-chamber)
	docker build -f docker/Dockerfile.app -t reddysec-app:$(IMAGE_TAG) .
	docker build -f docker/Dockerfile.chamber -t reddysec-chamber:$(IMAGE_TAG) .

clean: ## remove venv, caches, coverage output
	rm -rf $(VENV) .ruff_cache .pytest_cache htmlcov coverage.xml junit.xml
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
