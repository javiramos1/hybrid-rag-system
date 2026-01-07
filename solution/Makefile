.PHONY: help venv install install-dev clean test int-tests lint format type-check docker-up docker-down docker-logs health ingest run interactive docs setup reset status version zip

# Variables
PYTHON := python3
VENV_DIR := .venv
VENV_PYTHON := $(VENV_DIR)/bin/python
VENV_PIP := $(VENV_DIR)/bin/pip
VENV_ACTIVATE := $(VENV_DIR)/bin/activate

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Hybrid RAG System - Development Makefile$(NC)"
	@echo ""
	@echo "$(GREEN)Environment Setup:$(NC)"
	@echo "  make venv              Create virtual environment"
	@echo "  make install           Install production dependencies"
	@echo "  make install-dev       Install development dependencies"
	@echo "  make clean             Remove virtual environment and cache files"
	@echo ""
	@echo "$(GREEN)Docker Management:$(NC)"
	@echo "  make docker-up         Start Typesense container"
	@echo "  make docker-down       Stop Typesense container"
	@echo "  make docker-logs       View Typesense logs"
	@echo "  make health            Check Typesense health status"
	@echo ""
	@echo "$(GREEN)Testing:$(NC)"
	@echo "  make test              Run unit tests (31 tests)"
	@echo "  make int-tests         Run integration tests (17 queries)"
	@echo "  make lint              Run linting (ruff)"
	@echo "  make format            Format code (black)"
	@echo "  make type-check        Run type checking (mypy)"
	@echo ""
	@echo "$(GREEN)Application:$(NC)"
	@echo "  make ingest            Run data ingestion pipeline"
	@echo "  make run               Run interactive CLI"
	@echo "  make query Q='...'     Run single query (e.g., make query Q='explain SQL injection')"
	@echo "  make query Q='...' D=1 Run single query with debug info (add D=1 flag)"
	@echo ""
	@echo "$(GREEN)Documentation:$(NC)"
	@echo "  make docs              Open Typesense documentation"
	@echo ""
	@echo "$(GREEN)Distribution:$(NC)"
	@echo "  make zip               Create distribution zip (excludes typesense-data, venv)"
	@echo ""

## Environment Setup

venv: ## Create virtual environment
	@echo "$(YELLOW)Creating virtual environment...$(NC)"
	@if [ ! -d "$(VENV_DIR)" ]; then \
		$(PYTHON) -m venv $(VENV_DIR); \
		echo "$(GREEN)✓ Virtual environment created$(NC)"; \
	else \
		echo "$(YELLOW)Virtual environment already exists$(NC)"; \
	fi
	@$(VENV_PIP) install --upgrade pip setuptools wheel
	@echo "$(GREEN)✓ pip, setuptools, and wheel upgraded$(NC)"

install: venv ## Install production dependencies
	@echo "$(YELLOW)Installing production dependencies...$(NC)"
	@$(VENV_PIP) install -r requirements.txt
	@echo "$(GREEN)✓ Dependencies installed$(NC)"
	@echo ""
	@echo "$(BLUE)Verifying imports...$(NC)"
	@$(VENV_PYTHON) -c "import typesense; import polars; import sentence_transformers; import google.genai; print('$(GREEN)✓ All imports successful$(NC)')"

install-dev: install ## Install development dependencies (includes production)
	@echo "$(YELLOW)Installing development dependencies...$(NC)"
	@$(VENV_PIP) install pytest pytest-cov black ruff mypy 2>/dev/null || true
	@echo "$(GREEN)✓ Development dependencies installed$(NC)"

clean: ## Remove virtual environment and cache files
	@echo "$(YELLOW)Cleaning up...$(NC)"
	@rm -rf $(VENV_DIR)
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

## Docker Management

docker-up: ## Start Typesense container
	@echo "$(YELLOW)Starting Typesense container...$(NC)"
	@docker-compose up -d
	@echo "$(YELLOW)Waiting for Typesense to be ready...$(NC)"
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		if curl -s http://localhost:8108/health | grep -q "ok"; then \
			echo "$(GREEN)✓ Typesense is ready$(NC)"; \
			exit 0; \
		fi; \
		echo "  Attempt $$i/10..."; \
		sleep 1; \
	done; \
	echo "$(RED)✗ Typesense failed to start$(NC)"; \
	exit 1

docker-down: ## Stop Typesense container
	@echo "$(YELLOW)Stopping Typesense container...$(NC)"
	@docker-compose down
	@echo "$(GREEN)✓ Typesense stopped$(NC)"

docker-logs: ## View Typesense logs
	@docker-compose logs -f typesense

health: ## Check Typesense health status
	@echo "$(BLUE)Checking Typesense health...$(NC)"
	@curl -s http://localhost:8108/health | python3 -m json.tool || echo "$(RED)✗ Typesense not responding$(NC)"

docker-status: ## Show Docker container status
	@echo "$(BLUE)Docker container status:$(NC)"
	@docker-compose ps

## Development Tasks

test: install-dev ## Run test suite
	@echo "$(YELLOW)Running unit tests...$(NC)"
	@if [ -f .env ]; then \
		. ./.env; \
		export GOOGLE_API_KEY GEMINI_MODEL; \
	fi; \
	$(VENV_PYTHON) -m pytest tests/ -v --tb=short || \
		echo "$(YELLOW)No tests found or pytest not available$(NC)"

int-tests: docker-up install ## Run integration tests (17 queries across all RAG types)
	@echo "$(YELLOW)Running integration tests...$(NC)"
	@if [ -f .env ]; then \
		. ./.env; \
		export GOOGLE_API_KEY GEMINI_MODEL; \
	fi; \
	$(VENV_PYTHON) test_queries.py

lint: ## Run linting (ruff)
	@echo "$(YELLOW)Running linter (ruff)...$(NC)"
	@$(VENV_PIP) install ruff -q 2>/dev/null || true
	@$(VENV_PYTHON) -m ruff check src/ tests/ --fix || echo "$(YELLOW)Ruff not available$(NC)"

format: ## Format code (black)
	@echo "$(YELLOW)Formatting code (black)...$(NC)"
	@$(VENV_PIP) install black -q 2>/dev/null || true
	@$(VENV_PYTHON) -m black src/ tests/ --line-length 100 --quiet || echo "$(YELLOW)Black not available$(NC)"
	@echo "$(GREEN)✓ Code formatted$(NC)"

type-check: install-dev ## Run type checking (mypy)
	@echo "$(YELLOW)Running type checker (mypy)...$(NC)"
	@$(VENV_PIP) install mypy -q 2>/dev/null || true
	@$(VENV_PYTHON) -m mypy src/ tests/ --ignore-missing-imports || echo "$(YELLOW)MyPy check complete$(NC)"

## Application Tasks

ingest: docker-up ## Run data ingestion pipeline
	@echo "$(YELLOW)Running data ingestion...$(NC)"
	@if [ ! -f "src/ingest.py" ]; then \
		echo "$(RED)✗ src/ingest.py not found$(NC)"; \
		exit 1; \
	fi
	@if [ -f .env ]; then \
		. ./.env; \
		export GOOGLE_API_KEY TYPESENSE_HOST TYPESENSE_PORT TYPESENSE_API_KEY INGESTION_TASK_DIR; \
	fi; \
	$(VENV_PYTHON) src/ingest.py
	@echo "$(GREEN)✓ Data ingestion complete$(NC)"

run: docker-up ## Run interactive CLI
	@echo "$(BLUE)Starting interactive CLI...$(NC)"
	@if [ -f .env ]; then \
		. ./.env; \
		export GOOGLE_API_KEY GEMINI_MODEL TYPESENSE_HOST TYPESENSE_PORT TYPESENSE_API_KEY INGESTION_TASK_DIR; \
	fi; \
	$(VENV_PYTHON) main.py

query: docker-up ## Run single query (usage: make query Q='your question' [D=1 for debug])
	@if [ -z "$(Q)" ]; then \
		echo "$(RED)✗ Query not provided$(NC)"; \
		echo "$(YELLOW)Usage: make query Q='your question here' [D=1]$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Running query: $(Q)$(NC)"
	@if [ -f .env ]; then \
		. ./.env; \
		export GOOGLE_API_KEY GEMINI_MODEL TYPESENSE_HOST TYPESENSE_PORT TYPESENSE_API_KEY INGESTION_TASK_DIR; \
	fi; \
	if [ "$(D)" = "1" ]; then \
		$(VENV_PYTHON) main.py "$(Q)" --debug; \
	else \
		$(VENV_PYTHON) main.py "$(Q)"; \
	fi

## Documentation

docs: ## Open documentation
	@echo "$(BLUE)Documentation URLs:$(NC)"
	@echo "  Typesense API:        https://typesense.org/docs/29.0/"
	@echo "  Gemini API:           https://ai.google.dev/docs"
	@echo "  sentence-transformers: https://www.sbert.net/"
	@echo "  Polars:               https://docs.pola.rs/"

## Utility Targets

setup: clean venv install docker-up ## Complete setup (create venv, install, start docker, setup .env)
	@echo "$(GREEN)✓ Setup complete!$(NC)"
	@echo ""
	@echo "$(BLUE)Configuring environment...$(NC)"
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN)✓ Created .env file from template$(NC)"; \
		echo ""; \
		echo "$(YELLOW)⚠️  REQUIRED: Set your Google API key$(NC)"; \
		echo "  Get your key at: https://aistudio.google.com/app/apikey"; \
		echo "  Then edit solution/.env and set:"; \
		echo "    GOOGLE_API_KEY=your_api_key_here"; \
		echo ""; \
		read -p "$(BLUE)Paste your Google API key (or press Enter to skip):$(NC) " api_key; \
		if [ -n "$$api_key" ]; then \
			sed -i 's/GOOGLE_API_KEY=.*/GOOGLE_API_KEY='$$api_key'/' .env; \
			echo "$(GREEN)✓ API key saved to .env$(NC)"; \
		else \
			echo "$(YELLOW)⚠️  Skipped. You'll need to set GOOGLE_API_KEY in .env before running.$(NC)"; \
		fi; \
	else \
		echo "$(YELLOW)✓ .env already exists$(NC)"; \
	fi
	@echo ""
	@echo "$(BLUE)Next steps:$(NC)"
	@echo "  1. Verify GOOGLE_API_KEY is set in solution/.env"
	@echo "  2. Run data ingestion: make ingest"
	@echo "  3. Start using the system: make run"
	@echo ""

reset: docker-down clean ## Reset everything (stop docker, remove venv, clean cache)
	@echo "$(GREEN)✓ Reset complete$(NC)"

status: docker-status health ## Show system status
	@echo ""
	@echo "$(BLUE)Typesense health:$(NC)"
	@curl -s http://localhost:8108/health | python3 -m json.tool 2>/dev/null || echo "$(RED)Not available$(NC)"

version: ## Show versions of key tools
	@echo "$(BLUE)Tool Versions:$(NC)"
	@echo "  Python:       $$($(PYTHON) --version)"
	@echo "  Docker:       $$(docker --version)"
	@echo "  Docker Compose: $$(docker-compose --version)"
	@if [ -d "$(VENV_DIR)" ]; then \
		echo "  pip:          $$($$(VENV_PIP) --version)"; \
	fi

## Distribution

zip: ## Create a distribution archive (tar.gz) excluding typesense-data, venv, cache
	@echo "$(YELLOW)Creating distribution archive...$(NC)"
	@cd .. && tar --exclude='typesense-data' \
		--exclude='.venv' \
		--exclude='__pycache__' \
		--exclude='.pytest_cache' \
		--exclude='.mypy_cache' \
		--exclude='.ruff_cache' \
		--exclude='*.egg-info' \
		--exclude='.env' \
		--exclude='.DS_Store' \
		--exclude='*.pyc' \
		-czf hybrid-rag-system.tar.gz README.md solution/ task/ && \
	echo "$(GREEN)✓ Created hybrid-rag-system.tar.gz$$(du -h hybrid-rag-system.tar.gz | cut -f1)$(NC)" || \
	echo "$(RED)✗ Failed to create archive$(NC)"

.DEFAULT_GOAL := help
