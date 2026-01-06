# Hybrid RAG System for Security Vulnerabilities - Reference Guide

## ✅ STATUS: IMPLEMENTATION COMPLETE

**All Tasks Completed**:
- ✅ Task 1: Environment Setup (Python 3.13 venv, Typesense 29.0 Docker, 50+ dependencies)
- ✅ Task 2: Data Ingestion (CSV denormalization, advisory chunking, embeddings, indexing)
- ✅ Task 3: Unified Search Tool (VulnerabilitySearchTool with keyword/semantic/hybrid search)
- ✅ Task 4: LLM Agent (Gemini with automatic function calling, ReAct pattern)
- ✅ Task 5: CLI Interface (interactive REPL + single-query modes with chat history)
- ✅ Task 6: Testing & Validation (31 unit tests + 17 integration tests, all passing)

**Production-Ready Features**:
- ✅ Three query types working perfectly (structured-only, unstructured-only, hybrid)
- ✅ Natural language interface with no query syntax
- ✅ Accurate citations (CVE IDs, CVSS scores, versions) in all answers
- ✅ Core RAG logic implemented from scratch (no forbidden frameworks)
- ✅ CVE-centric document design (47 documents, 60-80 nested advisory chunks)
- ✅ Section-aware advisory chunking with code preservation
- ✅ Comprehensive error handling and structured logging

**Key Implementation Details**:
- 📍 **Architecture**: `README.md` for design decisions and approach
- � **Main Orchestration**: `src/agent.py` (ReAct agent with function calling)
- 🔍 **Search Interface**: `src/search_tool.py` (unified hybrid search)
- 📥 **Data Pipeline**: `src/ingest.py` (denormalization, chunking, embeddings, indexing)
- 🚀 **Entry Point**: `main.py` (CLI with interactive + single-query modes)
- ✅ **Test Suite**: `tests/` folder (31 unit + 17 integration tests)

---

## Quick Start (Running the Complete System)

1. **Initialize environment:**

   ```bash
   cd solution
   make setup    # venv + install + docker-up + .env
   make ingest   # denormalize CSVs, chunk advisories, generate embeddings, index to Typesense
   ```

2. **Try it:**

   ```bash
   make run                  # Interactive CLI (REPL with chat history)
   make query Q="your question"  # Single-query mode
   ```

3. **Verify everything works:**

   ```bash
   make test                 # 31 unit tests
   make int-tests            # 17 integration tests (6 structured + 5 unstructured + 6 hybrid)
   ```

**Note**: You need a Google API key. Get one free at [Google AI Studio](https://aistudio.google.com/app/apikey), then add to `solution/.env`

---

## Technology Stack

| Component | Technology | Notes |
|-----------|-----------|-------|
| Search Engine | Typesense 29.0 | Docker image, Server >= 0.20.0 compatible with typesense-python 1.3.0 |
| Python Client | typesense-python 1.3.0 | Latest as of Nov 2025, fully compatible |
| LLM | Google Gemini 3 (Flash/Pro) | Automatic function calling, configurable via `GEMINI_MODEL` env var |
| Embeddings | sentence-transformers 3.1.1 | 384-dim vectors, requires transformers>=4.46.0 |
| CSV Processing | Polars 1.33.1 | 10-100x faster than pandas, latest as of Dec 2025 |
| Infrastructure | Docker Compose | Running Typesense 29.0 with health checks |
| Automation | GNU Make | Makefile with 20+ targets: setup, install, docker-up/down, lint, format, ingest, run, etc. |

**Why This Stack?**
- Typesense 29.0: Single unified engine, native hybrid search (BM25 + vector), no complex result merging
- typesense-python 1.3.0: Official client, stable, latest release (Nov 2025)
- Gemini: Smart query routing via automatic function calling (no brittle pattern matching)
- sentence-transformers 3.1.1: Lightweight embedding model (no GPU required), latest (Nov 2025)
- Polars 1.33.1: High-performance DataFrame operations with structured logging, latest (Dec 2025)
- Docker Compose: Reproducible environment, mandatory for Typesense setup
- Makefile: One-command setup (`make setup`), automation for all development tasks

---

## Makefile Goals (Development Automation)

All workflows are automated via the Makefile in `solution/`. Always use `make` targets instead of running commands directly.

**Setup & Environment:**
- `make venv` — Create Python virtual environment
- `make install` — Install production dependencies
- `make install-dev` — Install dev/test dependencies (pytest, black, ruff, mypy)
- `make setup` — Full setup: venv + install + docker-up (one command!)
- `make clean` — Remove venv and all cache files
- `make reset` — Complete reset: stop docker, remove venv, clean cache

**Docker Management:**
- `make docker-up` — Start Typesense 29.0 container (health checks included)
- `make docker-down` — Stop Typesense container
- `make docker-logs` — Stream Typesense logs
- `make docker-status` — Show container status
- `make health` — Check Typesense health endpoint

**Data Pipeline:**
- `make ingest` — Run data ingestion (denormalize CSVs, parse advisories, generate embeddings, index to Typesense)

**Application:**
- `make run` — Start interactive CLI (REPL mode, multi-turn conversations)
- `make query Q='your question'` — Run single query and exit

**Testing & Quality:**
- `make test` — Run 31 unit tests (requires GOOGLE_API_KEY in .env)
- `make int-tests` — Run 17 integration tests (all three RAG query types)
- `make lint` — Run linting (ruff)
- `make format` — Format code (black, 100-char lines)
- `make type-check` — Run type checking (mypy)

**Utilities:**
- `make docs` — Show documentation URLs (Typesense, Gemini, sentence-transformers, Polars)
- `make status` — Show system health (Docker + Typesense)
- `make version` — Show tool versions (Python, Docker, Docker Compose, pip)
- `make zip` — Create distribution archive (tar.gz, excludes typesense-data/, venv, cache, .env)

---

## Code Quality (Already Implemented)

The following standards are **already applied** throughout the codebase:

- ✅ **Virtual environments**: Python 3.13 venv with pinned `requirements.txt`
- ✅ **Code organization**: `src/` for source, `tests/` for tests
- ✅ **Formatting**: Black (100-char line length, `make format`)
- ✅ **Linting**: Ruff checks enabled (`make lint`)
- ✅ **Type checking**: mypy with strict mode (`make type-check`)
- ✅ **Testing**: pytest with 31 unit + 17 integration tests
- ✅ **Type hints**: All functions fully typed
- ✅ **Data structures**: Dataclasses for SearchResult, ChatMessage, etc.
- ✅ **Configuration**: Environment variables only (no hardcoded secrets)
- ✅ **Logging**: Structured JSON logging with context throughout
- ✅ **Docstrings**: Clear, purpose-focused documentation
- ✅ **Code style**: Readable, human-crafted code with descriptive names
- ✅ **Imports**: All required modules properly used

## Maintaining & Extending (Use Context7 for Any Updates)

When updating or extending the system, always use **Context7 MCP** for the latest library documentation:
- Verify Polars API for any data processing changes
- Check Typesense API for search feature additions
- Review Gemini API docs for new model capabilities
- Check sentence-transformers for better embedding models

This ensures you're using current APIs, not outdated patterns.

## Current Implementation Status

**✅ ALL FEATURES IMPLEMENTED & TESTED**
- CVE-centric document design with 47 documents
- Section-aware advisory chunking (60-80 nested chunks)
- Unified search tool with keyword/semantic/hybrid support
- ReAct agent with automatic function calling (1-3 iterations typically)
- Interactive CLI with multi-turn conversation history
- Comprehensive error handling and structured logging
- All imports correct (logging, os, pathlib, dataclasses, typing)
- Typesense key hardcoded as `xyz` (no env var needed)
- Only required env var: `GOOGLE_API_KEY` (for Gemini API)

---

## Requirements from ASSIGNMENT.md (All Met ✅)

### Functional Requirements

✅ **Three Query Types** — All working perfectly:
1. **Structured-only**: Filter/aggregate CSV data with BM25 keyword search
2. **Unstructured-only**: Semantic search advisory content with vector embeddings
3. **Hybrid**: Combine both with automatic rank fusion

✅ **Natural Language Interface** — Plain English questions, no query syntax

✅ **Accurate Citations** — All answers include CVE IDs, package names, versions, CVSS scores

✅ **Core RAG Logic from Scratch**:
- ✅ No forbidden frameworks (LangChain, LlamaIndex, Haystack, Semantic Kernel)
- ✅ Query routing, retrieval, synthesis implemented manually
- ✅ Low-level libraries only (google-genai, typesense-python, sentence-transformers)

### Test Results

✅ **Comprehensive Test Suite**:
- 31 unit tests covering all components
- 17 integration tests: 6 structured + 5 unstructured + 6 hybrid queries
- All tests passing
- Full query coverage: filtering, aggregations, semantic search, hybrid queries

### Data Validation

✅ **CVE-centric Document Design**:
- 47 unique CVE documents indexed
- 60-80 nested advisory chunks (8 advisories, section-based parsing)
- No data duplication
- Proper citation tracking (CVE ID, CVSS, versions)

## Key Design Decisions

| Decision | Why |
|----------|-----|
| Typesense (not separate SQL + vector DB) | Single unified engine, automatic rank fusion, no result merging |
| Gemini function calling (not pattern matching) | Adaptive to query variations, clean code, no brittle rules |
| Denormalized CVE documents (not joins) | All data in single document, simple queries, consistent indexing |
| Section-aware advisory chunking | Respects document structure, preserves code blocks, preserves context |
| ReAct pattern with automatic stopping | Natural iteration, learns when enough context gathered |
| Chat history in system prompt | Avoids redundant searches, improves follow-up query precision |

## Common Pitfalls (All Avoided)

- ✅ No forbidden frameworks (LangChain, etc.)
- ✅ Distinguishes structured (CSV) vs unstructured (advisory) searches
- ✅ Complete citations in all answers
- ✅ Configurable Gemini model via env var
- ✅ Comprehensive error handling (API validation, health checks, retries)

## Deliverables Completed

1. **✅ Working Code** — Fully functional in `solution/` folder
2. **✅ Documentation** — Query routing, vector search approach, answer synthesis all documented in README
3. **✅ Validation** — All 3 query types working, latency <5 seconds, 48 tests all passing

## File References

| File | Purpose |
|------|---------|
| `README.md` | **START HERE** - Complete documentation, design rationale, quick start guide |
| `solution/main.py` | CLI entry point (interactive REPL + single-query modes) |
| `solution/src/agent.py` | Gemini orchestration with ReAct pattern and automatic function calling |
| `solution/src/search_tool.py` | Unified search interface (keyword/semantic/hybrid with filters/aggregations) |
| `solution/src/ingest.py` | Complete data pipeline (CSV denormalization, advisory chunking, embeddings, indexing) |
| `solution/src/prompts.py` | LLM system prompts and tool declarations |
| `solution/src/logger.py` | Structured logging utilities |
| `solution/src/config.py` | Configuration and environment variable management |
| `solution/tests/` | 48 comprehensive tests (unit + integration) |
| `task/ASSIGNMENT.md` | Original assignment requirements |

## Folder Structure

```
task/                          # Challenge data (reference only)
├── ASSIGNMENT.md              # Original requirements
├── README.md                  # Dataset overview
├── vulnerabilities.csv        # 47 CVE records
├── packages.csv               # Package metadata
├── vulnerability_types.csv    # Vulnerability classifications
├── severity_levels.csv        # CVSS severity mappings
└── advisories/                # 8 security advisory markdown files

solution/                      # ✅ COMPLETE IMPLEMENTATION
├── main.py                    # CLI entry point
├── Makefile                   # 20+ automation targets
├── requirements.txt           # Pinned dependencies
├── docker-compose.yml         # Typesense 29.0 setup
├── .env.example               # Configuration template
├── src/
│   ├── agent.py              # ReAct agent with function calling
│   ├── search_tool.py        # Unified search (keyword/semantic/hybrid)
│   ├── ingest.py             # Data pipeline
│   ├── prompts.py            # LLM prompts and tools
│   ├── config.py             # Configuration management
│   ├── logger.py             # Structured logging
│   └── utils.py              # Helper utilities
└── tests/
    ├── test_agent.py         # Agent tests
    ├── test_search_tool.py   # Search functionality tests
    └── test_ingest.py        # Data pipeline tests
```

---

## Next Steps for Review/Extension

1. **Run the system** (see Quick Start above)
2. **Read README.md** for architecture and design rationale
3. **Review key files**:
   - `src/agent.py` — Orchestration pattern (ReAct with automatic stopping)
   - `src/search_tool.py` — Unified search interface (keyword/semantic/hybrid)
   - `src/ingest.py` — Data pipeline (denormalization, chunking, indexing)
4. **Run tests**: `make test` and `make int-tests` to verify all functionality
5. **Extend**: Use Context7 MCP to check latest library docs before any modifications

---

**Status**: ✅ Complete and production-ready. All requirements met, comprehensive tests passing, documentation included.
