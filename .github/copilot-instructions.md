# Hybrid RAG System for Security Vulnerabilities - Implementation Guide

## ✅ STATUS: Task 1 Complete - Environment Setup Ready

**Task 1: Environment Setup - COMPLETE**
- ✅ Python 3.13 virtual environment created (.venv/)
- ✅ Typesense 29.0 running via Docker Compose (port 8108)
- ✅ All 50+ dependencies installed and verified
- ✅ Makefile with 20+ automation targets created
- ✅ Configuration templates (.env.example, .gitignore)
- ✅ All imports working and validated

**Remaining Tasks**: Task 2-6 in `solution/` folder (Data Ingestion, Search Tool, LLM Agent, CLI, Testing)

**What Exists (READ-ONLY)**:
- 📋 **Requirements**: `task/ASSIGNMENT.md` (full specification)
- 📊 **Test Data**: `task/` folder (4 CSV files + 8 advisory markdown documents)
- 🏗️ **Architecture**: `SOLUTION_DESIGN_SUMMARY.md` (design decisions)
- 📝 **Implementation Plan**: `IMPLEMENTATION_PLAN.md` (6 tasks with guidance)

**Key Constraint**: Implement core RAG logic yourself—no LangChain, LlamaIndex, Haystack, Semantic Kernel, or similar frameworks.

---

## Quick Start

1. **Read Documentation** (5 min):
   - `SOLUTION_DESIGN_SUMMARY.md` — Understand the architecture
   - `IMPLEMENTATION_PLAN.md` — See 6 concrete tasks with guidance

2. **Follow Implementation Plan** (8-12 hours):
   - Task 1: Environment Setup (Docker, dependencies)
   - Task 2: Data Ingestion (CSV + markdown, embeddings)
   - Task 3: Unified Search Tool (VulnerabilitySearchTool class)
   - Task 4: LLM Agent (Gemini with function calling)
   - Task 5: CLI Interface (interactive + single-query modes)
   - Task 6: Testing & Validation (verify all 3 query types)

3. **Build in `solution/` folder** — All code goes here, not `task/`

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

## Python Best Practices

- **Virtual environments**: Use `uv`, `pip-tools`, or `conda`; pin all versions in `requirements.txt`
- **Code organization**: Keep source code in `src/`, tests in `tests/`
- **Formatting**: `black solution/src/ solution/tests/ --line-length 100`
- **Linting**: `ruff check solution/src/ solution/tests/ --fix`
- **Type checking**: `mypy solution/src/ solution/tests/ --strict`
- **Testing**: Write small, focused functions; use `pytest solution/tests/`
- **Type hints**: Use on all function signatures
- **Data structures**: Use `dataclasses` for structured data
- **Configuration**: Use environment variables, never hardcode secrets
- **Logging**: Use structured logging (JSON), not print statements; log with context
- **Docstrings**: Clear, concise; document "why", not "what"
- **Code style**: Readable, human-crafted code; descriptive variable names; no clever one-liners
- **Imports**: Required - `logging`, `os`, `pathlib.Path`, `dataclasses`, `typing`

---

## Getting Latest Documentation with Context7 MCP

**Before implementing any feature**, use Context7 MCP to get up-to-date library documentation:
- Verify Polars API (CSV reading, joins, iteration patterns)
- Check Typesense API for hybrid search and vector queries
- Verify Gemini function calling approach (google-genai library)
- Review sentence-transformers recommendations

This ensures you're using current APIs, not outdated patterns.

## IMPLEMENTATION_PLAN.md Status

**✅ FULLY OPTIMIZED & REVIEWED**
- Critical bugs fixed (embedding indexing, version consistency)
- Code simplified & concise (Polars + logging throughout)
- Tool declaration comprehensive with routing examples
- System instructions detailed with query types and formatting
- All imports correct (logging, os, pathlib, dataclasses, typing)
- Typesense key: hardcoded as `xyz` in docker-compose.yml + Python code (no env var needed)
- Only required env var: `GOOGLE_API_KEY` (for Gemini API)

---

## Requirements from ASSIGNMENT.md

### Functional Requirements (Must Implement)

✅ **Three Query Types**:
1. **Structured-only**: Filter/aggregate CSV data ("List Critical npm vulnerabilities", "Average CVSS?")
2. **Unstructured-only**: Vector search advisories ("Explain SQL injection", "Show code example")
3. **Hybrid**: Combine both ("How to fix CVE-2024-1234?", "Most severe npm vulnerabilities + explanation")

✅ **Natural Language Interface**: No query syntax, plain English questions

✅ **Accurate Citations**: Answers cite CVE IDs, package names, versions, CVSS scores

✅ **Core RAG Logic from Scratch**:
- ❌ NO LangChain, LlamaIndex, Haystack, Semantic Kernel, AutoGPT
- ✅ Implement query routing, retrieval, synthesis yourself
- ✅ Use low-level libraries only (pandas, typesense-py, genai)

### Data Structure (See `task/README.md` for full details)

**CSV Files** (4 normalized tables, 47 vulnerabilities in `task/`):
- `vulnerabilities.csv`: CVE ID, package_id, type_id, severity_id, CVSS, versions
- `packages.csv`: Package ID, name, ecosystem (npm/pip/maven)
- `vulnerability_types.csv`: Type ID, name (XSS, SQL Injection, RCE, etc.)
- `severity_levels.csv`: Severity ID, name, CVSS min/max

**Advisory Documents** (8 markdown files in `task/advisories/`):
- Each covers one vulnerability type
- Sections: Summary, Details, Attack Vector, Code Examples (JS/Python), Remediation, CVSS Table
- See `advisory-001.md` and `advisory-002.md` for structure

### Evaluation Criteria (from ASSIGNMENT.md)

- **Functionality**: All three query types answered correctly?
- **Architecture**: Clean, modular design demonstrating RAG understanding?
- **Code Quality**: Readable, maintainable, well-documented?
- **Problem-Solving**: How did you handle challenges?

## Implementation Checklist

Follow the **IMPLEMENTATION_PLAN.md** step-by-step (6 tasks, ~8-12 hours):


### Task 1: Environment Setup
- [ ] Create `requirements.txt` with pinned versions (Typesense 30.0, google-genai 1.35.0, etc.)
- [ ] Start Typesense via `docker-compose.yml` with health checks
- [ ] Install dependencies, verify Typesense health endpoint

### Task 2: Data Ingestion
- [ ] Load and denormalize 4 CSVs into single documents (47 records)
- [ ] Parse advisory markdown, chunk by sentences (~500 chars each, 60-80 chunks total)
- [ ] Generate embeddings (sentence-transformers model)
- [ ] Index into Typesense collection (~120-130 total documents)

### Task 3: Unified Search Tool
- [ ] Implement `VulnerabilitySearchTool` class with single `search_vulnerabilities()` method
- [ ] Support keyword, semantic, hybrid search types
- [ ] Add filtering (CVE, ecosystem, severity, CVSS)
- [ ] Add aggregations (avg/min/max CVSS) and faceting
- [ ] Return `SearchResult` dataclass with citations

### Task 4: LLM Agent
- [ ] Initialize Gemini client with automatic function calling
- [ ] Expose `search_vulnerabilities()` as tool to Gemini
- [ ] Implement system prompt with query routing logic
- [ ] Implement `answer_question()` method to synthesize answers
- [ ] Handle retries and API key validation

### Task 5: CLI Interface
- [ ] Interactive mode (`python cli.py` → REPL loop)
- [ ] Single query mode (`python cli.py "question here"`)
- [ ] Help system with example queries
- [ ] Clear error messages (API key, Typesense, etc.)

### Task 6: Testing & Validation
- [ ] Test all three query types
- [ ] Verify citations (CVE IDs, versions) in answers
- [ ] Benchmark query latency (<5 seconds)
- [ ] Validate memory usage (<2GB)

## Code Quality Standards

Write code that looks natural and human-crafted, not verbose or overly complicated:

**Good Example** (clear, concise, readable):
```python
def search_vulnerabilities(
    query: str,
    search_type: str = "hybrid",
    severity_levels: Optional[list] = None
) -> SearchResult:
    """Search vulnerability data by type (keyword/semantic/hybrid).
    
    Args:
        query: Search text
        search_type: "keyword" (CSV), "semantic" (advisories), or "hybrid"
        severity_levels: Filter by severity (Critical, High, etc.)
        
    Returns:
        SearchResult with documents, stats, and execution time
    """
    logger.info(f"Searching vulnerabilities", extra={
        "query": query, "type": search_type, "severity": severity_levels
    })
    
    # Build Typesense query based on search type
    search_params = self._build_search_params(
        query, search_type, severity_levels
    )
    
    response = self.client.collections["vulnerabilities"].documents.search(
        search_params
    )
    
    documents = [hit["document"] for hit in response.get("hits", [])]
    
    return SearchResult(
        query_type=search_type,
        total_found=response["found"],
        documents=documents,
        execution_time_ms=response.get("search_time_ms")
    )
```

**What Makes This Good**:
- ✅ Clear variable names (`search_params`, not `sp`)
- ✅ Docstring with purpose, args, returns
- ✅ Type hints for all parameters and return
- ✅ Structured logging with context
- ✅ Comments explain "why" (query building), not "what" (building the query)
- ✅ Single responsibility (search logic only, no I/O handling)
- ✅ Readable without being verbose (no unnecessary lines)

**Avoid**:
- ❌ Generic names: `data`, `result`, `x`, `temp`
- ❌ Overly complex one-liners or nested comprehensions
- ❌ Missing error context in logs/exceptions
- ❌ No documentation for complex logic
- ❌ Over-commenting obvious code
- ❌ Print statements instead of logging

## Key Design Decisions

| Decision | Why |
|----------|-----|
| Typesense (not separate SQL + vector DB) | Single unified engine, automatic rank fusion, no result merging |
| Gemini function calling (not pattern matching) | Adaptive to query variations, clean code, no brittle rules |
| Denormalized CSV data (not joins) | All data in single document, simple queries |
| Sentence-boundary chunking (not fixed size) | Preserves context, optimal embedding size (~150 tokens) |

## Common Pitfalls to Avoid

- ❌ Using forbidden frameworks (LangChain, etc.)
- ❌ Treating all queries as vector search (CSV queries need keyword matching)
- ❌ Forgetting citations (CVE IDs, versions, CVSS scores)
- ❌ Hardcoded Gemini model (use `GEMINI_MODEL` env var)
- ❌ No error handling (API validation, Typesense health checks, retries)

## Deliverables

1. **Working Code** (in `solution/` folder)
2. **Documentation** (query routing, vector search approach, answer synthesis)
3. **Validation** (all 3 query types working, latency <5 seconds)

## File References

| File | Purpose |
|------|---------|
| `task/ASSIGNMENT.md` | **READ THIS FIRST** - Full requirements, constraints, evaluation criteria |
| `task/README.md` | Dataset overview, schema details, file descriptions |
| `SOLUTION_DESIGN_SUMMARY.md` | Architecture, design decisions, patterns, trade-offs |
| `IMPLEMENTATION_PLAN.md` | Step-by-step implementation guide (6 tasks, ~8-12 hours) |
| `task/advisories/advisory-001.md` | Example advisory structure (XSS vulnerability) |
| `task/vulnerabilities.csv` | Main data file (47 CVE records) |
| `solution/` | **PUT YOUR IMPLEMENTATION HERE** |

## Folder Structure

```
task/                          # Challenge data (READ-ONLY)
├── ASSIGNMENT.md              # Requirements & evaluation criteria
├── README.md                  # Dataset overview
├── vulnerabilities.csv        # 47 vulnerability records
├── packages.csv               # Package info (npm/pip/maven)
├── vulnerability_types.csv    # Vulnerability type definitions
├── severity_levels.csv        # Severity level definitions
└── advisories/                # 8 security advisory markdown files
    ├── advisory-001.md
    ├── advisory-002.md
    └── ...

solution/                      # YOUR IMPLEMENTATION (FRESH CODE)
```

---

## Next Steps

1. Read `SOLUTION_DESIGN_SUMMARY.md` for architectural context
2. Follow `IMPLEMENTATION_PLAN.md` task-by-task
3. **Always use Context7 MCP** for latest library documentation before implementing
4. Write code that looks human-crafted (clear, concise, readable—not verbose)
5. Apply Python best practices (type hints, logging, testing, configuration)
6. Test all three query types before finalizing

---

**Status**: Code challenge with full documentation. Solution code to be implemented fresh in `solution/` folder.
