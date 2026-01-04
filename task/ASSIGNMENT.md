# Building a Hybrid Query System for Security Vulnerability Data

## Objective

Design and implement a system that can answer user questions by intelligently querying both **structured data** (CSV files with vulnerability metadata) and **unstructured data** (security advisory markdown documents via vector search). The system should understand when to use each data source and how to combine information from both when needed.

## Dataset Overview

You will work with a security vulnerability dataset containing:

1. **Structured Data**: 4 normalized CSV files
   - `vulnerabilities.csv` - Main vulnerability records (47 vulnerabilities)
   - `packages.csv` - Package information (npm, pip, maven ecosystems)
   - `vulnerability_types.csv` - Vulnerability type definitions (34 types)
   - `severity_levels.csv` - Severity level definitions (4 levels: Critical, High, Medium, Low)

2. **Unstructured Data**: 8 security advisory markdown documents
   - Located in the `advisories/` directory
   - Each contains detailed vulnerability descriptions, code examples, attack vectors, remediation steps, and CVSS breakdown tables
   - Covers vulnerabilities like XSS, SQL Injection, RCE, CSRF, SSRF, Path Traversal, etc.

See `README.md` for complete dataset details, including table schemas, relationships, and advisory topics.

## System Requirements

### Input
- Natural language questions from the user (e.g., "How do I fix CVE-2024-1234?", "List all critical vulnerabilities in npm packages", "Explain how SQL injection works")

### Output
- Coherent, natural language answers that synthesize information from the appropriate data sources
- Answers should cite specific data when relevant (CVE IDs, package names, version numbers, etc.)

### Core Functionality

Your system must handle three types of queries:

1. **Structured-only queries**: Require only CSV data
   - Example: "What is the average CVSS score for High severity vulnerabilities in pip packages?"
   - Requires: SQL-like operations (joins, filters, aggregations) on CSV files

2. **Unstructured-only queries**: Require only advisory documents
   - Example: "Explain how path traversal attacks work and show me a vulnerable code example"
   - Requires: Vector search/retrieval from markdown documents

3. **Hybrid queries**: Require both structured and unstructured data
   - Example: "How do I fix CVE-2024-1234 and what version should I upgrade to?"
   - Requires: Combining SQL results with vector search results, then synthesizing

## Implementation Guidelines

### Language Requirement

**You must implement your solution in Python.** This ensures consistency and allows us to evaluate your code effectively.

### Allowed Technologies

✅ **You ARE allowed to use:**
- **Any LLM API or service** (OpenAI, Anthropic, Google, open-source models via HuggingFace, etc.)
- **Any vector database/store** (Pinecone, Weaviate, Chroma, Qdrant, FAISS, pgvector, etc.)
- **Any embedding model** (OpenAI embeddings, sentence-transformers, etc.)
- Standard Python libraries for database operations (sqlite3, pandas, etc.) for CSV/structured data
- Standard Python libraries for text processing, numerical operations (numpy), etc.
- **Command-line interface (CLI)** for user interaction (using Python's built-in `argparse` or `input()`)
- **Package managers**: pip, uv, or other Python package management tools

❌ **You are NOT allowed to use:**
- High-level RAG/LLM agent frameworks that abstract away core logic:
  - Langchain
  - LlamaIndex
  - Haystack
  - Semantic Kernel
  - AutoGPT/Agent frameworks
  - Any other framework that provides pre-built RAG pipelines or query decomposition logic

### Why These Restrictions?

The goal is to demonstrate your understanding of the fundamental components of hybrid query systems. We want to see how you approach:

- Determining which data sources a query needs
- Retrieving information from both structured and unstructured sources
- Combining results from different sources into coherent answers
- Using LLMs effectively for generation and synthesis

You should implement the core orchestration and decision-making logic yourself, even if you use libraries for lower-level operations (embeddings, vector math, database connections).

### Implementation Approach

Think about how you'll:

- **Process user queries**: Understand what information is needed and from which sources
- **Query structured data**: Access and filter the CSV files to extract relevant vulnerability information
- **Query unstructured data**: Retrieve relevant sections from the advisory documents using vector search
- **Synthesize results**: Combine information from different sources into coherent answers
- **Interact with users**: Provide a simple CLI interface for asking questions

The specific architecture and module structure is up to you—we're interested in seeing your design choices and how you reason about the problem.

## Example Queries to Support

Your system should handle various query types. Here are some examples to guide your testing:

- **Hybrid**: "How do I fix CVE-2024-1234 and what version should I upgrade to?"
- **Hybrid**: "What are all critical severity vulnerabilities in npm packages, and explain how the SQL injection one works?"
- **Structured-only**: "What is the average CVSS score for High severity vulnerabilities in pip packages?"
- **Unstructured-only**: "Explain how path traversal attacks work and show me a vulnerable code example."
- **Hybrid**: "Find all RCE vulnerabilities and explain the attack vector for the one with the highest CVSS score."

## Deliverables

1. **Working Code**
   - Python source code with clear structure and comments
   - Instructions for setup and running the system
   - Requirements/dependencies file (requirements.txt, pyproject.toml with uv, or similar)

2. **Documentation**
   - Brief explanation of your architecture and design choices
   - How you handle query routing (structured vs unstructured vs hybrid)
   - Your approach to vector search and retrieval
   - How you combine and synthesize results from different sources

3. **Demonstration**
   - Be prepared to run example queries during the interview
   - Walk through your code and explain key design decisions

## Evaluation Criteria

We will evaluate:

- **Functionality**: Does the system correctly answer queries across all three types?
- **Architecture**: Is the design clean, modular, and well-thought-out?
- **Understanding**: Do you demonstrate deep understanding of the components (query routing, vector search, synthesis)?
- **Code Quality**: Is the code readable, maintainable, and well-documented?
- **Problem-Solving**: How did you handle challenges in building from scratch?

## Questions?

If anything is unclear, please ask!


**Note**: This assignment is designed to be completed in a reasonable timeframe (typically 4-8 hours). Focus on demonstrating core understanding rather than building a production-ready system. We value clear thinking and good design over feature completeness.

