# Snyk Take Home Assignment for AI Incubation Engineer

## Your Task

Build a RAG system that can:
- Answer questions using structured data (CSV files)
- Answer questions using unstructured data (markdown advisory documents)
- Combine information from both sources when needed
- Process different content types: text, code snippets, and tables

## Dataset Overview

The dataset contains security vulnerability information in two formats:

1. **Structured Data**: 4 normalized CSV files with vulnerability metadata
2. **Unstructured Data**: 8 detailed security advisory documents in Markdown format

## Dataset Structure

```
snyk-interview-dataset/
├── vulnerabilities.csv          # Main vulnerability data (47 records)
├── packages.csv                 # Package information (47 packages)
├── vulnerability_types.csv      # Vulnerability type definitions (34 types)
├── severity_levels.csv          # Severity level definitions (4 levels)
├── advisories/                  # 8 security advisory documents
│   ├── advisory-001.md         # XSS in express-validator
│   ├── advisory-002.md         # SQL injection in webapp-auth
│   ├── advisory-003.md         # Dependency confusion in secure-config
│   ├── advisory-004.md         # Path traversal in data-processor
│   ├── advisory-005.md         # RCE in file-handler
│   ├── advisory-006.md         # CSRF in api-client
│   ├── advisory-007.md         # SSRF in http-server
│   └── advisory-008.md         # Insecure deserialization in json-parser
└── README.md                   # This file
```

## Structured Data (CSV Files)

The structured data is normalized into 4 related tables:

### Tables

1. **vulnerabilities.csv** - Main table with CVE IDs, package references, vulnerability types, severity levels, CVSS scores, affected/fixed versions, and descriptions
2. **packages.csv** - Package names and ecosystems (npm, pip, maven)
3. **vulnerability_types.csv** - Vulnerability type definitions (XSS, SQL Injection, etc.)
4. **severity_levels.csv** - Severity levels (Critical, High, Medium, Low) with CVSS score ranges

### Relationships

- `vulnerabilities.package_id` → `packages.package_id`
- `vulnerabilities.vulnerability_type_id` → `vulnerability_types.type_id`
- `vulnerabilities.severity_id` → `severity_levels.severity_id`

You can work with the normalized data (using joins) or denormalize it on load—the choice is yours and demonstrates your data modeling approach.

## Unstructured Data (Advisories)

The `advisories/` directory contains 8 detailed security advisory documents. Each advisory includes:

- **Text**: Vulnerability descriptions, attack vector explanations, impact analysis
- **Code**: Vulnerable and fixed code examples (JavaScript and Python)
- **Tables**: Affected version matrices, CVSS breakdown tables, remediation timelines

### Advisory Topics Covered

| Advisory | CVE | Vulnerability Type | Package | Ecosystem |
|----------|-----|-------------------|---------|-----------|
| advisory-001.md | CVE-2024-1234 | Cross-Site Scripting (XSS) | express-validator | npm |
| advisory-002.md | CVE-2024-1235 | SQL Injection | webapp-auth | npm |
| advisory-003.md | CVE-2024-1237 | Dependency Confusion | secure-config | npm |
| advisory-004.md | CVE-2024-1236 | Path Traversal | data-processor | npm |
| advisory-005.md | CVE-2024-1238 | Remote Code Execution (RCE) | file-handler | npm |
| advisory-006.md | CVE-2024-1239 | Cross-Site Request Forgery (CSRF) | api-client | pip |
| advisory-007.md | CVE-2024-1241 | Server-Side Request Forgery (SSRF) | http-server | pip |
| advisory-008.md | CVE-2024-1242 | Insecure Deserialization | json-parser | pip |

## Dataset Statistics

- **47 vulnerabilities** across npm, pip, and maven ecosystems
- **8 security advisories** with detailed documentation
- **34 different vulnerability types**
- **Severity distribution**: 4 Critical, 28 High, 13 Medium, 2 Low

## What to Build

Your RAG system should handle queries that:
- Require only structured data (e.g., "List all critical vulnerabilities")
- Require only unstructured data (e.g., "Explain how SQL injection works")
- Require both (e.g., "How do I fix CVE-2024-1234?")

The system should be able to process and understand:
- Text descriptions
- Code snippets in multiple languages
- Tables embedded in markdown documents

## Getting Started

1. Load and explore the CSV files to understand the data structure
2. Read the advisory markdown files to understand the content format
3. Design your RAG architecture (vector database, embeddings, retrieval strategy)
4. Implement query processing that can route to appropriate data sources
5. Test with various query types to ensure robust answers
