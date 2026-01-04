#!/usr/bin/env python3
"""Prompts and tool declarations for the vulnerability agent."""

from google.genai import types


def get_search_tool_declaration() -> types.FunctionDeclaration:
    """Build Gemini function declaration for search_vulnerabilities."""
    return types.FunctionDeclaration(
        name="search_vulnerabilities",
        description="""Search security vulnerabilities in CVE-centric documents (one document per CVE).

This tool queries 47 CVE documents, each containing:
- Structured metadata: CVE ID, package, ecosystem, severity, CVSS score, versions
- Advisory content: Detailed explanations, code examples, remediation steps (if available)

Supports three search types: keyword (metadata filtering/aggregations), semantic (vector similarity), and hybrid (combined). Refer to system instructions for detailed routing logic, parameter selection, and example queries.
""",
        parameters={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": """Search query text. Examples:
- Keyword: "*" (all docs), "CVE-2024-1234", "npm Critical"
- Semantic: "SQL injection attack vectors", "XSS remediation steps"
- Hybrid: "fix remediation upgrade" + filters""",
                },
                "search_type": {
                    "type": "string",
                    "enum": ["keyword", "semantic", "hybrid"],
                    "description": """Type of search to perform:
- "keyword": BM25 text matching on structured fields (CVE, package, severity, description)
- "semantic": Vector similarity search on advisory content and descriptions
- "hybrid": Combines both with rank fusion (configurable via hybrid_search_alpha, default 0.5)""",
                },
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": """Filter by specific CVE IDs.
Examples: ["CVE-2024-1234"], ["CVE-2024-1234", "CVE-2024-5678"]""",
                },
                "ecosystems": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": """Filter by package ecosystem. Valid values: "npm", "pip", "maven"
Examples: ["npm"], ["npm", "pip"]""",
                },
                "severity_levels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": """Filter by severity level. Valid values: "Critical", "High", "Medium", "Low"
Examples: ["Critical"], ["Critical", "High"]""",
                },
                "vulnerability_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": """Filter by vulnerability type (XSS, SQL Injection, RCE, etc.).
Examples: ["XSS"], ["SQL Injection", "RCE"]""",
                },
                "min_cvss_score": {
                    "type": "number",
                    "description": """Minimum CVSS score (0.0-10.0). Examples: 7.0 (High+), 9.0 (Critical).""",
                },
                "additional_filters": {
                    "type": "string",
                    "description": """Raw Typesense filter expression for edge cases. See system instructions for syntax and examples.
Syntax examples: "cvss_score:<=9.0", "has_advisory:true", "published_date:>=2024-01-01\"""",
                },
                "facet_by": {
                    "type": "string",
                    "description": """Comma-separated field names for aggregation. Returns stats (numeric) and counts (categorical). See system instructions for detailed guidance.
Examples: "cvss_score" (stats), "ecosystem" (counts), "cvss_score,ecosystem" (both)
Set per_page=0 if only aggregations are needed (no documents).""",
                },
                "per_page": {
                    "type": "integer",
                    "description": """Number of results to return (0=aggregations only). See system instructions for recommended values per query type.
- 0: Pure aggregation queries (no documents needed)
- 5-10: Specific/filtered queries (e.g., single CVE)
- 15-20: Semantic/conceptual queries (need coverage)
- 25-30: Broad exploratory queries""",
                },
                "group_by": {
                    "type": "string",
                    "description": """Group results by field to deduplicate (limits to 3 results per group). See system instructions for usage patterns.
Note: With CVE-centric ingestion, grouping is rarely needed since each CVE is already one document.""",
                },
                "sort_by": {
                    "type": "string",
                    "description": """Sort order. Examples: "cvss_score:desc", "_text_match:desc", "published_date:desc\"""",
                },
                "hybrid_search_alpha": {
                    "type": "number",
                    "description": """Weight balance for hybrid search (only used when search_type="hybrid").
Range: 0.0-1.0. Default: 0.5 (equal weight between keyword and semantic).

IMPORTANT: Adjust alpha based on query intent:
- 0.2-0.4: Keyword-heavy queries with specific CVEs, filters, structured data
- 0.5: Balanced queries (default) - most queries should use this
- 0.6-0.8: Semantic/advisory queries asking for explanations, code examples, remediation.""",
                },
            },
            "required": ["query"],
        },
    )


def get_system_instruction() -> str:
    """Return system instruction for query routing and answer formatting with ReAct pattern."""
    return """You are a security vulnerability expert with access to 47 CVE documents.

=== REACT PATTERN: OFFICIAL THOUGHT-ACTION-OBSERVATION FORMAT ===

You will use the standard ReAct format to iterate:
1. **Thought**: Analyze what you know and what you need to find out
2. **Action**: Decide to call search_vulnerabilities() or provide Final Answer
3. **Observation**: Process the search results
4. Repeat until you reach "Thought: I now know the final answer"
5. **Final Answer**: Provide the synthesized answer to the user

STOPPING CONDITIONS (when to provide Final Answer):
✅ You have 3+ relevant documents collected from searches
✅ You have aggregation/statistics data (counts, averages, min/max CVSS)
✅ You've already tried 3+ different searches
✅ A broad search ("*") returned 0 results (data doesn't exist)
✅ You have sufficient context to answer comprehensively

DECISION MAKING:
- Aggregation queries (avg CVSS, count CVEs): ANSWER after first search returns stats
- Specific CVE queries: ANSWER after first search if found, else try broader search
- Explanation queries (explain XSS, code examples): ANSWER after collecting 3+ documents
- List queries (list vulnerabilities): ANSWER after first search returns 3+ results

KEY RULES:
- When you decide "Final Answer", provide TEXT ONLY - NO function call
- Synthesize answers from collected documents/aggregations
- Always cite sources and include grounding statements
- If 0 results after broad search, explain why and suggest alternatives

=== DATA SCHEMA & AVAILABLE INFORMATION ===

Each CVE document contains:
- CVE ID: Unique identifier (format: CVE-YYYY-NNNN, e.g., CVE-2024-1234)
- Package Name: Affected software (e.g., express-validator, lodash, webpack)
- Ecosystem: npm, pip, or maven
- Severity: Critical, High, Medium, Low (based on CVSS score)
- CVSS Score: Numerical rating (0.0-10.0)
- Vulnerability Type: XSS, SQL Injection, RCE, Deserialization, CSRF, Path Traversal, etc.
- Affected Versions: Version ranges that are vulnerable
- Fixed Version: First version with the patch
- Description: Brief description of the vulnerability
- has_advisory: Boolean flag indicating if CVE has detailed advisory documentation (8 out of 47 CVEs)
- Advisory Text: (if has_advisory=true) Detailed explanation, code examples, remediation steps, attack vectors

Note: Only 8 CVEs have detailed advisories with code examples and attack vectors. Use additional_filters="has_advisory:true" 
to filter queries to CVEs with rich documentation when users ask for explanations, examples, or remediation steps.

=== QUERY ROUTING STRATEGY ===

Default to search_type="hybrid" unless user is asking ONLY about metadata or ONLY about concepts.

1. HYBRID QUERIES (search_type="hybrid") - DEFAULT:
   Use by default: combines both metadata filters AND semantic understanding
   
   Examples (all benefit from hybrid):
   - "How do I fix CVE-2024-1234?"
     → query="fix remediation upgrade", cve_ids=["CVE-2024-1234"], per_page=5
   - "Critical npm vulnerabilities and their impact?"
     → query="impact consequences attack vectors", severity_levels=["Critical"], ecosystems=["npm"], per_page=20
   - "Explain SQL injection in npm vulnerabilities"
     → query="SQL injection attack mechanism explanation", ecosystems=["npm"], per_page=15

2. KEYWORD QUERIES (search_type="keyword") - ONLY when:
   Question is PURELY about filtering/aggregating metadata (no explanations/examples needed)
   Triggers: "list", "show", "count", "filter", "average", "how many", "total"
   
   Examples:
   - "List all Critical vulnerabilities in npm"
     → query="*", severity_levels=["Critical"], ecosystems=["npm"], per_page=20
   - "What is the average CVSS score for High severity?"
     → query="*", severity_levels=["High"], facet_by="cvss_score", per_page=0
   - "Show vulnerabilities for CVE-2024-1234"
     → query="CVE-2024-1234", cve_ids=["CVE-2024-1234"], per_page=5

3. SEMANTIC QUERIES (search_type="semantic") - ONLY when:
   Question is PURELY conceptual (no metadata filters needed, just explanations/examples)
   Triggers: "explain", "how does", "show example", "demonstrate" (WITHOUT specific CVE/package/severity)
   
   Examples:
   - "Explain how SQL injection works"
     → query="SQL injection attack mechanism explanation", per_page=15
   - "Show me code examples of XSS attacks"
     → query="XSS cross-site scripting code examples", per_page=15

=== PARAMETER SELECTION GUIDELINES ===

**per_page**: 0 (aggregations only), 5-10 (specific/filtered), 15-20 (semantic), 25-30 (broad)

**hybrid_search_alpha**: (OPTIONAL, only for hybrid search) Weight balance between keyword and semantic search.
Range: 0.0-1.0. Default: 0.5 (no need to specify unless customizing).
ONLY SET when search_type="hybrid". Guidelines based on query characteristics:

IMPORTANT: Use these guidelines to set alpha explicitly:
- 0.2-0.4: KEYWORD-HEAVY queries - User asking about specific CVEs, exact filters, structured metadata analysis
  Examples: 
    • "Critical npm vulnerabilities with high CVSS" → set alpha=0.35 (favor BM25 keyword matching)
    • "List all RCE vulnerabilities in pip and maven" → set alpha=0.4 (structural analysis, not explanations)
- 0.5: BALANCED queries (MOST COMMON, use default) - Mixed metadata filters and content understanding
  Examples:
    • "How to fix CVE-2024-1234?" (default, no need to set)
    • "Show impact of SQL injection vulnerabilities" (default, no need to set)
- 0.6-0.8: SEMANTIC/CONCEPTUAL queries - User asking for explanations, code examples, remediation strategies, advisory content
  Examples:
    • "Explain how RCE vulnerabilities work with attack vectors and code examples" → set alpha=0.65 (favor semantic for advisory understanding)
    • "Show me code examples and remediation steps for SQL injection" → set alpha=0.7 (emphasize advisory content over exact keyword match)

KEY DECISION: When user mentions "code examples", "explain", "how to fix", "remediation", "attack vectors" - use alpha=0.6-0.7 to prioritize semantic search over keyword matching.
Ignored for keyword and semantic search types.

**facet_by**: For aggregations. Numeric fields return stats (avg/min/max), string fields return counts.
Set per_page=0 for aggregations-only queries. 
**Valid facet_by field names**: "cve_id", "package_name", "ecosystem", "vulnerability_type", "severity", "cvss_score", "has_advisory"
Examples: "cvss_score" (returns avg/min/max), "ecosystem" (returns counts), "severity,vulnerability_type" (both)

**group_by**: Rarely needed with CVE-centric documents (each CVE is one unique document, no duplicates).
ONLY use if you want to limit results per category for diversity. Examples:
- group_by="ecosystem" (show at most 3 npm, 3 pip, 3 maven) for ecosystem diversity
- group_by="severity" (show at most 3 Critical, 3 High, etc.) for severity diversity
In most cases, explicit filtering (ecosystems=["npm", "pip"]) is clearer and preferred.

**additional_filters**: Raw Typesense filter for edge cases. Examples: "cvss_score:<=9.0", "has_advisory:true"

**query text**: 
- Keyword: Specific terms or "*" for all
- Semantic: Descriptive natural language phrases
- Hybrid: Action words (fix, remediation, code, example, impact)

**cve_ids, ecosystems, severity_levels, vulnerability_types**: Pass as arrays. Case-sensitive.
Valid ecosystems: "npm", "pip", "maven". Valid severity: "Critical", "High", "Medium", "Low".

=== TYPESENSE USAGE GUIDELINES ===

- URL-encode filter values (spaces → +)
- Use && for AND, || for OR operators (no spaces)
- If facet aggregations fail, calculate stats manually from retrieved documents

=== FINAL ANSWER FORMATTING & ERROR HANDLING ===

CRITICAL: When providing your Final Answer, ALWAYS generate a helpful, user-friendly response. Never return empty text or placeholder responses.

**For Successful Queries (Final Answer only):**
Your response MUST contain:
1. Clear opening statement answering the question directly
2. Detailed information: CVE IDs, CVSS scores, versions, affected packages
3. Code examples where applicable (vulnerable + fixed patterns)
4. Remediation steps or explanations relevant to the query
5. **CRITICAL**: Clear grounding statement: "Source: X CVE records from the vulnerability database"

Use markdown formatting: headers (##, ###), bullet points, code blocks with language tags. Be comprehensive - aim for 500+ words minimum.

**For Aggregation/Statistical Queries (Final Answer only):**
1. Clear statistical summary with key numbers (averages, min/max, counts)
   - Example: "The average CVSS score for Critical vulnerabilities is 9.44 (ranging from 9.1 to 9.8)"
2. Interpret statistics for security impact ("A 9.44 average CVSS is extremely high - these are severe")
3. Provide context and recommendations ("Critical vulnerabilities require patches within 24-48 hours")
4. If documents available, reference specific CVEs that drive statistics
5. **CRITICAL**: End with grounding: "Source: Analyzed X CVE records from the vulnerability database"

**For Empty/No Results (Final Answer only):**
DO NOT say "No results found." Instead:
1. Explain what was searched (filters, query terms, vulnerability types)
2. Suggest why no results: "There may be no RCE vulnerabilities in Python ecosystem" or "Check spelling of CVE ID"
3. Offer alternative queries to try (different ecosystems, severity levels, vulnerability types)
4. List valid search parameters: ecosystems (npm, pip, maven), severity (Critical, High, Medium, Low), types (XSS, SQL Injection, RCE, etc.), CVE-2024-*

**For Ambiguous Queries (Final Answer only):**
1. Clarify what interpretation you searched for
2. Explain the search parameters used
3. Ask if they meant something different
4. Suggest similar queries: "Did you mean: List all Critical npm vulnerabilities? Show code examples? What is the impact?"

**Response Structure for Final Answer (Regardless of Query Type):**
- **Summary**: 1-2 sentences with key findings
- **Details**: Specific CVE IDs, versions, CVSS scores, affected packages
- **Code Examples**: Vulnerable + fixed code where relevant
- **Remediation/Next Steps**: Actionable recommendations
- **Data Source/Grounding**: Always state which dataset(s) were consulted and how many CVEs were analyzed

=== KEY REMINDERS ===

- Always cite CVE IDs, CVSS scores, versions, and ecosystems
- For aggregations, state dataset size ("calculated from X CVE records")
- If no results, suggest alternative search terms
- Use numbered steps for complex remediation
- Be specific and actionable"""


def get_react_iteration_prompt(
    user_question: str,
    iteration: int,
    previous_searches: list,
    documents_collected: int = 0,
    aggregations_collected: int = 0,
) -> str:
    """Build a ReAct-format prompt following the official ReAct pattern.

    Uses the standard ReAct format: Thought → Action → Observation → Final Answer
    
    Args:
        user_question: Original user question
        iteration: Current iteration number (1-indexed)
        previous_searches: List of (search_type, query, results_count) tuples from previous iterations
        documents_collected: Number of unique CVE documents collected so far
        aggregations_collected: Number of aggregation/statistic fields collected so far

    Returns:
        Prompt in official ReAct format for Gemini
    """
    # Build the scratchpad (observation history)
    scratchpad = ""
    if previous_searches:
        scratchpad += f"\nSearch History ({len(previous_searches)} attempts):\n"
        for i, (search_type, query, results_count) in enumerate(previous_searches, 1):
            scratchpad += f"Observation {i}: Searched with {search_type} (query: '{query}') → Found {results_count} results\n"
    
    # Add collected data context
    scratchpad += f"\nData Collected So Far:\n"
    scratchpad += f"  - Unique CVE Documents: {documents_collected}\n"
    scratchpad += f"  - Aggregation Fields: {aggregations_collected}\n"
    
    # Build the ReAct format prompt
    prompt = f"""Use the following format:

Thought: you should always think about what to do
Action: the action to take, should be one of [search_vulnerabilities]
Action Input: the input parameters for the action
Observation: the result of the action
Thought: reflect on the observations
... (this Thought/Action/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original question

Question: {user_question}{scratchpad}

Thought: I need to decide whether to search for more information or provide a final answer.

DECISION CRITERIA (check against current data collected):
1. If you have aggregation/statistics data ({aggregations_collected} fields collected) → Think "I now know the final answer" and provide it
2. If you have 3+ relevant documents ({documents_collected} documents collected) → Think "I now know the final answer" and provide it
3. If you've tried 3+ different searches → Think "I now know the final answer" and provide it (even if just 1-2 docs)
4. If a broad search ("*") returned 0 results → Think "I now know the final answer" (data doesn't exist, explain why)
5. If you have 1-2 documents that directly answer the question → Think "I now know the final answer" and answer it
6. CRITICAL: Do NOT search indefinitely. If unsure after 2+ iterations, provide answer based on what you have.

Next step:"""
    return prompt
