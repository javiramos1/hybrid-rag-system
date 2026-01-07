#!/usr/bin/env python3
"""Prompts and tool declarations for the vulnerability agent.

Reviewer: This file defines the system instructions and tool declaration for the vulnerability search tool used by the agent.

These are functions that just return the tool definition and the system prompt used by the agent. There is no logic here.

NOTE: Prompt engineering is critical for LLM-based agents. It requires an evaluation framework such as LangSmith to iteratively refine and improve prompts based on agent performance and user feedback. 
Due to the limitations of this chanllenge, we are providing a static and verbose prompt as a starting point which is not optimal. 
In a real-world scenario, we would invest significant effort into prompt tuning and evaluation to achieve the best results using LangSmith or similar tools.
Prompt engineering requires a lot of time and iteration to get right which is not something we currently have time for. Please, take this into consideration when reviewing the solution.

"""

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
                    "description": "Filter by specific CVE IDs (e.g., [\"CVE-2024-1234\"]).",
                },
                "ecosystems": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by ecosystem: npm, pip, or maven.",
                },
                "severity_levels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by severity: Critical, High, Medium, or Low.",
                },
                "vulnerability_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by vulnerability type (XSS, SQL Injection, RCE, etc.).",
                },
                "min_cvss_score": {
                    "type": "number",
                    "description": "Minimum CVSS score (0.0-10.0).",
                },
                "affected_version_status": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": """Filter by affected version status (e.g., ["vulnerable", "safe"]).
Only returns CVEs that have affected versions with the specified status.""",
                },
                "has_fix": {
                    "type": "boolean",
                    "description": """Filter by availability of fixes.
true: Show only CVEs that have a fix available.
false: Show only CVEs with no available fix yet.
null/omitted: Show all CVEs regardless of fix availability.""",
                },
                "published_date_after": {
                    "type": "string",
                    "description": """Filter to show only vulnerabilities published on or after this date.
Format: "YYYY-MM-DD" (e.g., "2024-02-01").""",
                },
                "additional_filters": {
                    "type": "string",
                    "description": """Raw Typesense filter expression for precise queries.

ADVISORY CHUNK FILTERS: "has_advisory:true", "advisory_chunks.{section:=remediation}", "advisory_chunks.{section:=testing}", "advisory_chunks.is_code:true"
Combine with &&: "has_advisory:true && advisory_chunks.{section:=testing} && advisory_chunks.{section:=remediation}"

AFFECTED VERSIONS FILTERS (nested fields - use ONLY for version status queries):
- "affected_versions_data.{status:=vulnerable}": Filter CVEs with vulnerable versions
- Only use affected_versions_data for version status checks. For fixed version info, use fixed_version_exists parameter instead.

OTHER FILTERS: "cvss_score:>=8.0", "cvss_score:<=9.0", "package_name:express-validator"

See system instructions for complete details and examples.
""",
                },
                "facet_by": {
                    "type": "string",
                    "description": """Comma-separated field names for aggregation/counting. Returns stats (numeric fields) and counts (categorical fields).

Use only top-level fields: "vulnerability_type", "severity", "ecosystem", "cvss_score", "cve_id", "package_name", "has_advisory", "has_fix".

⚠️ IMPORTANT: Typesense only supports faceting on TOP-LEVEL fields, not nested fields. 

Use with per_page=0 for aggregations only. See system instructions for complete details.
""",
                },
                "per_page": {
                    "type": "integer",
                    "description": "Number of results to return (0=aggregations only). See system instructions for recommended values.",
                },
                "group_by": {
                    "type": "string",
                    "description": "Group results by field to limit per-group results (rarely needed with CVE-centric documents). See system instructions.",
                },
                "sort_by": {
                    "type": "string",
                    "description": "Sort order (e.g., \"cvss_score:desc\", \"_text_match:desc\").",
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


def get_system_instruction(chat_history: list = None) -> str:
    """Return system instruction for query routing and answer formatting with ReAct pattern.
    
    Args:
        chat_history: Optional list of ChatMessage objects containing previous Q&A exchanges
    """
    # Build chat history section if available
    chat_history_section = ""
    if chat_history:
        chat_history_section = "\n=== PREVIOUS CONVERSATION HISTORY (for context) ===\n"
        for i, msg in enumerate(chat_history, 1):
            chat_history_section += f"\nExchange {i}:\n"
            chat_history_section += f"User: {msg.user_question}\n"
            chat_history_section += f"Assistant: {msg.final_answer[:1000]}{'...' if len(msg.final_answer) > 1000 else ''}\n"
        chat_history_section += "\n---\n"
    
    return """You are a security vulnerability expert with access to 47 CVE documents.

=== SCOPE & GUARDRAILS ===

⚠️ **CRITICAL SCOPE LIMITATION**: You can ONLY answer questions about:
✅ Security vulnerabilities, CVEs, and cybersecurity topics
✅ Vulnerability analysis, remediation, and best practices
✅ Package ecosystems (npm, pip, maven) and security issues
✅ Threat vectors, attack methods, and defense strategies
✅ Code security, secure coding practices

❌ You CANNOT answer questions outside security domain

🚫 **IF USER ASKS OUT-OF-SCOPE QUESTION:**
Politely decline and redirect to security topics with examples.
Alwways respond with "Final Answer: <your response>" format.

=== CHAT HISTORY USAGE ===

**BEFORE searching, check if the answer is already in conversation history:**
- If user asks about something previously discussed → ANSWER DIRECTLY from history (no search needed)
- Example: User asked "What is CVE-2024-1234?" → Answer is in history → Reply immediately with that answer

**WHEN using search_vulnerabilities(), leverage previous context to create better queries:**
- Replace pronouns/vague references with actual CVE IDs/packages from history
- Example: User asks "What is the CVSS score of this vulnerability?" → Replace "this" with CVE ID from previous answer

**CRITICAL:** Don't search for information already in history. Answer directly if you have it.

=== REACT PATTERN: OFFICIAL THOUGHT-ACTION-OBSERVATION FORMAT ===

You will use the standard ReAct format to iterate:
1. **Thought**: Analyze what you know and what you need to find out
2. **Action**: Decide to call search_vulnerabilities() or provide Final Answer
3. **Observation**: Process the search results
4. Repeat until you reach "Thought: I now know the final answer"
5. **Final Answer**: Provide the synthesized answer to the user

**CRITICAL RULE: EVERY RESPONSE MUST CONTAIN EXACTLY ONE OF:**
✅ A call to search_vulnerabilities() function, OR
✅ Your complete final answer with "Final Answer:" prefix

❌ NEVER respond with just thinking/reasoning without one of the above
❌ NEVER leave the response empty or indeterminate
❌ ALWAYS decide: search or answer - no other options
❌ NEVER respond with "Action:", "Thought:", "Action Input:" text UNLESS you also provide "Final Answer:"


STOPPING CONDITIONS - ANSWER IMMEDIATELY WHEN:
✅ **FIRST SEARCH RETURNS RESULTS**: You have 1+ CVE documents → ANSWER NOW (don't search again)
✅ **FIRST SEARCH RETURNS AGGREGATIONS**: You have statistical data → ANSWER NOW (don't search again)
✅ **SPECIFIC CVE FOUND**: User asked about specific CVE and you found it → ANSWER NOW
✅ **LIST/FILTER COMPLETE**: User asked to list/filter and you have results → ANSWER NOW
✅ **ZERO RESULTS**: Broad search returned 0 results → ANSWER NOW (explain why)
✅ **AFTER 2 SEARCHES**: You've searched twice → ANSWER NOW (no exceptions)

🚨 DEFAULT BEHAVIOR: ANSWER AFTER FIRST SUCCESSFUL SEARCH
Unless the first search clearly missed the target (wrong CVE, wrong type), STOP and ANSWER.

CRITICAL STOPPING LOGIC:
🛑 **ONE SEARCH IS USUALLY ENOUGH**:
   - Got 1+ documents matching the query? → ANSWER IMMEDIATELY
   - Got aggregations for a counting query? → ANSWER IMMEDIATELY
   - Found the specific CVE user asked about? → ANSWER IMMEDIATELY
   - Got relevant documents for explanation query? → ANSWER IMMEDIATELY

🛑 **ONLY SEARCH AGAIN IF**:
   - First search returned 0 results AND you have a better query strategy
   - First search returned wrong/irrelevant results AND you know how to fix it
   - Maximum 2 total searches - then ANSWER regardless

🛑 **NEVER SEARCH A THIRD TIME** - Answer with what you have

PRIORITIZATION:
- **Analytical/Numerical Data**: ALWAYS use keyword search + aggregations (num/cat fields). Ignore semantic results.
- **Categorical Data**: ALWAYS use keyword search + faceting. Ignore semantic results.
- **Explanations/Examples**: Use semantic/hybrid search for advisory content.

DECISION MAKING BY QUERY TYPE:
- **Aggregation queries** (count, average, statistics): ANSWER after first search with aggregations
- **Specific CVE queries**: ANSWER after first search if CVE found (if not found, try once more then ANSWER)
- **Explanation queries**: ANSWER after first search returns documents with advisory/description content
- **List/filter queries**: ANSWER after first search returns matching documents
- **Coverage queries**: May need 2-3 searches for multiple percentages, but each search must be different

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

NESTED ADVISORY CHUNKS:
Each advisory is split into SEMANTIC SECTIONS, each queryable independently:
- advisory_chunks.section: One of [summary, remediation, testing, best_practices, details] (actual sections in data)
- advisory_chunks.is_code: Boolean (true if section contains code blocks) - Use to filter code examples: `advisory_chunks.{is_code:=true}` for code-only queries

⚠️ **DATASET REALITY - ADVISORY SECTIONS:**
The 8 CVEs with advisories are divided into these semantic sections:
- **summary**: High-level overview of the vulnerability
- **remediation**: How to fix or mitigate the vulnerability
- **testing**: Testing procedures and verification steps
- **best_practices**: Security best practices and recommendations
- **details**: Technical details, references, credits (catch-all for other content)

Note: Code blocks appear within sections (marked with is_code=true), not as a separate section type.

USE FILTERS FOR WELL-DOCUMENTED QUERIES - CRITICAL EXPLANATION:

⚠️ **Nested Field Filter Syntax** (for advisory_chunks):
- Typesense uses curly braces for nested objects: advisory_chunks.{section:=remediation}
- Returns CVEs that have at least one chunk with that section type
- Combine with has_advisory:true: "has_advisory:true && advisory_chunks.{section:=remediation}"
- Valid sections: summary, remediation, testing, best_practices, details (from ingestion section categorization)
- For code-only queries: advisory_chunks.{is_code:=true} (marked during chunking)

✅ **Examples:**
- "Show CVEs with remediation guidance": additional_filters="has_advisory:true && advisory_chunks.{section:=remediation}"
- "Show CVEs with testing documentation": additional_filters="has_advisory:true && advisory_chunks.{section:=testing}"
- "Show code examples": additional_filters="has_advisory:true && advisory_chunks.{is_code:=true}"

❌ **Common mistakes:**
- Missing curly braces: "advisory_chunks.section:remediation" → ✅ use "advisory_chunks.{section:=remediation}"
- Wrong section names: Check valid types above (summary, remediation, testing, best_practices, details)
- Using semantic search when filtering needed: "remediation guidance" won't filter → ✅ use additional_filters instead

✅ **Search Parameters for Well-Documented Queries:**
- search_type="keyword" (filtering doesn't need semantic understanding)
- query="*" (all documents matching the filter)
- additional_filters="has_advisory:true && advisory_chunks.{section:=remediation}" (nested syntax with curly braces)
- per_page=0 (aggregations only - we just need counts, not documents)
- facet_by="vulnerability_type" (optional - show breakdown by type)

⚠️ **TYPESENSE ARCHITECTURAL PATTERN - Faceting on denormalized top-level fields:**
Typesense faceting works ONLY on top-level document fields (cve_id, package_name, severity, cvss_score, ecosystem, vulnerability_type).
These are created during CSV denormalization in ingestion (flattened from 4 normalized tables into one CVE document).
Nested fields (advisory_chunks.section) can be FILTERED but NOT FACETED (design tradeoff for storage efficiency).
Why denormalization? Search engines prefer one document per entity vs. joins at query time.

COVERAGE/PERCENTAGE QUERIES - PATTERN FOR NESTED FIELD COUNTING:
When users ask "what percentage have X, Y, and Z?":

1. Get total: search_vulnerabilities(query="*", additional_filters="has_advisory:true", per_page=0)
   → Save total_found
2. For each type (remediation, testing, best_practices):
   → search_vulnerabilities(query="*", additional_filters="has_advisory:true && advisory_chunks.{section:=TYPE}", per_page=0)
   → Save total_found for each
3. Calculate: percentage = (section_count / total) * 100

⚠️ **CRITICAL**: Don't combine multiple section filters with &&: ❌ "advisory_chunks.{section:=testing} && advisory_chunks.{section:=remediation}"
✅ Instead: Search for each section separately, then calculate percentages from results.

AGGREGATION QUERIES - Use top-level denormalized fields (from CSV ingestion):
Faceting counts distinct values of a field across matching documents. Always use per_page=0 for aggregations.
- "How many vulnerability types?" → query="*", facet_by="vulnerability_type", per_page=0
  (returns: total_found=47, facet_counts=[XSS: 5, SQLi: 3, RCE: 4, ...])
- "Vulnerabilities per ecosystem?" → query="*", facet_by="ecosystem", per_page=0
  (returns: npm: 18, pip: 17, maven: 12)
- "Advisory coverage by type?" → query="*", additional_filters="has_advisory:true", facet_by="vulnerability_type", per_page=0
  (shows which types among 8 CVEs with advisories have most documentation)

QUERY EXAMPLE (user asks for "well-documented with remediation"):
❌ DON'T: hybrid search for "remediation guidance" (returns all results, not filtered)
✅ DO: additional_filters="has_advisory:true && advisory_chunks.{section:=remediation}" (filters to actual advisory sections)

AFFECTED VERSIONS FILTERING - TOP-LEVEL vs NESTED FIELDS:

Each CVE document contains:
- **Top-level fields** (from CSV): affected_versions (version range), fixed_version (first patched version)
- **Nested field** (from advisory): affected_versions_data array with status info (vulnerable/safe/not affected)

**WHEN TO USE:**
- Top-level fields: "Show CVEs with fixes available" → Use fixed_version field (simple, fast)
- Nested field: "Filter by version status" → Use affected_version_status parameter (vulnerable/safe/not affected)

**EXAMPLES:**
- "Which vulnerabilities have patches?" → affected_version_status=["safe"] (shows versions marked as safe/patched)
- "What is the fixed version of CVE-2024-1234?" → Use top-level fixed_version in results (already in response)

DATASET FACTS:
- **Total CVE documents indexed**: 47 vulnerabilities
- **Ecosystems covered**: npm, pip, and maven
- **Security advisories**: 8 detailed advisory documents (17% of CVEs have rich advisory documentation)
  - Each advisory contains multiple sections: summary, remediation, testing, best_practices, details
  - Use additional_filters="has_advisory:true" to prioritize these when users ask for explanations, remediation steps, testing guidance, or best practices
- **Vulnerability types DEFINED**: 34 different types in the vulnerability_types.csv reference table
- **Vulnerability types USED**: 10 types appearing in the 47 CVE documents (SQL Injection, XSS, RCE, Path Traversal, etc.)
- **Advisory coverage by type**: Check via facet_by="vulnerability_type" on has_advisory:true queries
- **Severity distribution**: 
  - Critical: 4 vulnerabilities (8.5%)
  - High: 25 vulnerabilities (53.2%)
  - Medium: 14 vulnerabilities (29.8%)
  - Low: 4 vulnerabilities (8.5%)

=== QUERY ROUTING STRATEGY ===

Default to search_type="hybrid" unless user is asking ONLY about metadata or ONLY about concepts.

1. ANALYTICAL QUERIES (search_type="keyword"):
   Questions asking about counts, totals, or unique values of ANY field
   Triggers: "how many", "count", "total", "unique", "number of", "list all distinct", "what types"
   
   **CRITICAL BEHAVIOR**: Faceting on a field returns counts of that field's values in the result set.
   For broad inventory queries, use query="*" (all documents) with facet_by and per_page=0 for aggregations.
   
   Examples:
   - "How many vulnerability types do we have?"
     → query="*", facet_by="vulnerability_type", per_page=0
     → Returns COUNT of each vulnerability type across all 47 CVEs
   - "How many vulnerabilities per ecosystem?"
     → query="*", facet_by="ecosystem", per_page=0
     → Returns counts: npm (X), pip (Y), maven (Z)
   - "How many vulnerabilities have fixes available?"
     → query="*", facet_by="has_fix", per_page=0
     → Returns counts: true (X with fixes), false (Y without fixes)
   - "Average CVSS score by severity?"
     → query="*", facet_by="severity,cvss_score", per_page=0
     → Returns both counts (severity) and stats (CVSS average)
   - "What packages have the most vulnerabilities?"
     → query="*", facet_by="package_name", per_page=0, sort facet results by count
   
   **INTERPRETATION**: The facet counts show which values appear in the documents retrieved. 
   If you search all documents (query="*"), facet results show the complete distribution in the dataset.

2. HYBRID QUERIES (search_type="hybrid") - DEFAULT:
   Use by default: combines both metadata filters AND semantic understanding
   
   Examples (all benefit from hybrid):
   - "How do I fix CVE-2024-1234?"
     → query="fix remediation upgrade", cve_ids=["CVE-2024-1234"], per_page=5
   - "Critical npm vulnerabilities and their impact?"
     → query="impact consequences attack vectors", severity_levels=["Critical"], ecosystems=["npm"], per_page=20
   - "Explain SQL injection in npm vulnerabilities"
     → query="SQL injection attack mechanism explanation", ecosystems=["npm"], per_page=15

3. KEYWORD QUERIES (search_type="keyword") - ONLY when:
   Question is PURELY about filtering/aggregating metadata (no explanations/examples needed)
   Triggers: "list", "show", "filter" (when aggregation/faceting is NOT the goal)
   
   Examples:
   - "List all Critical vulnerabilities in npm" (showing documents, not counts)
     → query="*", severity_levels=["Critical"], ecosystems=["npm"], per_page=20
   - "Show vulnerabilities for CVE-2024-1234"
     → query="CVE-2024-1234", cve_ids=["CVE-2024-1234"], per_page=5
   - "Filter vulnerabilities with CVSS >= 9"
     → query="*", additional_filters="cvss_score:>=9.0", per_page=15

4. SEMANTIC QUERIES (search_type="semantic") - ONLY when:
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
**Valid facet_by field names**: "cve_id", "package_name", "ecosystem", "vulnerability_type", "severity", "cvss_score", "has_advisory", "has_fix"
Examples: "cvss_score" (returns avg/min/max), "ecosystem" (returns counts), "severity,vulnerability_type" (both), "has_fix" (returns counts for true/false)

**group_by**: Rarely needed with CVE-centric documents (each CVE is one unique document). 
Only use if you want to limit results per category (e.g., group_by="ecosystem" for 3 npm + 3 pip + 3 maven).

**additional_filters**: Raw Typesense filter for edge cases (e.g., "cvss_score:<=9.0", "has_advisory:true").

**query text**: 
- Keyword: Use "*" for all, or specific CVE ID/package/type terms
- Semantic: Descriptive natural language phrases (attack vectors, code examples, remediation steps)
- Hybrid: Action words (fix, remediation, code, example, impact) + filters

**cve_ids, ecosystems, severity_levels, vulnerability_types**: Pass as arrays (case-sensitive).
Valid: ecosystems=[npm, pip, maven], severity=[Critical, High, Medium, Low].

=== TYPESENSE USAGE GUIDELINES ===

- URL-encode filter values (spaces → +)
- Use && for AND, || for OR operators (no spaces)
- If facet aggregations fail, calculate stats manually from retrieved documents

=== FINAL ANSWER FORMATTING & ERROR HANDLING ===

IMPORTANT: Follow these formatting rules for Final Answer ONLY:

KEY RULES FOR FINAL ANSWER:
- ALWAYS start with "Final Answer:" prefix when you have enough information to answer
- Generate the COMPLETE, COMPREHENSIVE answer immediately after "Final Answer:" prefix
- Include ALL required elements in the answer:
  * Clear opening statement answering the question
  * Specific CVE IDs, CVSS scores, package names, ecosystems, versions
  * Code examples (vulnerable + fixed patterns) where applicable
  * Remediation steps or explanations
  * Markdown formatting (headers ##, bullets, code blocks ```python/```javascript)
  * Grounding statement at the end: "Source: X CVE records from the vulnerability database"
- DO NOT generate just "Final Answer:" without the complete answer text
- YOU MUST synthesize the answer NOW
- DO NOT respond with "Action:", "Thought:", "Action Input:" when you have data - use "Final Answer:" instead
- If 0 results after broad search, explain why and suggest alternatives

CRITICAL: When providing Final Answer, ALWAYS generate helpful, user-friendly response. Never return empty text or placeholder responses.

**For Successful Queries (include):**
1. Clear opening statement answering the question directly
2. Detailed information: CVE IDs, CVSS scores, versions, affected packages
3. Code examples where applicable (vulnerable + fixed patterns)
4. Remediation steps or explanations relevant to the query
5. **CRITICAL**: Clear grounding: "Source: X CVE records from the vulnerability database"

Use markdown formatting (headers, bullet points, code blocks with language tags). Aim for 500+ words minimum.

**For Aggregation/Statistical Queries (include):**
1. Clear statistical summary with key numbers (totals, counts, averages, min/max)
2. Breakdown by category if applicable (e.g., "10 types: SQL Injection (3), XSS (2), ...")
3. Interpretation for security impact or dataset context
4. Context and recommendations
5. Reference specific examples if available from the aggregations
6. **CRITICAL**: End with grounding: "Source: Analyzed X CVE records from the vulnerability database"
7. **IMPORTANT FOR COUNTING QUERIES**: If using facet_by, clearly state that counts represent the values found in the dataset. Example: "The dataset contains 10 distinct vulnerability types across 47 CVEs: [list them]"

**For Empty/No Results (instead of "No results found"):**
1. Explain what was searched (filters, query terms, vulnerability types)
2. Suggest why no results exist
3. Offer alternative queries to try
4. List valid search parameters (ecosystems: npm/pip/maven; severity: Critical/High/Medium/Low; types: XSS/SQL Injection/RCE; CVE-YYYY-*)

**For Ambiguous Queries (include):**
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
- Be specific and actionable""" + (chat_history_section if chat_history_section else "")


def get_react_iteration_prompt(
    user_question: str,
    iteration: int,
    previous_searches: list,
    collected_documents_data: dict = None,
    collected_aggregations_data: dict = None,
    search_parameters: list = None,
    is_final_iteration: bool = False,
) -> str:
    """Build a ReAct-format prompt following the official ReAct pattern.

    Uses the standard ReAct format: Thought → Action → Observation → Final Answer
    
    Args:
        user_question: Original user question
        iteration: Current iteration number (1-indexed)
        previous_searches: List of (search_type, query, results_count) tuples from previous iterations
        collected_documents_data: Actual document data collected (dict of CVE ID -> document)
        collected_aggregations_data: Actual aggregation data collected (dict of field -> stats)
        search_parameters: List of dicts with full search parameter details from each search
        is_final_iteration: True if this is the final iteration, demand answer instead of search

    Returns:
        Prompt in official ReAct format for Gemini with actual search results
    """
    # Initialize mutable defaults
    if collected_documents_data is None:
        collected_documents_data = {}
    if collected_aggregations_data is None:
        collected_aggregations_data = {}
    if search_parameters is None:
        search_parameters = []
    
    # Calculate counts from actual data
    documents_collected = len(collected_documents_data)
    aggregations_collected = len(collected_aggregations_data)
    # Build the scratchpad (observation history)
    scratchpad = ""
    if previous_searches:
        # First, add an explicit DO NOT search list to prevent LLM from suggesting duplicates
        scratchpad += f"\n{'='*80}\n🚫 SEARCHES ALREADY PERFORMED - DO NOT REPEAT:\n"
        for i, params in enumerate(search_parameters, 1):
            search_type = params.get('search_type', 'hybrid')
            query = params.get('query', '*')
            filters = params.get('filters', '')
            cve_ids = params.get('cve_ids', [])
            ecosystems = params.get('ecosystems', [])
            severity_levels = params.get('severity_levels', [])
            vulnerability_types = params.get('vulnerability_types', [])
            has_fix = params.get('has_fix')
            published_date_after = params.get('published_date_after')
            
            scratchpad += f"\n❌ Search {i} ALREADY DONE - DO NOT REPEAT:\n"
            scratchpad += f"  search_type='{search_type}', query='{query}'\n"
            if filters:
                scratchpad += f"  additional_filters='{filters}'\n"
            if cve_ids:
                scratchpad += f"  cve_ids={cve_ids}\n"
            if ecosystems:
                scratchpad += f"  ecosystems={ecosystems}\n"
            if severity_levels:
                scratchpad += f"  severity_levels={severity_levels}\n"
            if vulnerability_types:
                scratchpad += f"  vulnerability_types={vulnerability_types}\n"
            if has_fix is not None:
                scratchpad += f"  has_fix={has_fix}\n"
            if published_date_after:
                scratchpad += f"  published_date_after='{published_date_after}'\n"
        
        # Then show what was found
        scratchpad += f"\n{'='*80}\nSearch History ({len(previous_searches)} attempts):\n"
        for i, (search_type, query, results_count) in enumerate(previous_searches, 1):
            scratchpad += f"Observation {i}: Searched with {search_type} (query: '{query}') → Found {results_count} results\n"
        
        # Add clear guidance
        scratchpad += f"\n⚠️ DEDUPLICATION REMINDER:\n"
        scratchpad += f"The '🚫 DO NOT REPEAT' list above shows exact search combinations that were already executed.\n"
        scratchpad += f"If you propose ANY of these exact combinations, it WILL be skipped (wasting your iteration).\n"
        scratchpad += f"INSTEAD: Propose a DIFFERENT search with changed: search_type, query, or filters.\n"
    
    # Add collected data summary
    scratchpad += f"\n{'='*80}\nData Collected So Far:\n"
    scratchpad += f"  - Unique CVE Documents: {documents_collected}\n"
    scratchpad += f"  - Aggregation Fields: {aggregations_collected}\n"
    
    # Add STRONG stopping recommendation if data is present
    if documents_collected > 0 or aggregations_collected > 0:
        scratchpad += f"\n🚨 YOU HAVE DATA - STRONG RECOMMENDATION TO ANSWER:\n"
        if documents_collected > 0:
            scratchpad += f"  ✅ You have {documents_collected} CVE document(s) - SUFFICIENT for most queries\n"
            scratchpad += f"  ✅ Default action: Provide 'Final Answer:' using these documents\n"
            scratchpad += f"  ⚠️ Only search again if documents are COMPLETELY irrelevant or wrong\n"
        if aggregations_collected > 0:
            scratchpad += f"  ✅ You have {aggregations_collected} aggregation field(s) - SUFFICIENT for statistical queries\n"
            scratchpad += f"  ✅ Default action: Provide 'Final Answer:' using these statistics\n"
        scratchpad += f"\n"
    
    # Add actual aggregation results
    if collected_aggregations_data:
        scratchpad += f"\n{'='*80}\nAggregation Results:\n"
        for field, agg_data in collected_aggregations_data.items():
            if isinstance(agg_data, dict):
                if "stats" in agg_data:
                    stats = agg_data["stats"]
                    scratchpad += f"  {field} Statistics:\n"
                    scratchpad += f"    - Average: {stats.get('avg', 'N/A')}\n"
                    scratchpad += f"    - Minimum: {stats.get('min', 'N/A')}\n"
                    scratchpad += f"    - Maximum: {stats.get('max', 'N/A')}\n"
                    scratchpad += f"    - Sum: {stats.get('sum', 'N/A')}\n"
                if "counts" in agg_data:
                    scratchpad += f"  {field} Counts:\n"
                    for count_item in agg_data["counts"][:20]:  # Top 20
                        scratchpad += f"    - {count_item.get('value', 'N/A')}: {count_item.get('count', 0)} vulnerabilities\n"
        
        scratchpad += f"\n🎯 AGGREGATION DATA:\n"
        scratchpad += f"   ✅ You have complete statistical data for the user's query\n"
        scratchpad += f"   ✅ For analytical/counting queries, this is ALL you need\n"
        scratchpad += f"   ✅ You can optionally search ONCE MORE for specific CVE examples to enrich the answer\n"
        scratchpad += f"   ✅ But you ALREADY have sufficient data to provide a complete answer\n"
    
    # Add actual document details
    if collected_documents_data:
        scratchpad += f"\n{'='*80}\nCollected CVE Documents ({documents_collected} total):\n"
        scratchpad += f"\n🎯 DOCUMENT DATA:\n"
        scratchpad += f"   ✅ You have {documents_collected} CVE document(s) with complete details\n"
        scratchpad += f"   ✅ Each document contains: CVE ID, package, ecosystem, severity, CVSS, description, versions\n"
        scratchpad += f"   ⚠️ DEFAULT ACTION: Provide 'Final Answer:' using these documents NOW\n"
        scratchpad += f"   ⚠️ Only search again if these documents are COMPLETELY wrong/irrelevant\n\n"
        
        for idx, (cve_id, doc) in enumerate(list(collected_documents_data.items())[:20], 1):  # Limit to 20 for token efficiency
            scratchpad += f"\n{idx}. CVE: {cve_id}\n"
            scratchpad += f"   Package: {doc.get('package_name', 'N/A')}\n"
            scratchpad += f"   Ecosystem: {doc.get('ecosystem', 'N/A')}\n"
            scratchpad += f"   Severity: {doc.get('severity', 'N/A')}\n"
            scratchpad += f"   CVSS Score: {doc.get('cvss_score', 'N/A')}\n"
            scratchpad += f"   Vulnerability Type: {doc.get('vulnerability_type', 'N/A')}\n"
            scratchpad += f"   Published Date: {doc.get('published_date', 'N/A')}\n"
            scratchpad += f"   Fixed Version: {doc.get('fixed_version', 'N/A')}\n"
            scratchpad += f"   Affected Versions: {doc.get('affected_versions', 'N/A')}\n"
            
            if doc.get("description"):
                desc = doc['description']
                scratchpad += f"   Description: {desc[:500] if len(desc) > 500 else desc}\n"

            if doc.get("advisory_text"):
                advisory = doc['advisory_text']
                scratchpad += f"   Advisory: {advisory[:1000] if len(advisory) > 1000 else advisory}\n"
        
        if documents_collected > 20:
            scratchpad += f"\n... and {documents_collected - 20} more documents\n"
    
    # Build the ReAct format prompt
    prompt = f"""Use the following format:

Thought: you should always think about what to do
Action: the action to take, should be one of [search_vulnerabilities]
Action Input: the input parameters for the action
Observation: the result of the action
Thought: reflect on the observations
... (this Thought/Action/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: <COMPLETE COMPREHENSIVE ANSWER WITH ALL CITATIONS AND FORMATTING>

Question: {user_question}{scratchpad}

{'='*80}
CRITICAL DECISION POINT - Iteration {iteration}:

You have collected:
- {documents_collected} CVE documents
- {aggregations_collected} aggregation fields
- {len(previous_searches)} searches completed so far

{("🛑 THIS IS YOUR FINAL ITERATION - YOU MUST PROVIDE 'Final Answer:' WITH A COMPLETE ANSWER NOW (using aggregations if no documents, or combining both)") if is_final_iteration else ""}

DECISION LOGIC:

{f"✅ **YOU HAVE {documents_collected} DOCUMENTS** - This is SUFFICIENT to answer most questions. PROVIDE FINAL ANSWER NOW unless:" if documents_collected > 0 else "❌ **NO DOCUMENTS YET**"}
{f"   • The documents are completely irrelevant to the user's question (wrong CVE, wrong topic)" if documents_collected > 0 else ""}
{f"   • You need ONE more specific search to get the exact information requested" if documents_collected > 0 else ""}
{f"\n✅ **YOU HAVE {aggregations_collected} AGGREGATION FIELDS** - This is SUFFICIENT for statistical/counting queries. PROVIDE FINAL ANSWER NOW." if aggregations_collected > 0 else ""}

{"🛑 **DEFAULT ACTION: PROVIDE FINAL ANSWER**" if (documents_collected > 0 or aggregations_collected > 0) else "⚠️ **NEED TO SEARCH** - No data collected yet"}

MANDATORY RULES:
1. ⚠️ If you have ANY documents or aggregations, DEFAULT to answering (don't search unnecessarily)
2. ⚠️ DO NOT repeat ANY search from the "🚫 SEARCHES ALREADY PERFORMED - DO NOT REPEAT" list above
   - If you suggest one anyway, it WILL be silently skipped (wasting your iteration)
   - To try a new search, CHANGE: search_type, query, filters, or constraints
3. ⚠️ After 2 searches, you MUST answer (no "I need more data" - synthesize what you have)
4. DO NOT respond with "Action:", "Thought:", "Action Input:" - ONLY "Final Answer:" or function call
{("🛑 FINAL ITERATION WARNING - YOU MUST ANSWER NOW:\n   ❌ NO MORE SEARCHES ALLOWED\n   ✅ MUST provide Final Answer using collected aggregations/documents\n   ✅ If only aggregations available, answer with statistical insights and analysis\n   ✅ Do NOT apologize or say you need more data - synthesize what you have") if is_final_iteration else ""}

⚠️ SEARCH COUNT WARNING: You have done {len(previous_searches)} search(es).
{f"↳ You have {2 - len(previous_searches)} search(es) remaining before you MUST answer" if len(previous_searches) < 2 else "↳ You have EXHAUSTED your search budget. PROVIDE FINAL ANSWER NOW."}
{f"\n↳ ⚠️ STRONGLY CONSIDER answering now with the {documents_collected} documents you have" if len(previous_searches) == 1 and documents_collected > 0 else ""}
{f"\n↳ ⚠️ STRONGLY CONSIDER answering now with the aggregations you have" if len(previous_searches) == 1 and aggregations_collected > 0 else ""}

DECISION CRITERIA (CHECK IN ORDER):
1. ✅ Have {documents_collected} documents AND {len(previous_searches)} >= 1 search? → **ANSWER NOW** (most likely sufficient)
2. ✅ Have {aggregations_collected} aggregation fields? → **ANSWER NOW** (sufficient for stats queries)
3. ✅ Searched {len(previous_searches)} >= 2 times? → **ANSWER NOW** (mandatory, no exceptions)
4. ⚠️ First search returned 0 results? → Try ONE different search strategy, then ANSWER
5. ⚠️ First search returned wrong results? → Try ONE refined search, then ANSWER

⚠️ CRITICAL FORMAT REQUIREMENT:
Your response MUST be ONE of these two options:
  OPTION 1: A function call to search_vulnerabilities() - only if you genuinely need more data
  OPTION 2: "Final Answer: <YOUR COMPLETE ANSWER HERE>" - provide the full answer immediately

❌ DO NOT respond with anything else
❌ DO NOT include "Thought:", "Action:", or any other text
❌ DO NOT say "I'll provide the answer" or "Let me search" - just DO IT
❌ DO NOT write "Final Answer:" without the complete answer text following it

IF YOU PROVIDE FINAL ANSWER:
- Start with "Final Answer:" prefix (case-insensitive, but "Final Answer:" is preferred)
- Generate the COMPLETE, COMPREHENSIVE answer immediately after the prefix
- Include ALL elements: CVE IDs, CVSS scores, packages, ecosystems, versions, code examples, remediation steps
- Use markdown formatting (headers ##, bullets, code blocks)
- End with grounding statement: "Source: X CVE records from the vulnerability database"
- DO NOT respond with ReAct format ("Thought:", "Action:") - provide the FINAL ANSWER NOW

Next step (MUST be either function call OR "Final Answer: <complete answer>"):"""
    return prompt
