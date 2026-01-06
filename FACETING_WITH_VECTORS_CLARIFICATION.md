# Faceting & Filtering with Vector Search - Clarification

## The Question

> "Q2: Why use section-aware chunking instead of sliding windows or fixed-size chunks?"
> 
> **A: "Enables Faceted Search"** — Tag each chunk with section type (remediation, code_example, etc.), users can request "Show remediation steps" specifically, agent can route "how to fix" questions to remediation chunks
>
> **But wait...** Does faceting work with vectors? How does this work?

Great question! Let me clarify the nuance here.

---

## ✅ YES: Filtering Works With Vectors

Typesense allows you to **filter vector search results** just like keyword search. The `filter_by` parameter applies to ALL search types (keyword, semantic, hybrid).

### Example: Filter by Section Type in Semantic Search

```python
# Semantic search for "how to fix this vulnerability?" but ONLY in remediation sections
search_result = search_tool.search_vulnerabilities(
    query="how to fix this vulnerability?",
    search_type="semantic",  # Vector similarity on query embedding
    additional_filters="advisory_chunks.section:remediation"  # ← Filter nested field
)
```

**What happens:**
1. Encode query → `[0.123, -0.456, ...]`
2. Search vector index for nearest neighbors
3. **THEN apply filter:** Keep only documents where `advisory_chunks.section == "remediation"`
4. Return filtered results ranked by vector similarity

---

## ✅ YES: Faceting (Aggregations) Works With Vectors Too

The `facet_by` parameter also works with all search types:

```python
# Semantic search + faceting
search_result = search_tool.search_vulnerabilities(
    query="SQL injection",
    search_type="semantic",
    facet_by="advisory_chunks.section,severity"  # ← Get counts per section
)

# Results include:
# {
#   "documents": [...results...],
#   "aggregations": {
#     "advisory_chunks.section": {
#       "counts": [
#         {"value": "remediation", "count": 5},
#         {"value": "code_example", "count": 3},
#         {"value": "summary", "count": 8}
#       ]
#     },
#     "severity": {
#       "counts": [
#         {"value": "Critical", "count": 10},
#         {"value": "High", "count": 6}
#       ]
#     }
#   }
# }
```

Agent can say: *"Found 16 SQL injection results. Most are in the summary section (8), followed by remediation (5). Here are the top Critical ones..."*

---

## ⚠️ BUT: The Current Implementation Has a Gap

### What We Claim (In INTERVIEW_QA.md)

> "Enables Faceted Search: Tag each chunk with section type (remediation, code_example, etc.), users can request 'Show remediation steps' specifically, **agent can route 'how to fix' questions to remediation chunks**"

### What Actually Happens

The **agent does NOT actively route** "how to fix" questions to remediation sections. Here's why:

#### Current Behavior: **Implicit Semantic Routing**

```python
# Actual code in search_tool.py function signature
def search_vulnerabilities(
    self,
    query: str = "*",
    search_type: Literal["keyword", "semantic", "hybrid"] = "hybrid",
    # ... other params ...
    additional_filters: Optional[str] = None,  # ← Available but NOT used by agent
)

# The agent calls the search with automatic function calling:
# It asks Gemini "what tool should I use?" but Gemini's schema
# doesn't mention "optional section filtering"
```

#### Current Agent Flow

User: *"Show me remediation steps for critical vulnerabilities"*

Agent decides: **Hybrid search** with query="remediation steps" + severity filter
- ✅ Hybrid search on "remediation steps" → semantic matching finds actual remediation content
- ✅ Filter severity="Critical"
- ❌ Does NOT explicitly filter `advisory_chunks.section:remediation`

**Why?**
- Semantic search is **implicit**: Encoding "remediation steps" naturally finds remediation chunks
- Semantic similarity already prioritizes relevant sections
- No need for explicit filtering when vector similarity handles it

#### What the Code Could Do (But Doesn't)

```python
# This is POSSIBLE in Typesense but NOT implemented in current agent:

if "fix" in user_question.lower() or "remediation" in user_question.lower():
    additional_filters = "advisory_chunks.section:remediation"
    # Explicitly filter to only show remediation sections
    
search_vulnerabilities(
    query=user_question,
    search_type="semantic",
    additional_filters=additional_filters  # ← Explicit section routing
)
```

---

## 🎯 The Design Trade-Off

### Explicit Routing (Implement Section Filtering)

**Pros:**
- Precise: "Show remediation" returns ONLY remediation sections
- Predictable: Same query always targets same section
- Audit trail: Can see in logs which queries use which sections
- Interview answer: "The agent intelligently routes queries to relevant sections"

**Cons:**
- More complex: Agent needs query classification logic
- Brittleness: Variations like "how to fix", "repair", "patch" need explicit handling
- Over-filtering: Misses cross-section insights (e.g., summary might mention remediation)

### Implicit Routing (Current: Semantic Matching)

**Pros:**
- Simpler: Rely on vector similarity to find relevant content
- Flexible: "show remediation", "fix this", "patch steps" all work
- Robustness: Finds remediation-like content even in unexpected sections
- Fewer iterations: Semantic search finds answer in 1 iteration usually

**Cons:**
- Less transparent: How does it know to pick remediation?
- Interview confusion: Claim about "routing" isn't literally true
- No section-aware aggregations: Can't answer "how many CVEs have remediation steps?"

---

## 📋 What to Clarify in Interview

### If Asked: "Does Faceting Work With Vectors?"

**A (Short):** "Yes, absolutely. Typesense applies filters to vector search results, then aggregates. So we could filter `advisory_chunks.section:remediation` in a semantic search and get counts per severity."

### If Asked: "So Does the Agent Route to Remediation Sections?"

**A (Honest):** "It depends on what you mean by 'route':

- **Semantically, yes:** When the agent searches for 'remediation steps', the vector embeddings naturally prioritize remediation chunks. Semantic similarity handles section selection implicitly.

- **With explicit filters, no:** The current implementation doesn't actively set `additional_filters='advisory_chunks.section:remediation'` for 'how to fix' questions. It relies on the query wording + vector similarity.

- **Trade-off we made:** Implicit routing is simpler and more flexible. Explicit routing would be more precise but requires query classification logic.

- **Could be extended:** We could add logic like 'if query contains fix/remediation/patch, set section filter', but current design trusts semantic search to do this naturally."

### If They Push: "Isn't That Misleading in the Q&A?"

**A (Acknowledge):** "Fair point. The Q&A says 'agent can route to remediation chunks', which technically means the vector search naturally finds remediation-relevant content. But the *mechanism* is semantic similarity, not explicit section filtering. The section tags enable faceting/aggregations, which we use for answer synthesis ('5 results, 3 have remediation steps'). Would be good to clarify that distinction."

---

## 💾 Code Evidence

### What Filtering Looks Like (from `src/search_tool.py`)

```python
def _build_filters(self, ..., additional_filters: Optional[str] = None):
    """Build Typesense filter expression from parameters."""
    filters = []
    
    # These all work with vector search:
    if cve_ids:
        filters.append(f"cve_id:[{','.join(cve_ids)}]")
    if ecosystems:
        filters.append(f"ecosystem:[{','.join(ecosystems)}]")
    if severity_levels:
        filters.append(f"severity:[{','.join(severity_levels)}]")
    
    # This is how you'd filter nested advisory_chunks:
    if additional_filters:
        filters.append(additional_filters)
        # Examples: "advisory_chunks.section:remediation"
        #           "has_advisory:true"
        #           "cvss_score:>8.0"
    
    return " && ".join(filters)  # Combine with AND logic

# In search_vulnerabilities:
if filters:
    search_params["filter_by"] = filters  # ← Applies to ALL search types

if search_type in ("semantic", "hybrid"):
    # Vector search still respects filter_by!
    multi_response = self.client.multi_search.perform(search_request)
    # Result: Vector search + filter applied
```

### What the Agent Actually Does

```python
# From src/agent.py _execute_search_and_collect:
args_dict = dict(function_call.args)  # Get what Gemini chose
search_result = self.search_tool.search_vulnerabilities(**args_dict)

# Gemini's parameters come from tool schema (src/prompts.py)
# Schema includes: search_type, query, filters, facet_by, additional_filters
# But agent rarely uses additional_filters in practice
# It relies on query wording + search_type selection
```

### What Happens With Faceting

```python
# From search_tool.py response parsing:
if facet_by:
    search_params["facet_by"] = facet_by  # "ecosystem,severity"

# Typesense returns:
{
    "facet_counts": [
        {
            "field_name": "ecosystem",
            "counts": [
                {"value": "npm", "count": 15},
                {"value": "pip", "count": 8}
            ]
        }
    ]
}

# Agent uses this in synthesized answer:
# "15 npm vulnerabilities, 8 pip"
```

---

## 🎓 Summary Table

| Aspect | Capability | Current Implementation | Interview Answer |
| --- | --- | --- | --- |
| **Filter by section** | ✅ Works with vectors | ❌ Available but unused | "Typesense supports it; we use semantic routing instead" |
| **Faceting on sections** | ✅ Works with vectors | ⚠️ Possible but not factored on sections | "Returns aggregations; could facet by section if needed" |
| **Route 'fix' to remediation** | ✅ Via explicit filter | ❌ Via semantic matching | "Vector similarity handles it implicitly" |
| **Explain section-aware design** | ✅ Enables chunking strategy | ✅ Used for answer synthesis | "Tags sections for faceting & structured output" |

---

## 🚀 If You Want to Implement Explicit Routing

Here's how to add query classification:

```python
def _should_filter_by_section(self, query: str) -> Optional[str]:
    """Detect if query asks for specific section."""
    if any(word in query.lower() for word in ['fix', 'remediation', 'patch', 'solution', 'resolve']):
        return "remediation"
    elif any(word in query.lower() for word in ['example', 'code', 'snippet']):
        return "code_example"
    elif any(word in query.lower() for word in ['overview', 'summary', 'explain', 'what']):
        return "summary"
    return None

# Then in agent's search decision:
section_filter = self._should_filter_by_section(query)
if section_filter:
    additional_filters = f"advisory_chunks.section:{section_filter}"
```

But this adds complexity and brittleness. Current implicit approach is simpler and works well.

---

## ✨ Key Takeaway

**Faceting with vectors** is fully supported by Typesense. The current implementation:
- ✅ CAN filter section in vector search (technical capability)
- ❌ DOESN'T actively do so (design choice)
- ✅ USES section tags for chunking & synthesis (via semantic similarity)
- ✅ COULD easily add explicit routing (if needed)

Make sure your interview answer distinguishes between:
1. **What's technically possible** (filtering + faceting work with vectors)
2. **What we actually do** (semantic routing via vector similarity)
3. **Why we chose it** (simpler, more flexible, relies on embeddings)
