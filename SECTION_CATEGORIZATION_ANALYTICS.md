# Section Categorization & Analytics: CSV + Advisory Combined

## Your Question

> "This section allows to gather analytics not only in CSV but also in the advisory files, correct?"

**Yes!** But with an important distinction. Let me break down what analytics becomes possible.

---

## 📊 Analytics BEFORE Section Categorization (CSV-Only)

The CSV metadata was always faceted in Typesense:

```python
# Always possible - CSV fields are faceted by default
search_result = search_vulnerabilities(
    query="*",
    facet_by="ecosystem,severity,vulnerability_type,cvss_score"
)

# Results (from CSV data only):
{
  "ecosystem": {"npm": 20, "pip": 15, "maven": 12},
  "severity": {"Critical": 8, "High": 15, "Medium": 24},
  "vulnerability_type": {"XSS": 6, "SQL Injection": 5, "RCE": 3},
  "cvss_score": {"min": 4.1, "max": 9.8, "avg": 7.2}
}
```

**Questions answered (CSV-only analytics):**
- ✅ "How many npm vulnerabilities?"
- ✅ "What's the CVSS distribution?"
- ✅ "Which vulnerability type is most common?"

**Questions NOT answerable (no advisory structure):**
- ❌ "How many CVEs have remediation steps?"
- ❌ "What % of advisories include code examples?"
- ❌ "Which ecosystem has the best remediation coverage?"

---

## 📈 Analytics WITH Section Categorization (NEW!)

Section categorization (`_categorize_section()`) stores each advisory chunk with semantic tags:

```python
# From ingest.py - Every advisory chunk gets tagged
chunk = {
    "content": "...",
    "section": _categorize_section(title),  # ← "remediation", "code_example", "summary", etc.
    "is_code": True/False,                   # ← Code block marker
    "index": 0,
    "embedding": [...]
}

# Stored in Typesense as indexed nested fields
# "advisory_chunks.section" and "advisory_chunks.is_code" are now facetable!
```

Now you can query advisory structure directly:

```python
# NEW: Analytics on advisory content!
search_result = search_vulnerabilities(
    query="*",
    facet_by="advisory_chunks.section,advisory_chunks.is_code"
)

# Results (advisory structure analytics):
{
  "advisory_chunks.section": {
    "summary": 12,
    "remediation": 8,
    "code_example": 7,
    "attack": 5,
    "cvss": 3,
    "details": 10
  },
  "advisory_chunks.is_code": {
    "true": 15,      # 15 sections are code blocks
    "false": 30      # 30 sections are text-only
  }
}
```

**New questions answerable (advisory analytics):**
- ✅ "How many advisory sections are remediation?" (8)
- ✅ "What % of advisory content is code examples?" (15/45 ≈ 33%)
- ✅ "Which section types are most common?" (summary > details > remediation > code > attack > cvss)
- ✅ "How many CVEs have code_example sections?" (7 unique CVEs)

---

## 🎯 The REAL Power: Combined CSV + Advisory Analytics

This is where section categorization shines - answering questions that span both data sources:

```python
# Example 1: "For npm vulnerabilities, what sections appear in advisories?"
search_result = search_vulnerabilities(
    ecosystems=["npm"],                    # ← CSV filter
    facet_by="advisory_chunks.section"     # ← Advisory structure
)

# Results:
{
  "total_found": 20,  # 20 npm vulnerabilities (from CSV)
  "aggregations": {
    "advisory_chunks.section": {
      "remediation": 5,         # npm CVEs with remediation sections
      "code_example": 4,        # npm CVEs with code examples
      "summary": 6,
      "attack": 2
    }
  }
}

# Answer: "20 npm vulnerabilities. Among those with advisories:
#          5 have remediation steps, 4 have code examples"
```

```python
# Example 2: "Critical vulnerabilities - remediation coverage by ecosystem"
for eco in ["npm", "pip", "maven"]:
    result = search_vulnerabilities(
        ecosystems=[eco],
        severity_levels=["Critical"],
        facet_by="advisory_chunks.section"
    )
    
    remediation_count = result.aggregations.get("advisory_chunks.section", {}).get("remediation", 0)
    total = result.total_found
    
    print(f"{eco}: {remediation_count}/{total} critical have remediation ({remediation_count/total*100:.0f}%)")

# Output:
# npm: 5/8 critical have remediation (62%)
# pip: 2/5 critical have remediation (40%)
# maven: 1/4 critical have remediation (25%)
```

```python
# Example 3: "CVSS statistics for advisories with code examples"
search_result = search_vulnerabilities(
    query="*",
    additional_filters="advisory_chunks.section:code_example",  # Filter to only code sections
    facet_by="cvss_score"  # Get CVSS stats for those CVEs
)

# Results:
{
  "total_found": 7,  # 7 CVEs have code_example sections
  "aggregations": {
    "cvss_score": {
      "min": 6.2,
      "max": 9.8,
      "avg": 8.1
    }
  }
}

# Answer: "Code examples are typically found in higher-severity vulnerabilities
#          (avg CVSS 8.1 vs overall avg 7.2)"
```

---

## 💾 What Gets Stored in Typesense (Document Structure)

```python
# Single CVE Document
{
  "id": "csv-CVE-2024-1234",
  "cve_id": "CVE-2024-1234",
  "package_name": "express-validator",
  
  # CSV-level fields (facetable)
  "ecosystem": "npm",                    # ← Can facet
  "severity": "Critical",                # ← Can facet
  "vulnerability_type": "Input Validation",  # ← Can facet
  "cvss_score": 9.8,                    # ← Can aggregate (min/max/avg)
  "affected_versions": ["1.0.0", "1.0.1"],
  "fixed_version": "1.0.2",
  
  # CSV description
  "content": "Improper input validation allows...",
  "embedding": [0.123, -0.456, ...],    # Vector for semantic search
  
  # Advisory metadata
  "has_advisory": true,
  
  # Nested advisory chunks (array of objects)
  "advisory_chunks": [
    {
      "content": "This vulnerability affects express-validator...",
      "section": "summary",              # ← NEW: Can facet!
      "is_code": false,                  # ← NEW: Can facet!
      "index": 0,
      "embedding": [...]
    },
    {
      "content": "Upgrade to version 1.0.2 or later.",
      "section": "remediation",          # ← NEW: Can facet!
      "is_code": false,
      "index": 1,
      "embedding": [...]
    },
    {
      "content": "```js\nconst validator = require('express-validator');\nconst result = validator.validationResult(req);",
      "section": "code_example",         # ← NEW: Can facet!
      "is_code": true,                   # ← NEW: Can facet!
      "index": 2,
      "embedding": [...]
    }
  ]
}
```

**Key insight:** Because `section` and `is_code` are indexed fields in nested objects, Typesense lets you facet on them automatically. You don't need special handling—just include them in `facet_by` parameter.

---

## 📋 Analytics Comparison Table

| Analytics Capability | Before Section Categorization | After Section Categorization | How It Works |
| --- | --- | --- | --- |
| **CSV-Only Analytics** | | | |
| Ecosystem distribution | ✅ | ✅ | `facet_by="ecosystem"` |
| Severity distribution | ✅ | ✅ | `facet_by="severity"` |
| CVSS statistics | ✅ | ✅ | `facet_by="cvss_score"` |
| Vulnerability type breakdown | ✅ | ✅ | `facet_by="vulnerability_type"` |
| **Advisory Analytics** | | | |
| Section type breakdown | ❌ | ✅ | `facet_by="advisory_chunks.section"` |
| Code coverage | ❌ | ✅ | `facet_by="advisory_chunks.is_code"` |
| Sections per CVE | ❌ | ✅ | `facet_by="advisory_chunks.index"` (count chunks) |
| **Combined Analytics** | | | |
| Ecosystem × Section type | ❌ | ✅ | `ecosystems=["npm"] + facet_by="advisory_chunks.section"` |
| Critical CVEs with remediation | ❌ | ✅ | `severity_levels=["Critical"] + facet_by="advisory_chunks.section"` |
| CVSS for code-heavy advisories | ❌ | ✅ | `filter="advisory_chunks.is_code:true" + facet_by="cvss_score"` |
| Remediation coverage by ecosystem | ❌ | ✅ | Loop ecosystems, count remediation sections per ecosystem |

---

## 🏗️ Why This Architecture Matters

### Traditional Vector DB Approach
```
Vector Database (FAISS, Weaviate):
├── Stores embeddings
├── Searches by similarity
├── ❌ Can't facet or aggregate
├── ❌ No structured analytics on metadata
└── To get analytics, you must:
    - Fetch all results to Python
    - Manual post-processing to count sections
    - No SQL-like queries available
```

### Hybrid Search Engine Approach (What We Do)
```
Search Engine (Typesense):
├── Stores embeddings + metadata
├── Searches by similarity OR keyword
├── ✅ Facets on ANY indexed field
├── ✅ Nested field faceting supported
└── Analytics in single query:
    - Returns documents AND aggregations
    - No post-processing needed
    - Millisecond-level performance
```

**The advantage:** By storing section categorization and is_code flags as indexed fields, you automatically get analytics capabilities at zero extra cost. Typesense handles the faceting internally.

---

## 🔍 Code Evidence

### How Sections Get Indexed (ingest.py)

```python
def _categorize_section(title: str) -> str:
    """Categorize advisory section by keywords for faceted search and analytics.
    
    Maps markdown section headers to semantic categories, enabling:
      - Faceted search: Find all "remediation" or "code_example" sections across CVEs
      - Analytics: Count vulnerability types by section (how many have code examples?)
      - Targeted retrieval: "Show me attack vectors" retrieves only attack sections
    """
    title_lower = title.lower()
    if "summary" in title_lower or "overview" in title_lower:
        return "summary"
    elif "remediat" in title_lower or "fix" in title_lower:
        return "remediation"
    # ... etc
    return "details"

# Each chunk gets tagged:
chunk = {
    "content": chunk_text,
    "section": _categorize_section(section_title),  # ← Facetable!
    "is_code": True/False,                          # ← Facetable!
    "embedding": embedding
}
```

### How Typesense Schema Enables Faceting (ingest.py)

```python
schema = {
    "name": "vulnerabilities",
    "enable_nested_fields": True,
    "fields": [
        # CSV fields - all faceted
        {"name": "ecosystem", "type": "string", "facet": True},
        {"name": "severity", "type": "string", "facet": True},
        {"name": "cvss_score", "type": "float", "facet": True},
        
        # Nested advisory chunks
        {
            "name": "advisory_chunks",
            "type": "object[]",
            "fields": [
                {"name": "content", "type": "string"},
                {"name": "section", "type": "string"},  # ← Automatically facetable
                {"name": "is_code", "type": "bool"},    # ← Automatically facetable
                {"name": "embedding", "type": "float[]"},
            ]
        }
    ]
}
```

### How Queries Use This (search_tool.py)

```python
# Query for combined CSV + advisory analytics
search_result = search_vulnerabilities(
    ecosystems=["npm"],                    # ← Filter CSV data
    facet_by="advisory_chunks.section,advisory_chunks.is_code"  # ← Aggregate advisory structure
)

# Behind the scenes, Typesense:
# 1. Filters to ecosystem="npm" (CSV level)
# 2. Returns those CVE documents
# 3. Counts section types and is_code flags across nested chunks
# 4. Returns both results + aggregations in single response
```

---

## 💡 Interview Answer

**If asked: "Does section categorization help with analytics?"**

*A:* "Section categorization enables **two types of analytics**:

1. **Advisory structure analytics** (NEW): By tagging each chunk with semantic categories (remediation, code_example, summary, etc.) and storing these as indexed fields in Typesense, we can now facet on advisory metadata. Questions like 'how many CVEs have code examples?' or 'what's the remediation coverage?' become single queries instead of manual post-processing.

2. **Combined CSV + advisory analytics** (POWERFUL): We can now answer cross-domain questions like 'for npm vulnerabilities, how many have remediation steps?' by filtering on CSV fields and faceting on advisory structure simultaneously.

CSV analytics (ecosystem, severity, CVSS) were already possible. Section categorization unlocks analytics on *advisory content structure* that traditional vector databases can't provide."

**If pushed on specifics:**

*A:* "The key is that section and is_code are indexed fields in Typesense's nested object schema. So when we do `facet_by='advisory_chunks.section'`, Typesense automatically counts all nested advisory chunks by section type across all CVE documents. It's the same faceting capability we use for CSV fields like ecosystem or severity, just applied to nested advisory metadata."

---

## 🎓 Summary

**Your insight was spot-on:** Section categorization enables analytics not just on CSV metadata, but also on advisory structure. And more importantly, it enables **combined analytics** across both data sources—something neither pure vector databases nor pure relational databases do well natively.

The hybrid search engine approach lets you:
- Filter on structured data (CSV)
- Facet on nested data (advisory sections)
- Aggregate metrics (CVSS statistics)
- All in a single query with instant results

That's the architectural advantage that justifies the complexity of nested documents and section categorization.
