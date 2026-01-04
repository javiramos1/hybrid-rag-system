#!/usr/bin/env python3
"""Unified search tool for hybrid RAG queries.

Why a search tool abstraction instead of direct Typesense SDK access?

Direct SDK access is flexible but imprecise for LLMs: the agent would need to construct
raw Typesense queries, manage vector embeddings, and understand filter syntax. Our tool
abstracts away low-level details with a clean interface: the agent just says what it wants
(search_type, filters, aggregations) and the tool handles:

- Embedding generation and caching (performance optimization)
- Filter building (safe expressions, abbreviation normalization)
- Rank fusion for hybrid search (configurable alpha for BM25/vector balance)
- Aggregation parsing (facet counts, statistics)
- Nested document handling (advisory chunks as sub-documents)

Result: The agent focuses on answering questions; we handle search complexity.

Search overview:

- Keyword (BM25): Full-text search on structured fields (CVE ID, package, severity) and
  advisory content. Fast, best for explicit filters and aggregations.
- Semantic (Vector): Similarity search on embeddings. Good for conceptual queries
  ("explain SQL injection") that don't match keywords directly.
- Hybrid: Combines BM25 + vector with configurable alpha (0=keyword-only, 1=vector-only).
  Typesense automatically fuses results by score; higher alpha favors semantic relevance.

Aggregations & Faceting:

Faceting counts documents in each category (e.g., "5 npm, 3 pip, 2 maven vulnerabilities").
Aggregations compute statistics on numeric fields (e.g., "avg CVSS: 8.2, min: 4.1, max: 9.8").
Both are returned in the SearchResult; the agent uses them to summarize findings
("Most vulnerabilities are Critical" or "XSS appears in 12 documents").

NOTE: In production without framework restrictions, this tool would be an MCP
(Model Context Protocol) server using FastMCP to provide a standardized interface
for LLM integration, replacing raw Typesense SDK calls with a transport-agnostic
protocol.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional

import typesense
from sentence_transformers import SentenceTransformer

from config import Config
from logger import get_logger

logger = get_logger(__name__)


@dataclass
class SearchResult:
    """Structured response from search operations.
    
    Output fields:
    - query_type: What kind of search was run (keyword, semantic, or hybrid)
    - total_found: Total documents matching the query (before pagination)
    - documents: The actual CVE documents returned (each has metadata + advisory chunks)
    - aggregations: Stats on numeric fields (CVSS min/max/avg) and category counts
    - facets: (Legacy) category breakdowns; aggregations preferred
    - execution_time_ms: How long Typesense took to run the search
    """

    query_type: str
    total_found: int
    documents: List[Dict[str, Any]]
    aggregations: Optional[Dict[str, Any]] = None
    facets: Optional[Dict[str, List[Dict]]] = None
    execution_time_ms: Optional[int] = None


class VulnerabilitySearchTool:
    """Unified search interface for keyword, semantic, and hybrid queries."""

    def __init__(self, config: Config):
        """Initialize search tool with Typesense client and embedding model.

        Args:
            config: Config instance with Typesense and embedding settings
        """
        self.config = config
        
        # Connect to Typesense server; handles both keyword and vector queries
        # In Production we would add timeouts, retries, and error handling
        self.client = typesense.Client(
            {
                "nodes": [
                    {
                        "host": config.typesense_host,
                        "port": config.typesense_port,
                        "protocol": "http",
                    }
                ],
                "api_key": config.typesense_api_key,
                "connection_timeout_seconds": 10,
            }
        )
        
        # Load embedding model for semantic search; encodes queries into vectors
        self.embedding_model = SentenceTransformer(config.embedding_model)

        # Load vulnerability type mapping from Typesense (lazy-loaded on first use)
        self._vulnerability_type_mapping = None

        logger.info(f"Initialized search tool with model: {config.embedding_model}")
        logger.debug(f"Vector search k={config.vector_search_k}")

    def _get_vulnerability_type_mapping(self) -> Dict[str, str]:
        """Lazily load vulnerability type mapping from Typesense.

        Maps common abbreviations (RCE, XSS, etc.) to their full names from the database.
        
        Why we need this:
        - CSV files and advisories use inconsistent naming: some have abbreviations (RCE) 
          while others use full names (Remote Code Execution)
        - Users might ask "show RCE vulnerabilities" but the database has "Remote Code Execution"
        - We query Typesense to learn what names are actually stored, then create mappings
        - This ensures filters work regardless of whether the user says RCE or Remote Code Execution
        - The search engine doesn't understand semantic equivalence, so we provide explicit mappings
        
        Production alternatives (not implemented here):
        - Connect the agent to a glossary/taxonomy service: agent learns abbreviations upfront,
          then queries the search engine with normalized names
        - Improve ingestion pipeline: add synonym fields to documents at index time, so Typesense
          natively handles both "RCE" and "Remote Code Execution" in searches
        
        Both approaches solve this more elegantly, but for now this simple mapping is sufficient.
        Only creates mappings for abbreviations not already in the database.
        """
        if self._vulnerability_type_mapping is not None:
            return self._vulnerability_type_mapping

        mapping = {}
        try:
            # Query Typesense to get all unique vulnerability types
            logger.debug("Querying Typesense for unique vulnerability types...")
            response = self.client.collections["vulnerabilities"].documents.search(
                {
                    "q": "*",
                    "query_by": "vulnerability_type",
                    "facet_by": "vulnerability_type",
                    "per_page": 1,  # We only need the facet counts, not documents
                }
            )

            # Extract full names from database
            db_types = set()
            if "facet_counts" in response:
                for facet in response["facet_counts"]:
                    if facet.get("field_name") == "vulnerability_type":
                        for count_item in facet.get("counts", []):
                            vuln_type = count_item.get("value", "")
                            if vuln_type:
                                db_types.add(vuln_type)

            # Create mappings for common abbreviations only if not already in database
            abbreviation_candidates = [
                ("RCE", "Remote Code Execution"),
                ("DoS", "Denial of Service"),
                ("IDOR", "Insecure Direct Object Reference"),
            ]

            for abbrev, full_name_hint in abbreviation_candidates:
                # Only map if the abbreviation is not already in the database
                if abbrev not in db_types:
                    # Try to find the full name in the database
                    matching_types = [t for t in db_types if full_name_hint in t]
                    if matching_types:
                        mapping[abbrev] = matching_types[0]
                        logger.debug(f"Mapped '{abbrev}' -> '{matching_types[0]}'")

            logger.debug(f"Loaded {len(mapping)} abbreviation mappings from Typesense")
        except Exception as e:
            logger.warning(f"Failed to load vulnerability type mapping from Typesense: {e}")

        # Cache the mapping
        self._vulnerability_type_mapping = mapping
        return mapping

    def search_vulnerabilities(
        self,
        query: str = "*",
        search_type: Literal["keyword", "semantic", "hybrid"] = "hybrid",
        # Common filters (explicit for ease of use)
        cve_ids: Optional[List[str]] = None,
        ecosystems: Optional[List[str]] = None,
        severity_levels: Optional[List[str]] = None,
        vulnerability_types: Optional[List[str]] = None,
        min_cvss_score: Optional[float] = None,
        # Flexible overrides for edge cases
        additional_filters: Optional[str] = None,
        facet_by: Optional[str] = None,
        # Results control
        per_page: int = 10,
        group_by: Optional[str] = None,
        sort_by: Optional[str] = None,
        # Hybrid search parameter
        hybrid_search_alpha: float = 0.5,
        # Performance optimization: pre-computed embedding to avoid re-encoding
        query_embedding: Optional[List[float]] = None,
    ) -> SearchResult:
        """Search vulnerabilities with flexible filtering and aggregation.

        Args:
            query: Search text or '*' for all documents
            search_type: "keyword" (BM25), "semantic" (vector), or "hybrid"
            cve_ids: Filter by CVE IDs
            ecosystems: Filter by package ecosystem (npm, pip, maven)
            severity_levels: Filter by severity level (Critical, High, Medium, Low)
            vulnerability_types: Filter by vulnerability type (XSS, SQL Injection, RCE, etc.)
            min_cvss_score: Minimum CVSS score threshold
            additional_filters: Raw Typesense filter expression for advanced filtering.
                Examples: "cvss_score:<=9.0", "advisory_chunks.section:code_example",
                "published_date:>=2024-01-01", "package_name:express-validator",
                "has_advisory:true" (filter to CVEs with detailed advisory documentation)
            facet_by: Comma-separated field names for aggregation/faceting.
                Returns statistics (avg/min/max/sum) for numeric fields and
                category counts for string fields.
                Examples: "cvss_score", "ecosystem,severity", "vulnerability_type,has_advisory"
            per_page: Number of results to return
            group_by: Group results by field to show diversity across categories (e.g., "ecosystem", "severity").
                Rarely needed with CVE-centric design (each CVE is one unique document, no duplicates).
                Example: group_by="ecosystem" limits to 3 results per ecosystem.
            sort_by: Sort order (e.g., "cvss_score:desc", "_text_match:desc")
            hybrid_search_alpha: Weight balance for hybrid search (only used when search_type="hybrid").
                Range: 0.0-1.0. Default: 0.5 (equal weight). Higher values favor semantic/vector search.
                Adjust based on query specificity (keyword-heavy=0.3-0.4, balanced=0.5, conceptual=0.6-0.7)
            query_embedding: Pre-computed query embedding for performance optimization.
                If provided, skips re-encoding during semantic/hybrid search. Useful when the same
                query is searched multiple times (e.g., across ReAct iterations).

        Returns:
            SearchResult with documents, aggregations, and metadata
        """
        logger.info(
            f"Searching vulnerabilities: {search_type} - '{query[:50]}'",
            extra={
                "query": query,
                "search_type": search_type,
                "ecosystems": ecosystems,
                "severity_levels": severity_levels,
                "vulnerability_types": vulnerability_types,
                "min_cvss_score": min_cvss_score,
                "cve_ids": cve_ids,
                "sort_by": sort_by,
                "hybrid_search_alpha": hybrid_search_alpha,
                "facet_by": facet_by,
                "per_page": per_page,
            },
        )

        # Build the base search query (keyword, semantic, or hybrid)
        search_params = self._build_search_params(
            query, search_type, per_page, sort_by, hybrid_search_alpha, query_embedding
        )

        logger.debug(f"Built search params: {search_params}")

        # Apply filters (CVE IDs, ecosystem, severity, etc.)
        filters = self._build_filters(
            cve_ids,
            ecosystems,
            severity_levels,
            vulnerability_types,
            min_cvss_score,
            additional_filters,
        )
        if filters:
            search_params["filter_by"] = filters
            logger.debug(f"Filters: {filters}")

        # Request aggregations (counts per category, stats on numeric fields)
        # Faceting tells Typesense: "for each unique value in this field, count how many 
        # documents have it" (for strings) or "compute min/max/avg" (for numbers).
        # Example: facet_by="ecosystem,severity" returns {ecosystem: {npm: 10, pip: 8, maven: 5}, 
        # severity: {Critical: 8, High: 10, Low: 5}}. Used by agent to summarize results
        # ("Most are Critical") or suggest follow-up filters.
        if facet_by:
            search_params["facet_by"] = facet_by
            logger.debug(f"Faceting by: {facet_by}")

        # Optionally group results for diversity (e.g., 3 npm, 3 pip, 3 maven)
        if group_by:
            search_params["group_by"] = group_by
            search_params["group_limit"] = 3
            logger.debug(f"Grouping by: {group_by}")

        # Execute search against Typesense
        logger.debug(f"Search params: {json.dumps(search_params, indent=2, default=str)}")
        try:
            if search_type in ("semantic", "hybrid"):
                # Vector queries use multi_search endpoint (handles rank fusion internally)
                search_request = {
                    "searches": [
                        {
                            "collection": "vulnerabilities",
                            **search_params,
                        }
                    ]
                }
                logger.debug(f"Multi-search request: {search_request}")
                multi_response = self.client.multi_search.perform(search_request, {})
                response = multi_response["results"][0]
            else:
                # Keyword queries use standard endpoint (BM25 only)
                response = self.client.collections["vulnerabilities"].documents.search(
                    search_params
                )
        except Exception as e:
            logger.error(f"Search failed: {e}", exc_info=True)
            raise

        # Parse aggregations from response (facet counts and statistics)
        aggregations = self._parse_aggregations(response)

        # Extract documents (handle grouped results if group_by was used)
        if group_by and "grouped_hits" in response:
            logger.debug(f"Extracting from grouped_hits (group_by='{group_by}')")
            documents = []
            for group in response.get("grouped_hits", []):
                group_docs = group.get("hits", [])
                for hit in group_docs:
                    documents.append(hit["document"])
        else:
            hits = response.get("hits", [])
            documents = [hit["document"] for hit in hits]

        logger.debug(f"Returned {len(documents)} documents out of {response.get('found', 0)} found")

        # Return structured result with documents, stats, and timing
        result = SearchResult(
            query_type=search_type,
            total_found=response.get("found", 0),
            documents=documents,
            aggregations=aggregations if aggregations else None,
            execution_time_ms=response.get("search_time_ms"),
        )

        logger.info(
            "Search completed",
            extra={
                "total_found": result.total_found,
                "returned": len(result.documents),
                "time_ms": result.execution_time_ms,
            },
        )

        return result

    def _build_search_params(
        self,
        query: str,
        search_type: str,
        per_page: int,
        sort_by: Optional[str],
        hybrid_search_alpha: float = 0.5,
        query_embedding: Optional[List[float]] = None,
    ) -> Dict[str, Any]:
        """Build Typesense search parameters based on search type.
        
        Constructs the low-level Typesense query dict. Three search strategies:
        
        1. Keyword (BM25): Full-text search using BM25 ranking algorithm
           - Matches exact/partial keywords in CVE ID, package name, severity, etc.
           - Best for: "List all Critical npm vulnerabilities", "Find CVE-2024-1234"
           - Fast, precise for structured filters + text queries
           
        2. Semantic (Vector): Embedding-based similarity search
           - Encodes user query as vector, finds nearest embeddings in database
           - Best for: "Explain SQL injection", "Show code examples for XSS"
           - Captures intent/concepts even if keywords don't match exactly
           - Uses pre-computed embedding if provided (avoids re-encoding)
           
        3. Hybrid: Combines BM25 + vector with rank fusion
           - Runs both searches, Typesense merges results using configurable alpha weight
           - Best for: "Show npm vulnerabilities with high CVSS + explain the risk"
           - alpha: 0=pure keyword, 0.5=balanced, 1.0=pure vector
           - Handles both exact matches (keywords) and conceptual understanding (embeddings)

        Agent decides which strategy to use based on query type.
        """
        params = {"per_page": per_page}

        if search_type == "keyword":
            # BM25 text search on structured fields and nested advisory content
            params["q"] = query
            params["query_by"] = (
                "cve_id,package_name,vulnerability_type,severity,content,affected_versions,fixed_version,"
                "advisory_chunks.content,advisory_chunks.section"
            )

        elif search_type == "semantic":
            # Vector similarity search using query encoding
            # Use pre-computed embedding if provided (performance optimization), otherwise encode now
            embedding = query_embedding if query_embedding is not None else self.embedding_model.encode(query).tolist()
            params["q"] = "*"
            params["vector_query"] = (
                f"embedding:([{','.join(str(v) for v in embedding)}], k:{self.config.vector_search_k})"
            )
            params["exclude_fields"] = "embedding,advisory_chunks.embedding"  # Save bandwidth

        else:  # hybrid
            # Combine BM25 and vector search with rank fusion (alpha configurable)
            # Use pre-computed embedding if provided (performance optimization), otherwise encode now
            embedding = query_embedding if query_embedding is not None else self.embedding_model.encode(query).tolist()
            params["q"] = query
            params["query_by"] = (
                "cve_id,package_name,vulnerability_type,severity,content,affected_versions,fixed_version,"
                "advisory_chunks.content,advisory_chunks.section"
            )
            params["vector_query"] = (
                f"embedding:([{','.join(str(v) for v in embedding)}], alpha:{hybrid_search_alpha})"
            )
            params["exclude_fields"] = "embedding,advisory_chunks.embedding"

        if sort_by:
            params["sort_by"] = sort_by

        logger.debug(f"Built {search_type} search params for: '{query[:50]}'")
        return params

    def _build_filters(
        self,
        cve_ids: Optional[List[str]],
        ecosystems: Optional[List[str]],
        severity_levels: Optional[List[str]],
        vulnerability_types: Optional[List[str]],
        min_cvss_score: Optional[float],
        additional_filters: Optional[str],
    ) -> Optional[str]:
        """Build Typesense filter expression from parameters.

        Applies optional filters for CVE IDs, ecosystems, severity levels,
        vulnerability types, and CVSS score thresholds.
        """
        filters = []

        if cve_ids:
            cve_filter = ",".join(cve_ids)
            filters.append(f"cve_id:[{cve_filter}]")

        if ecosystems:
            eco_filter = ",".join(ecosystems)
            filters.append(f"ecosystem:[{eco_filter}]")

        if severity_levels:
            sev_filter = ",".join(severity_levels)
            filters.append(f"severity:[{sev_filter}]")

        # Normalize and apply vulnerability_types filter using mapping from Typesense
        if vulnerability_types:
            # Get the vulnerability type mapping (lazy-loaded from Typesense)
            mapping = self._get_vulnerability_type_mapping()

            # Normalize abbreviations (RCE -> Remote Code Execution, XSS -> Cross-Site Scripting (XSS))
            normalized_types = [mapping.get(vt, vt) for vt in vulnerability_types]

            # Escape special characters for Typesense filter (parentheses, etc.)
            # Use backticks for literal values with special characters
            vuln_filters = [f"vulnerability_type:`{vt}`" for vt in normalized_types]
            filters.append(" || ".join(vuln_filters))

        if min_cvss_score is not None:
            filters.append(f"cvss_score:>={min_cvss_score}")

        # Add raw filter expression for advanced use cases
        if additional_filters:
            filters.append(additional_filters)

        return " && ".join(filters) if filters else None

    def _parse_aggregations(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Extract aggregation results from Typesense response.
        
        How aggregations work:
        - Typesense returns facet_counts: category counts (npm: 10, pip: 8) and stats (min/max/avg)
        - We parse these into a clean dict for the agent: {"ecosystem": {"counts": [...]}, 
          "cvss_score": {"stats": {min: 4.1, max: 9.8, avg: 7.2}}}
        
        Why needed:
        - Answers to "What's the average CVSS?" or "How many npm vulnerabilities?" come from stats/counts
        - Agent uses aggregations to summarize large result sets without listing every document
        - Enables questions like "Which ecosystem has the most Critical vulnerabilities?" 
          (combine counts + filters to show breakdown by category)
        - Reduces response size: return 10 documents + aggregations instead of all 47
        """
        aggregations = {}

        if "facet_counts" in response:
            for facet in response["facet_counts"]:
                field_name = facet.get("field_name")
                # Handle both statistics (numeric fields) and category counts (string fields)
                facet_data = {}
                if facet.get("stats"):
                    facet_data["stats"] = facet["stats"]
                if "counts" in facet:
                    facet_data["counts"] = facet["counts"]

                if facet_data:
                    aggregations[field_name] = facet_data

        return aggregations
