#!/usr/bin/env python3
"""Stand alone data ingestion pipeline: Load CSVs, merge with advisories, generate embeddings, index to Typesense.

Pipeline Overview:
  1. Load 4 CSVs: vulnerabilities, packages, vulnerability_types, severity_levels
  2. Denormalize into single "one doc per CVE" structure (47 CVEs total)
  3. Parse 8 advisory markdown files with section-aware chunking
  4. Generate embeddings for CSV descriptions + advisory chunks (384-dim vectors)
  5. Create Typesense collection with nested schema (CVE doc contains advisory_chunks array)
  6. Import 47 CVE documents with nested chunks into Typesense

We use Polars for fast CSV loading and joins, SentenceTransformers for embeddings, and
Typesense for vector search with nested objects.

Schema Design (CVE-Centric):
  - Each CVE is one top-level document with fields: cve_id, package_name, ecosystem,
    vulnerability_type, severity, cvss_score, affected_versions, fixed_version, content,
    embedding, has_advisory (bool flag)
  - Nested advisory_chunks: array of {content, section, is_code, index, embedding}
  - This design keeps analytics clean (47 docs, not 95+) while enabling rich search
    across both metadata and advisory content

Chunking Strategy (Section-Aware):
  - Split advisories by ## markdown headers (natural semantic boundaries)
  - Preserve entire code blocks intact (never split mid-code)
  - Split text-only sections at sentence boundaries (~500 chars per chunk)
  - Each chunk tagged with section type (summary, remediation, testing, best_practices, details)
  - Result: ~60-80 advisory chunks total, each with separate embedding
"""

import re
from pathlib import Path

import polars as pl
import typesense
from sentence_transformers import SentenceTransformer

from config import Config
from logger import get_logger

logger = get_logger(__name__)


def load_csv_data(task_dir: Path) -> pl.DataFrame:
    """Load and denormalize CSV data using SQL-like joins.
    
    Uses Polars for faster CSV loading and joins compared to pandas.
    Joins 4 normalized tables into single flat structure:
      vulnerabilities → packages (package details)
                     → vulnerability_types (XSS, SQL Injection, etc.)
                     → severity_levels (Critical, High, etc.)
        This strategy is recommend for search engines to avoid complex joins at query time. 
        Search engines prefer unnormalized flat documents for efficiency.
    
    Returns 47 rows (one per CVE) with all normalized fields flattened.
    """
    logger.info("Loading CSV files...")

    vulnerabilities = pl.read_csv(task_dir / "vulnerabilities.csv")
    packages = pl.read_csv(task_dir / "packages.csv")
    vulnerability_types = pl.read_csv(task_dir / "vulnerability_types.csv")
    severity_levels = pl.read_csv(task_dir / "severity_levels.csv")

    logger.info("Denormalizing data with joins...")
    full_data = (
        vulnerabilities.join(packages, on="package_id", how="left")
        .join(
            vulnerability_types,
            left_on="vulnerability_type_id",
            right_on="type_id",
            how="left",
        )
        .join(severity_levels, on="severity_id", how="left")
        .rename(
            {
                "name": "package_name",
                "type_name": "vulnerability_type",
                "severity_name": "severity",
            }
        )
        .select(
            [
                "cve_id",
                "package_name",
                "ecosystem",
                "vulnerability_type",
                "severity",
                "cvss_score",
                "affected_versions",
                "fixed_version",
                "description",
                "published_date",
            ]
        )
    )

    logger.info(f"Loaded {len(full_data)} vulnerability records")
    return full_data


def parse_advisories(task_dir: Path) -> list[dict]:
    """Parse advisory markdown files with section-aware chunking strategy.

    For each advisory (8 total):
      1. Extract CVE ID and metadata from header
      2. Parse affected versions table for filtering/aggregations
      3. Split by ## section headers (semantic boundaries: Summary, Remediation, Details, etc.)
      4. For sections with code blocks (```): keep entire section intact (never split mid-code)
      5. For text-only sections: split at sentence boundaries (~500 chars per chunk)
      6. Tag each chunk with section type (summary, remediation, testing, best_practices, details)
    
    Returns list of ~60-80 chunk dicts {cve_id, content, section, is_code, affected_versions, ...}
    Each chunk will be embedded separately for semantic search.
    Sections with code blocks are marked with is_code=true for filtering.
    Affected versions data is attached to all chunks from the same CVE for filtering/aggregations.
    """
    advisories_dir = task_dir / "advisories"
    all_chunks = []

    for filepath in sorted(advisories_dir.glob("*.md")):
        logger.info(f"Parsing {filepath.name}...")
        content = filepath.read_text(encoding="utf-8")

        # Extract CVE ID and metadata from header
        metadata = _extract_metadata(content)
        cve_id = metadata.get("cve_id")

        if not cve_id:
            logger.warning(f"No CVE ID found in {filepath.name}, skipping")
            continue

        # Parse affected versions table for metadata/filtering
        affected_versions = _parse_affected_versions_table(content)
        if affected_versions:
            logger.debug(f"  Parsed {len(affected_versions)} affected version entries for {cve_id}")
        
        # Split by section headers (##) to preserve semantic boundaries
        sections = re.split(r"^## ", content, flags=re.MULTILINE)

        for section in sections[1:]:  # Skip document title (first split)
            lines = section.split("\n", 1)
            section_title = lines[0].strip()
            section_content = lines[1] if len(lines) > 1 else ""

            if not section_content.strip():
                continue

            # Check if section contains code blocks
            has_code = "```" in section_content

            # Simple chunking: Keep code blocks intact, split text by ~500 chars
            if has_code:
                # Preserve entire section with code (don't split mid-code)
                chunk = {
                    **metadata,
                    "content": f"## {section_title}\n{section_content}",
                    "section": _categorize_section(section_title),
                    "is_code": True,
                    "cve_id": cve_id,
                    "affected_versions": affected_versions,  # Attach parsed versions table
                }
                all_chunks.append(chunk)
                logger.debug(
                    f"  Created code chunk for section: {section_title} ({len(chunk['content'])} chars)"
                )
            else:
                # Split text content into ~500 char chunks at sentence boundaries
                text_chunks = _split_text(section_content, max_chars=500)
                for chunk_text in text_chunks:
                    chunk = {
                        **metadata,
                        "content": chunk_text,
                        "section": _categorize_section(section_title),
                        "is_code": False,
                        "cve_id": cve_id,
                        "affected_versions": affected_versions,  # Attach parsed versions table
                    }
                    all_chunks.append(chunk)
                logger.debug(
                    f"  Created {len(text_chunks)} text chunks for section: {section_title}"
                )

        logger.info(f"Parsed {filepath.name}: {len(all_chunks)} total chunks created for {cve_id}")

    logger.info(
        f"Total advisory chunks created: {len(all_chunks)} from {len(set(c.get('cve_id') for c in all_chunks))} CVEs"
    )
    return all_chunks


def _extract_metadata(content: str) -> dict:
    """Extract metadata from advisory header for structured filtering and analytics.
    
    Extracts key metadata fields (CVE ID, package name, ecosystem, severity, CVSS score)
    from the advisory markdown header. This is a critical advantage of hybrid search engines
    like Typesense over pure vector databases:
    
    - Vector DBs: Can only search semantic similarity, no structured filtering
    - Search Engines: Enable faceting, aggregations, and range queries on metadata
    
    With extracted metadata, we can:
      - Filter by ecosystem (npm/pip/maven), severity level, CVSS score range
      - Generate analytics: avg CVSS by ecosystem, vulnerability type distribution, etc.
      - Combine keyword + vector search with structured filters for precise retrieval
    
    This enables sophisticated queries like "Critical npm vulnerabilities + explain fix" 
    which require both semantic understanding AND structured filtering.
    """
    metadata = {}
    for line in content.split("\n")[:20]:
        if "**CVE ID:**" in line:
            metadata["cve_id"] = line.split("**CVE ID:**")[1].strip()
        elif "**Package:**" in line:
            metadata["package_name"] = line.split("**Package:**")[1].strip()
        elif "**Ecosystem:**" in line:
            metadata["ecosystem"] = line.split("**Ecosystem:**")[1].strip()
        elif "**Severity:**" in line:
            metadata["severity"] = line.split("**Severity:**")[1].strip()
        elif "**CVSS Score:**" in line:
            try:
                score = float(line.split("**CVSS Score:**")[1].strip())
                metadata["cvss_score"] = score
            except (ValueError, IndexError):
                pass
    return metadata


def _parse_affected_versions_table(content: str) -> list[dict]:
    """Parse affected versions table from markdown advisory.
    
    Markdown format (from advisories):
    | Version Range | Status | Fixed Version |
    |--------------|--------|---------------|
    | < 4.5.0 | Vulnerable | 4.5.0 |
    | >= 4.5.0 | Safe | - |
    
    Returns list of version entries with parsed metadata:
    [
        {"version_range": "< 4.5.0", "status": "Vulnerable", "fixed_version": "4.5.0"},
        {"version_range": ">= 4.5.0", "status": "Safe", "fixed_version": None}
    ]
    
    Enables queries like:
    - "Show vulnerabilities affecting versions < 4.5.0"
    - Aggregate: "How many CVEs have vulnerable versions < 2.0?"
    - Filter: "Find npm packages with fixes available"
    """
    versions = []
    lines = content.split("\n")
    
    # Find the affected versions table (starts with "### Affected Versions")
    table_start = None
    for idx, line in enumerate(lines):
        if "### Affected Versions" in line or "## Affected Versions" in line:
            table_start = idx + 1
            break
    
    if table_start is None:
        return versions
    
    # Skip header separator line (|---|---|---|)
    in_table = False
    for line in lines[table_start:]:
        if line.strip().startswith("|"):
            # Skip header row and separator
            if "Version" in line or "---" in line:
                in_table = True
                continue
            
            if in_table:
                # Parse table row
                parts = [p.strip() for p in line.split("|")[1:-1]]  # Remove empty first/last
                if len(parts) >= 3:
                    version_range = parts[0]
                    status = parts[1]
                    fixed_version = parts[2]
                    
                    # Normalize "Safe" status and handle "-" for missing fixed version
                    status_normalized = status.lower() if status else "unknown"
                    fixed_version_normalized = None if fixed_version == "-" else fixed_version
                    
                    versions.append({
                        "version_range": version_range,
                        "status": status_normalized,
                        "fixed_version": fixed_version_normalized,
                    })
        else:
            # End of table when we hit non-table content
            if in_table and line.strip() and not line.startswith("|"):
                break
    
    return versions


def _categorize_section(title: str) -> str:
    """Categorize advisory section by keywords for faceted search and analytics.
    
    Maps markdown section headers to semantic categories based on actual data.
    Current sections in the 8 advisory documents:
      - summary: High-level vulnerability overview
      - remediation: How to fix or mitigate the vulnerability
      - testing: Testing procedures and verification steps
      - best_practices: Security best practices and recommendations
      - details: Technical details, references, credits (catch-all)
    
    This enables:
      - Faceted search: Find all "remediation" or "testing" sections across CVEs
      - Analytics: Measure documentation completeness (% with testing, best practices)
      - Cross-dimensional queries: "Which ecosystem has best testing coverage?"
      - Targeted retrieval: "Show me testing steps" retrieves only testing sections
    
    Note: Code blocks are marked with is_code=true within any section, not a separate section type.
    """
    title_lower = title.lower()
    if "summary" in title_lower or "overview" in title_lower:
        return "summary"
    elif "remediat" in title_lower or "fix" in title_lower:
        return "remediation"
    elif "test" in title_lower:
        return "testing"
    elif "best practice" in title_lower:
        return "best_practices"
    return "details"


def _split_text(text: str, max_chars: int = 500) -> list[str]:
    """Split text into chunks at sentence boundaries (~max_chars each).

    Why sentence boundaries?
      - Preserves context (related sentences stay together)
      - Avoids cutting mid-sentence (better for embeddings)
      - Simple and effective for technical docs
    
    Returns list of ~150-200 token chunks (sentence count varies by length).
    """
    # Simple sentence split on period, exclamation, question mark
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())

    chunks = []
    current_chunk = ""

    for sentence in sentences:
        if not sentence.strip():
            continue

        # Start new chunk if adding sentence exceeds limit
        if current_chunk and len(current_chunk) + len(sentence) + 1 > max_chars:
            chunks.append(current_chunk.strip())
            current_chunk = sentence
        else:
            current_chunk += (" " if current_chunk else "") + sentence

    # Add final chunk
    if current_chunk.strip():
        chunks.append(current_chunk.strip())

    return chunks


def generate_embeddings(texts: list[str], model: SentenceTransformer) -> list[list[float]]:
    """Generate embeddings for texts."""
    logger.info(f"Generating embeddings for {len(texts)} texts...")
    embeddings = model.encode(texts, show_progress_bar=True)
    return [emb.tolist() for emb in embeddings]


def create_typesense_collection(client: typesense.Client) -> None:
    """Create Typesense collection schema with nested advisory chunks and affected versions.
    
    One document per CVE (47 total). Each CVE doc has:
      - Top-level fields: cve_id, package_name, ecosystem, severity, cvss_score, etc.
      - affected_versions_data: nested array of {version_range, status, fixed_version}
        Enables filtering: "Show vulnerable versions < 2.0", aggregations: "Count by fix availability"
      - CSV embedding: vector for BM25+semantic hybrid search on description
      - has_advisory: boolean flag (8 CVEs have advisories, 39 don't)
      - advisory_chunks: nested array of {content, section, is_code, index, embedding}
    
    Nested chunks enable rich search: find CVEs by advisory section (remediation, testing, best_practices, etc.)
    without creating 95 top-level documents. Analytics report 47 CVEs, not 95.
    """
    logger.info("Creating Typesense collection...")

    schema = {
        "name": "vulnerabilities",
        "enable_nested_fields": True,  # Enable nested objects/arrays
        "fields": [
            {"name": "id", "type": "string"},  # csv-{cve_id}
            {"name": "cve_id", "type": "string", "facet": True},
            {"name": "package_name", "type": "string", "facet": True},
            {"name": "ecosystem", "type": "string", "facet": True},
            {"name": "vulnerability_type", "type": "string", "facet": True, "optional": True},
            {"name": "severity", "type": "string", "facet": True},
            {"name": "cvss_score", "type": "float", "facet": True, "optional": True},
            {"name": "affected_versions", "type": "string", "optional": True},
            {"name": "fixed_version", "type": "string", "optional": True},
            {"name": "has_fix", "type": "bool", "facet": True},  # Whether CVE has a fix available
            {"name": "published_date", "type": "string", "optional": True},
            {"name": "content", "type": "string"},  # CSV description
            {"name": "embedding", "type": "float[]", "num_dim": 384},  # CSV embedding
            {
                "name": "has_advisory",
                "type": "bool",
                "facet": True,
            },  # Whether CVE has detailed advisory documentation
            # Nested affected versions table from advisory markdown
            {
                "name": "affected_versions_data",
                "type": "object[]",
                "optional": True,
                "fields": [
                    {"name": "version_range", "type": "string"},  # e.g., "< 4.5.0", ">= 2.0.0 < 2.3.1"
                    {"name": "status", "type": "string", "facet": True},  # vulnerable, safe, unknown
                    {"name": "fixed_version", "type": "string", "optional": True},  # e.g., "4.5.0"
                ],
            },
            # Nested advisory chunks (array of objects)
            {
                "name": "advisory_chunks",
                "type": "object[]",
                "optional": True,
                "fields": [
                    {"name": "content", "type": "string"},  # Chunk text
                    {
                        "name": "section",
                        "type": "string",
                    },  # summary, remediation, testing, best_practices, details
                    {"name": "is_code", "type": "bool"},  # Code block marker
                    {"name": "index", "type": "int32"},  # Chunk index within advisory
                    {"name": "embedding", "type": "float[]", "num_dim": 384},  # Chunk embedding
                ],
            },
        ],
    }

    try:
        client.collections["vulnerabilities"].delete()
        logger.info("Deleted existing collection")
    except Exception:
        pass

    client.collections.create(schema)
    logger.info("Collection created successfully (nested chunks and affected versions enabled)")


def import_documents(
    client: typesense.Client,
    csv_data: pl.DataFrame,
    csv_embeddings: list[list[float]],
    advisory_chunks: list[dict],
    advisory_embeddings: list[list[float]],
) -> None:
    """Import documents to Typesense with nested advisory chunks and affected versions.

    Process:
      1. Group advisory chunks and affected versions by CVE ID (8 CVEs have advisories)
      2. For each CVE: create doc with metadata + nested advisory_chunks + affected_versions_data
      3. Each nested chunk has its own embedding (for semantic search within advisories)
      4. Batch import all 47 CVE docs (with ~60-80 nested chunks total)
    
    Result: Hybrid search spans CVE metadata (BM25) + advisory content (semantic)
    Analytics: 47 documents, not 95+ (clean reporting)
    Affected versions enable filtering ("Show versions < 2.0") and aggregations
    """
    logger.info("Preparing documents with nested chunks and affected versions...")

    # Group advisory chunks by CVE ID
    chunks_by_cve: dict[str, list[dict]] = {}
    # Group affected versions by CVE ID
    versions_by_cve: dict[str, list[dict]] = {}
    
    for idx, chunk in enumerate(advisory_chunks):
        cve_id = chunk["cve_id"]
        if cve_id not in chunks_by_cve:
            chunks_by_cve[cve_id] = []

        # Create nested chunk object with embedding
        nested_chunk = {
            "content": chunk["content"],
            "section": chunk.get("section", "details"),
            "is_code": chunk.get("is_code", False),
            "index": len(chunks_by_cve[cve_id]),
            "embedding": advisory_embeddings[idx],
        }
        chunks_by_cve[cve_id].append(nested_chunk)
        
        # Store affected versions (only once per CVE)
        if cve_id not in versions_by_cve:
            affected_versions = chunk.get("affected_versions", [])
            if affected_versions:
                versions_by_cve[cve_id] = affected_versions

    # Create CVE documents with nested advisory chunks and affected versions
    logger.info(f"Creating {len(csv_data)} CVE documents with nested chunks and affected versions...")
    documents = []

    for idx, row in enumerate(csv_data.iter_rows(named=True)):
        cve_id = row["cve_id"]

        fixed_version = row.get("fixed_version") or ""
        doc = {
            "id": f"csv-{cve_id}",
            "cve_id": cve_id,
            "package_name": row["package_name"],
            "ecosystem": row["ecosystem"],
            "vulnerability_type": row["vulnerability_type"],
            "severity": row["severity"],
            "cvss_score": float(row["cvss_score"]),
            "affected_versions": row.get("affected_versions") or "",
            "fixed_version": fixed_version,
            "has_fix": bool(fixed_version.strip()),  # True if fixed_version is non-empty
            "published_date": row.get("published_date") or "",
            "content": row["description"],
            "embedding": csv_embeddings[idx],
            "has_advisory": cve_id in chunks_by_cve,
        }

        # Add nested advisory chunks if available
        if cve_id in chunks_by_cve:
            doc["advisory_chunks"] = chunks_by_cve[cve_id]
        
        # Add nested affected versions data if available
        if cve_id in versions_by_cve:
            doc["affected_versions_data"] = versions_by_cve[cve_id]

        documents.append(doc)

    # Batch import to Typesense
    logger.info(f"Importing {len(documents)} CVE documents with nested chunks and affected versions...")
    client.collections["vulnerabilities"].documents.import_(documents)
    logger.info(f"Successfully imported {len(documents)} CVE documents")

    # Log statistics
    total_chunks = sum(len(chunks) for chunks in chunks_by_cve.values())
    code_chunks = sum(
        1 for chunks in chunks_by_cve.values() for chunk in chunks if chunk.get("is_code", False)
    )
    total_versions = sum(len(versions) for versions in versions_by_cve.values())
    logger.info(
        f"Statistics: {len(documents)} CVE documents, {total_chunks} nested advisory chunks "
        f"({code_chunks} with code), {total_versions} affected version entries"
    )


def main() -> None:
    """Run full ingestion pipeline: CSV → merge advisories → embed → index.
    
    Steps:
      1. Load embedding model (384-dim all-MiniLM-L6-v2)
      2. Load and denormalize 4 CSVs (47 vulnerabilities)
      3. Parse 8 advisories with section-based chunking (~60-80 chunks)
      4. Encode all texts to embeddings (CSV descriptions + advisory chunks)
      5. Create Typesense collection with nested schema
      6. Import 47 CVE documents with nested advisory chunks
    """
    config = Config.from_env()

    # Load embedding model
    logger.info(f"Loading embedding model: {config.embedding_model}")
    embedding_model = SentenceTransformer(config.embedding_model)

    # Load and denormalize CSV data
    csv_data = load_csv_data(config.task_dir)

    # Parse advisories with section-based chunking (NEW STRATEGY)
    advisory_chunks = parse_advisories(config.task_dir)

    # Generate embeddings for all texts
    logger.info("Preparing texts for embedding generation...")

    # CSV descriptions for CSV documents
    csv_texts = csv_data.select(["description"]).to_series(0).to_list()

    # Advisory chunk content
    advisory_texts = [chunk["content"] for chunk in advisory_chunks]

    # Generate embeddings for both
    all_texts = csv_texts + advisory_texts
    logger.info(
        f"Generating embeddings for {len(all_texts)} texts ({len(csv_texts)} CSV + {len(advisory_texts)} advisory chunks)..."
    )
    embeddings = embedding_model.encode(all_texts, show_progress_bar=True)

    # Split embeddings back
    csv_embeddings = [emb.tolist() for emb in embeddings[: len(csv_texts)]]
    advisory_embeddings = [emb.tolist() for emb in embeddings[len(csv_texts) :]]

    # Connect to Typesense, in Production we will use timeouts and retries
    logger.info("Connecting to Typesense...")
    client = typesense.Client(
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

    # Create collection and import documents
    create_typesense_collection(client)
    import_documents(client, csv_data, csv_embeddings, advisory_chunks, advisory_embeddings)

    # Verify
    stats = client.collections["vulnerabilities"].retrieve()
    logger.info(f"Collection stats: {stats.get('num_documents')} documents indexed")
    logger.info("✅ Ingestion complete - section-based chunking with code preservation")


if __name__ == "__main__":
    main()
