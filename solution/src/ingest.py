#!/usr/bin/env python3
"""Data ingestion pipeline for vulnerability RAG system."""

import os
import re
from dataclasses import dataclass
from pathlib import Path

import polars as pl
import typesense
from sentence_transformers import SentenceTransformer

from logger import get_logger

logger = get_logger(__name__)


@dataclass
class IngestionConfig:
    """Configuration for ingestion pipeline."""

    task_dir: Path = Path(os.getenv("INGESTION_TASK_DIR", "../task"))
    embedding_model: str = os.getenv(
        "INGESTION_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
    )
    typesense_host: str = os.getenv("INGESTION_TYPESENSE_HOST", "localhost")
    typesense_port: str = os.getenv("INGESTION_TYPESENSE_PORT", "8108")
    typesense_api_key: str = os.getenv("INGESTION_TYPESENSE_API_KEY", "xyz")
    chunk_max_chars: int = int(os.getenv("INGESTION_CHUNK_MAX_CHARS", "500"))


def load_csv_data(config: IngestionConfig) -> pl.DataFrame:
    """Load and denormalize CSV data using SQL-like joins."""
    logger.info("Loading CSV files...")

    vulnerabilities = pl.read_csv(config.task_dir / "vulnerabilities.csv")
    packages = pl.read_csv(config.task_dir / "packages.csv")
    vulnerability_types = pl.read_csv(config.task_dir / "vulnerability_types.csv")
    severity_levels = pl.read_csv(config.task_dir / "severity_levels.csv")

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


def parse_advisories(config: IngestionConfig) -> list[dict]:
    """Parse advisory markdown files with section-aware chunking strategy.

    Strategy: Split by section headers (##) and preserve code blocks intact.
    This maintains context for code examples and remediation steps.

    Returns:
        List of chunk dictionaries with metadata, content, section type, and code flag
    """
    advisories_dir = config.task_dir / "advisories"
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
                }
                all_chunks.append(chunk)
                logger.debug(
                    f"  Created code chunk for section: {section_title} ({len(chunk['content'])} chars)"
                )
            else:
                # Split text content into ~500 char chunks at sentence boundaries
                text_chunks = _split_text(section_content, max_chars=config.chunk_max_chars)
                for chunk_text in text_chunks:
                    chunk = {
                        **metadata,
                        "content": chunk_text,
                        "section": _categorize_section(section_title),
                        "is_code": False,
                        "cve_id": cve_id,
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
    """Extract metadata from advisory header."""
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


def _categorize_section(title: str) -> str:
    """Categorize section by keywords."""
    title_lower = title.lower()
    if "summary" in title_lower or "overview" in title_lower:
        return "summary"
    elif "remediat" in title_lower or "fix" in title_lower:
        return "remediation"
    elif "attack" in title_lower or "exploit" in title_lower:
        return "attack"
    elif "code" in title_lower or "example" in title_lower:
        return "code_example"
    elif "cvss" in title_lower:
        return "cvss"
    return "details"


def _split_text(text: str, max_chars: int = 500) -> list[str]:
    """Split text into chunks at sentence boundaries (~max_chars each).

    Uses simple sentence splitting (good enough for technical documentation).
    Preserves sentence context and avoids splitting mid-sentence.

    Args:
        text: Text to split
        max_chars: Maximum characters per chunk

    Returns:
        List of text chunks split at sentence boundaries
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


def _truncate_text(text: str, max_chars: int = 10000) -> str:
    """Truncate text to max_chars while preserving sentence boundaries."""
    if len(text) <= max_chars:
        return text

    # Truncate and find last sentence boundary
    truncated = text[:max_chars]
    last_period = truncated.rfind(".")
    last_newline = truncated.rfind("\n")

    cutoff = max(last_period, last_newline)
    if cutoff > 0:
        return truncated[: cutoff + 1]
    return truncated


def generate_embeddings(texts: list[str], model: SentenceTransformer) -> list[list[float]]:
    """Generate embeddings for texts."""
    logger.info(f"Generating embeddings for {len(texts)} texts...")
    embeddings = model.encode(texts, show_progress_bar=True)
    return [emb.tolist() for emb in embeddings]


def create_typesense_collection(client: typesense.Client) -> None:
    """Create Typesense collection schema with nested advisory chunks (one CVE doc per vulnerability)."""
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
            {"name": "published_date", "type": "string", "optional": True},
            {"name": "content", "type": "string"},  # CSV description
            {"name": "embedding", "type": "float[]", "num_dim": 384},  # CSV embedding
            {
                "name": "has_advisory",
                "type": "bool",
                "facet": True,
            },  # Whether CVE has detailed advisory documentation
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
                    },  # summary, remediation, code_example, etc.
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
    logger.info("Collection created successfully (nested chunks enabled)")


def import_documents(
    client: typesense.Client,
    csv_data: pl.DataFrame,
    csv_embeddings: list[list[float]],
    advisory_chunks: list[dict],
    advisory_embeddings: list[list[float]],
) -> None:
    """Import documents to Typesense with nested advisory chunks.

    Structure (maintains 1 document per CVE):
    - 47 top-level documents (one per CVE)
    - Each CVE document contains nested advisory_chunks array
    - Advisory chunks are sub-documents with embeddings

    Benefits:
    - Analytics report 47 vulnerabilities (not 95)
    - Search spans both CVE metadata and advisory content
    - Chunk embeddings enable semantic search within advisories
    """
    logger.info("Preparing documents with nested chunks...")

    # Group advisory chunks by CVE ID
    chunks_by_cve: dict[str, list[dict]] = {}
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

    # Create CVE documents with nested advisory chunks
    logger.info(f"Creating {len(csv_data)} CVE documents with nested chunks...")
    documents = []

    for idx, row in enumerate(csv_data.iter_rows(named=True)):
        cve_id = row["cve_id"]

        doc = {
            "id": f"csv-{cve_id}",
            "cve_id": cve_id,
            "package_name": row["package_name"],
            "ecosystem": row["ecosystem"],
            "vulnerability_type": row["vulnerability_type"],
            "severity": row["severity"],
            "cvss_score": float(row["cvss_score"]),
            "affected_versions": row.get("affected_versions") or "",
            "fixed_version": row.get("fixed_version") or "",
            "published_date": row.get("published_date") or "",
            "content": row["description"],
            "embedding": csv_embeddings[idx],
            "has_advisory": cve_id in chunks_by_cve,
        }

        # Add nested advisory chunks if available
        if cve_id in chunks_by_cve:
            doc["advisory_chunks"] = chunks_by_cve[cve_id]

        documents.append(doc)

    # Batch import to Typesense
    logger.info(f"Importing {len(documents)} CVE documents with nested chunks...")
    client.collections["vulnerabilities"].documents.import_(documents)
    logger.info(f"Successfully imported {len(documents)} CVE documents")

    # Log statistics
    total_chunks = sum(len(chunks) for chunks in chunks_by_cve.values())
    code_chunks = sum(
        1 for chunks in chunks_by_cve.values() for chunk in chunks if chunk.get("is_code", False)
    )
    logger.info(
        f"Statistics: {len(documents)} CVE documents, {total_chunks} nested advisory chunks "
        f"({code_chunks} with code)"
    )


def main() -> None:
    """Run the ingestion pipeline with section-based chunking strategy."""
    config = IngestionConfig()

    # Load embedding model
    logger.info(f"Loading embedding model: {config.embedding_model}")
    embedding_model = SentenceTransformer(config.embedding_model)

    # Load and denormalize CSV data
    csv_data = load_csv_data(config)

    # Parse advisories with section-based chunking (NEW STRATEGY)
    advisory_chunks = parse_advisories(config)

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

    # Connect to Typesense
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
