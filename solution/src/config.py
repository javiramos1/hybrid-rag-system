#!/usr/bin/env python3
"""Centralized configuration management for the vulnerability query assistant.

Reviewer: These are just the env vars. See .env.example for documentation.

All configuration is read once from environment variables at startup and bundled
into a single Config dataclass. This provides:
- Single source of truth for configuration
- Type safety and validation
- Easy dependency injection to agent and search tool
- Clear separation of configuration from business logic
"""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    """Centralized configuration for the application."""

    # ========== Google Gemini API ==========
    google_api_key: str
    """Google API key for Gemini (required). Get from: https://aistudio.google.com/app/apikey"""

    gemini_model: str = "gemini-3-pro-preview"
    """Gemini model name. Override with GEMINI_MODEL env var."""

    # ========== Typesense Vector Database ==========
    typesense_host: str = "localhost"
    """Typesense server hostname. Override with TYPESENSE_HOST env var."""

    typesense_port: str = "8108"
    """Typesense server port. Override with TYPESENSE_PORT env var."""

    typesense_api_key: str = "xyz"
    """Typesense API key (hardcoded as 'xyz' in docker-compose.yml). Override with TYPESENSE_API_KEY env var."""

    # ========== ReAct Agent Parameters ==========
    max_react_iterations: int = 6
    """Max iterations in ReAct loop before returning answer. Override with MAX_REACT_ITERATIONS env var."""

    max_retries: int = 2
    """Max retries on API errors. Override with MAX_RETRIES env var."""

    max_chat_history: int = 3
    """Max chat history messages to keep for multi-turn conversations. Override with MAX_CHAT_HISTORY env var."""

    # ========== Vector Search Parameters ==========
    vector_search_k: int = 100
    """Number of nearest neighbors for vector search. Override with VECTOR_SEARCH_K env var."""

    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    """Sentence transformer model for embeddings. Override with EMBEDDING_MODEL env var."""

    # ========== Score-based Document Filtering ==========
    min_score: float = 0.4
    """Minimum relevance score (0-1) to include a document. Lower scores filtered out. Override with MIN_SCORE env var."""

    max_gap: float = 0.2
    """Maximum score gap between consecutive documents. Documents with larger gaps removed as noise. Override with MAX_GAP env var."""

    # ========== Data Ingestion ==========
    data_dir: Path = None  # type: ignore
    """Path to data directory (advisories, CSVs). Override with INGESTION_DATA_DIR env var."""

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables with validation.

        Returns:
            Config instance with all settings loaded

        Raises:
            ValueError: If required environment variables are missing
        """
        # Required: Google API key
        google_api_key = os.getenv("GOOGLE_API_KEY")
        if not google_api_key:
            raise ValueError(
                "GOOGLE_API_KEY environment variable is required. "
                "Get your key at: https://aistudio.google.com/app/apikey"
            )

        # Optional: Gemini model (with default)
        gemini_model = os.getenv("GEMINI_MODEL", "gemini-3-pro-preview")

        # Optional: Typesense configuration (with defaults)
        typesense_host = os.getenv("TYPESENSE_HOST", "localhost")
        typesense_port = os.getenv("TYPESENSE_PORT", "8108")
        typesense_api_key = os.getenv("TYPESENSE_API_KEY", "xyz")

        # Optional: ReAct agent parameters (with defaults)
        try:
            max_react_iterations = int(os.getenv("MAX_REACT_ITERATIONS", "6"))
            max_retries = int(os.getenv("MAX_RETRIES", "2"))
            max_chat_history = int(os.getenv("MAX_CHAT_HISTORY", "3"))
        except ValueError as e:
            raise ValueError(f"Invalid integer env var: {e}")

        # Optional: Vector search parameters (with defaults)
        try:
            vector_search_k = int(os.getenv("VECTOR_SEARCH_K", "100"))
        except ValueError as e:
            raise ValueError(f"Invalid integer env var: {e}")

        embedding_model = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")

        # Optional: Score-based document filtering (with defaults)
        try:
            min_score = float(os.getenv("MIN_SCORE", "0.4"))
            max_gap = float(os.getenv("MAX_GAP", "0.2"))
        except ValueError as e:
            raise ValueError(f"Invalid float env var for MIN_SCORE or MAX_GAP: {e}")

        # Optional: Data ingestion path (with default)
        data_dir = Path(os.getenv("INGESTION_DATA_DIR", "../data"))

        return cls(
            google_api_key=google_api_key,
            gemini_model=gemini_model,
            typesense_host=typesense_host,
            typesense_port=typesense_port,
            typesense_api_key=typesense_api_key,
            max_react_iterations=max_react_iterations,
            max_retries=max_retries,
            max_chat_history=max_chat_history,
            vector_search_k=vector_search_k,
            embedding_model=embedding_model,
            min_score=min_score,
            max_gap=max_gap,
            data_dir=data_dir,
        )

    def __repr__(self) -> str:
        """Return a safe representation that doesn't expose API keys."""
        return (
            f"Config(gemini_model={self.gemini_model}, "
            f"typesense_host={self.typesense_host}:{self.typesense_port}, "
            f"max_react_iterations={self.max_react_iterations}, "
            f"min_score={self.min_score}, max_gap={self.max_gap}, "
            f"vector_search_k={self.vector_search_k}, "
            f"data_dir={self.data_dir})"
        )
