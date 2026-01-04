#!/usr/bin/env python3
"""CLI for Hybrid RAG System - Security Vulnerabilities.

Supports two modes:
  - Interactive: python main.py (REPL with 'help', 'exit' commands)
  - Single query: python main.py "your question here"
"""

import os
import sys
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from agent import VulnerabilityAgent
from logger import get_logger
from rich.console import Console
from rich.markdown import Markdown

console = Console()
logger = get_logger(__name__)


def print_help() -> None:
    """Print help message and example queries."""
    help_text = """
=== Vulnerability Query Assistant ===

COMMANDS:
  help, h, ?     Show this help message
  exit, quit, q  Exit the program

STRUCTURED QUERIES (filtering, aggregations):
  "List critical npm vulnerabilities"
  "What is the average CVSS score for High severity?"
  "Count vulnerabilities by ecosystem"

SEMANTIC QUERIES (conceptual, examples):
  "Explain SQL injection with code examples"
  "How do path traversal attacks work?"
  "Show me XSS vulnerability examples"

HYBRID QUERIES (specific CVE + explanation):
  "How do I fix CVE-2024-1234?"
  "Critical npm vulnerabilities and how to fix them"
"""
    print(help_text)


def validate_api_key() -> None:
    """Validate Google API key is set."""
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("❌ Error: GOOGLE_API_KEY environment variable not set")
        print("   Get your key at: https://aistudio.google.com/app/apikey")
        print("   Then: export GOOGLE_API_KEY='your-key-here'")
        sys.exit(1)


def interactive_mode(agent: VulnerabilityAgent) -> None:
    """Interactive REPL mode."""
    console.print("\n[bold cyan]=== Vulnerability Query Assistant ===[/bold cyan]")
    console.print('[dim]Type "help" for examples or ask a question (Ctrl+C to exit)[/dim]\n')

    while True:
        try:
            user_input = input("💬 ").strip()

            if not user_input:
                continue

            if user_input.lower() in ["help", "h", "?"]:
                print_help()
                continue

            if user_input.lower() in ["exit", "quit", "q"]:
                console.print("\n👋 Goodbye!")
                break

            # Process query
            console.print("\n[yellow]🔍 Searching...[/yellow]\n")
            answer = agent.answer_question(user_input)
            console.print(Markdown(answer))
            console.print()

        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}\n")


def single_query_mode(agent: VulnerabilityAgent, question: str) -> None:
    """Process a single query and exit."""
    try:
        answer = agent.answer_question(question)
        print(answer)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """CLI entry point with mode routing."""
    # Validate API key
    validate_api_key()

    # Read Typesense configuration from environment variables
    typesense_host = os.getenv("TYPESENSE_HOST", "localhost")
    typesense_port = os.getenv("TYPESENSE_PORT", "8108")
    typesense_api_key = os.getenv("TYPESENSE_API_KEY", "xyz")
    gemini_model = os.getenv("GEMINI_MODEL")
    google_api_key = os.getenv("GOOGLE_API_KEY")

    logger.info(
        "Starting vulnerability assistant",
        extra={
            "typesense_host": typesense_host,
            "typesense_port": typesense_port,
            "gemini_model": gemini_model or "default",
        },
    )

    # Initialize agent
    try:
        agent = VulnerabilityAgent(
            api_key=google_api_key,
            model=gemini_model,
            typesense_host=typesense_host,
            typesense_port=typesense_port,
            typesense_api_key=typesense_api_key,
        )
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error connecting to Typesense: {e}")
        print("   Is Docker Compose running? (docker-compose up -d)")
        sys.exit(1)

    # Route to single-query or interactive mode
    if len(sys.argv) > 1:
        # Single query mode
        question = " ".join(sys.argv[1:])
        single_query_mode(agent, question)
    else:
        # Interactive mode
        interactive_mode(agent)


if __name__ == "__main__":
    main()
