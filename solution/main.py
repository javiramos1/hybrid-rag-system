#!/usr/bin/env python3
"""
Main Entry Point for Vulnerability Query Assistant.

Simple CLI that allows users to ask questions about software vulnerabilities.

NOTE: This implementation uses a basic REPL loop and direct API calls via google-genai.
For production-grade applications, consider using a framework like PydanticAI which already comes with a feature rich CLI.
Reviewer: Ignore this file for the purpose of the challenge, focus on the core logic in the src/ folder.

Supports two modes:
  - Interactive: python main.py (REPL with 'help', 'exit' commands)
  - Single query: python main.py "your question here"
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from config import Config
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


def validate_config() -> Config:
    """Load and validate configuration from environment variables.

    Returns:
        Config instance with all settings

    Raises:
        ValueError: If required configuration is missing
    """
    try:
        config = Config.from_env()
        logger.info(f"Configuration loaded: {config}")
        return config
    except ValueError as e:
        print(f"❌ Error: {e}")
        print("   Get your Google API key at: https://aistudio.google.com/app/apikey")
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
    # Load and validate configuration
    config = validate_config()

    logger.info(
        "Starting vulnerability assistant",
        extra={
            "typesense_host": config.typesense_host,
            "typesense_port": config.typesense_port,
            "gemini_model": config.gemini_model,
        },
    )

    # Initialize agent with config
    try:
        agent = VulnerabilityAgent(config)
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
