#!/usr/bin/env python3
"""LLM agent with ReAct pattern for intelligent vulnerability query answering.

DESIGN NOTES:
- Implements ReAct (Reasoning + Acting) pattern for multi-iteration search and synthesis
- Uses low-level google-genai library for direct API control (per requirement to avoid
  high-level RAG frameworks like LangChain, LlamaIndex, PydanticAI, etc.)
- Trade-offs: No conversation memory, limited function call error handling, and manual
  response parsing. High-level frameworks would provide automatic retries, validation,
  and state management, but implementing core logic from scratch was a requirement.
- Result: More verbose code with explicit 3-step flow (initial query → search execution →
  answer synthesis) rather than automatic orchestration.
- Simple, human-readable code: decision logic is explicit, not hidden in framework magic
- Iteration tracking: agent knows when to search again vs. when to answer
"""

import os
from typing import Optional, List
from dataclasses import dataclass

from google import genai
from google.genai import types

from logger import get_logger
from search_tool import VulnerabilitySearchTool
from utils import retry_with_backoff
from prompts import (
    get_search_tool_declaration,
    get_system_instruction,
    get_react_iteration_prompt,
)

logger = get_logger(__name__)


@dataclass
class IterationState:
    """Tracks state during ReAct iteration."""

    iteration: int
    search_history: list  # List of (search_type, query, results_count)
    documents_collected: dict  # CVE ID -> document, for deduplication
    aggregations_collected: dict = None  # Field name -> aggregation data (optional, defaults to empty dict)
    question_embedding: Optional[List[float]] = None  # Cached embedding of original question
    final_answer: Optional[str] = None

    def __post_init__(self):
        """Initialize mutable defaults after dataclass creation."""
        if self.aggregations_collected is None:
            self.aggregations_collected = {}


class VulnerabilityAgent:
    """Query agent using ReAct pattern with Gemini function calling."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_iterations: Optional[int] = 6,
        max_retries: Optional[int] = 2,
        typesense_host: str = "localhost",
        typesense_port: str = "8108",
        typesense_api_key: str = "xyz",
    ):
        """Initialize agent with ReAct capabilities.

        Args:
            api_key: Google API key (defaults to GOOGLE_API_KEY env var)
            model: Gemini model (defaults to GEMINI_MODEL env var)
            max_iterations: Max ReAct iterations (defaults to MAX_REACT_ITERATIONS env var, fallback 5)
            max_retries: Max retries on API errors (defaults to MAX_RETRIES env var, fallback 2)
            typesense_host: Typesense server host
            typesense_port: Typesense server port
            typesense_api_key: Typesense API key
        """
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY environment variable not set")

        self.model = model or os.getenv("GEMINI_MODEL", "gemini-3-pro-preview")
        self.max_iterations = max_iterations or int(os.getenv("MAX_REACT_ITERATIONS", "6"))
        self.max_retries = max_retries or int(os.getenv("MAX_RETRIES", "2"))

        self.client = genai.Client(api_key=self.api_key)
        self.search_tool = VulnerabilitySearchTool(
            typesense_host, typesense_port, typesense_api_key
        )
        logger.info(
            f"Initialized agent: model={self.model}, max_iterations={self.max_iterations}, max_retries={self.max_retries}"
        )

    def answer_question(self, user_question: str) -> str:
        """Answer user question using ReAct pattern (Reasoning + Acting).

        Iteratively searches for information and synthesizes answers:
        1. Reason about what to search for
        2. Execute search
        3. Evaluate if more searches are needed
        4. When sufficient info is gathered, synthesize final answer

        Args:
            user_question: Natural language question

        Returns:
            Synthesized answer with citations
        """
        logger.info("=" * 80)
        logger.info(f"Starting ReAct loop for: {user_question}")
        logger.info("=" * 80)

        state = IterationState(
            iteration=0, 
            search_history=[], 
            documents_collected={}
        )

        # Pre-compute embedding of question once for reuse across iterations (performance optimization)
        # This avoids re-encoding the same question in each semantic/hybrid search
        state.question_embedding = self.search_tool.embedding_model.encode(user_question).tolist()

        # Get tool and system instruction
        tool = types.Tool(function_declarations=[get_search_tool_declaration()])
        system_instruction = get_system_instruction()

        # Main ReAct loop
        while state.iteration < self.max_iterations:
            state.iteration += 1
            logger.info(f"\n>>> Iteration {state.iteration}/{self.max_iterations}")

            # Build prompt: first iteration uses question directly, later use full history
            if state.iteration == 1:
                prompt_content = user_question
            else:
                prompt_content = get_react_iteration_prompt(
                    user_question, state.iteration, state.search_history,
                    len(state.documents_collected), len(state.aggregations_collected)
                )

            # Ask LLM what to do next (search or answer)
            response = retry_with_backoff(
                lambda: self.client.models.generate_content(
                    model=self.model,
                    contents=prompt_content,
                    config=types.GenerateContentConfig(
                        tools=[tool],
                        system_instruction=system_instruction,
                        temperature=0.1,
                    ),
                ),
                max_retries=self.max_retries,
                extra_prompt="Decide whether to search again or provide final answer.",
            )

            # Check for function call (LLM wants to search)
            function_call = self._extract_function_call(response)

            if function_call and function_call.name == "search_vulnerabilities":
                # Execute search with cached question embedding for performance
                args_dict = dict(function_call.args) if function_call.args else {}
                args_dict["query_embedding"] = state.question_embedding
                
                search_result = self.search_tool.search_vulnerabilities(**args_dict)

                # Track search in history
                state.search_history.append(
                    (
                        args_dict.get("search_type", "hybrid"),
                        args_dict.get("query", "*"),
                        search_result.total_found,
                    )
                )

                # Collect unique documents
                if search_result.documents:
                    for doc in search_result.documents:
                        cve_id = doc.get("cve_id")
                        if cve_id and cve_id not in state.documents_collected:
                            state.documents_collected[cve_id] = doc

                # Collect aggregations (for statistics queries)
                if search_result.aggregations:
                    logger.debug(f"Collecting aggregations: {list(search_result.aggregations.keys())}")
                    for field, agg_data in search_result.aggregations.items():
                        state.aggregations_collected[field] = agg_data

                logger.info(
                    f"Found {search_result.total_found} results. "
                    f"Unique docs: {len(state.documents_collected)}, "
                    f"Aggregations: {len(state.aggregations_collected)}"
                )
                # Continue loop - LLM will decide next action

            else:
                # LLM decided not to call a function - check if it's providing a Final Answer
                text_response = self._extract_text_response(response)
                if text_response and "Final Answer" in text_response:
                    logger.info("LLM provided final answer - synthesizing comprehensive response from collected data")
                    # LLM decided to answer; synthesize from collected data for consistent formatting
                    # This ensures consistent formatting, citations, and grounding statements
                    state.final_answer = self._synthesize_final_answer(
                        user_question, state, system_instruction
                    )
                    break
                else:
                    logger.warning("No function call and no Final Answer in response - trying again")
                    if state.iteration >= self.max_iterations:
                        state.final_answer = "Could not generate answer after maximum iterations."
                        break

        if state.iteration >= self.max_iterations:
            logger.warning(f"Reached max iterations ({self.max_iterations})")
            if not state.final_answer:
                # Synthesize answer from collected data
                state.final_answer = self._synthesize_final_answer(
                    user_question, state, system_instruction
                )

        result = state.final_answer or "Could not generate answer."
        logger.info(f"\n✅ Final answer ({len(result)} chars)")
        logger.info("=" * 80 + "\n")
        return result

    def _extract_function_call(self, response):
        """Extract function call from LLM response if present."""
        if not response or not response.candidates:
            return None

        candidate = response.candidates[0]
        if not candidate.content or not candidate.content.parts:
            return None

        for part in candidate.content.parts:
            if hasattr(part, "function_call") and part.function_call:
                return part.function_call

        return None

    def _extract_text_response(self, response) -> Optional[str]:
        """Extract text response from LLM.
        
        Uses the direct .text property (per google-genai docs) with minimal fallback.
        """
        if not response:
            logger.debug("Response is None")
            return None
        
        # Check for finish reason issues that prevent text extraction
        if hasattr(response, "candidates") and response.candidates:
            candidate = response.candidates[0]
            if hasattr(candidate, "finish_reason"):
                finish_reason = str(candidate.finish_reason)
                if "MALFORMED" in finish_reason or "SAFETY" in finish_reason:
                    logger.warning(f"LLM response blocked: {finish_reason}")
                    return None
        
        try:
            # Primary: Use direct .text property (recommended by google-genai docs)
            if hasattr(response, "text") and response.text:
                logger.debug(f"Extracted text: {len(response.text)} chars")
                return response.text
        except Exception as e:
            logger.debug(f"Error accessing response.text: {e}")
        
        return None

    def _synthesize_final_answer(
        self, user_question: str, state: IterationState, system_instruction: str
    ) -> str:
        """Synthesize final answer from collected documents and search history.
        
        Uses comprehensive context with full document details to help LLM generate
        better answers. Includes synthesis instructions and structured formatting hints.
        
        IMPORTANT: No tools are provided in synthesis to prevent function call confusion.
        """
        logger.info("Synthesizing answer from collected documents...")

        # Build comprehensive context from collected documents
        context = self._build_answer_context(user_question, state)
        logger.debug(f"Synthesis context length: {len(context)} chars")

        # Create synthesis-specific system instruction (no function calling)
        synthesis_system_instruction = (
            "You are a security analyst providing clear, well-formatted answers about vulnerabilities. "
            "Based on the search results provided, answer the user's question comprehensively. "
            "\n\nCITATION REQUIREMENTS (CRITICAL):\n"
            "- Always cite specific CVE IDs, package names, ecosystems, and CVSS scores\n"
            "- For aggregation/statistics queries, include counts and averages\n"
            "- ALWAYS end your answer with a grounding statement showing data sources\n"
            "  Examples: 'Source: 5 CVE records from the vulnerability database'\n"
            "           'Source: Analyzed 12 CVE documents with CVSS statistics'\n"
            "           'Source: 8 CVE documents with detailed advisories'\n"
            "\n"
            "FORMATTING:\n"
            "- Use markdown headers (##, ###) for sections\n"
            "- Use bullet points for lists\n"
            "- Use code blocks (```python, ```javascript) for code examples\n"
            "- Aim for 500+ words for comprehensive answers\n"
            "- Provide remediation steps, attack vectors, or explanations where relevant\n"
            "\n"
            "IMPORTANT: Do NOT attempt to call any functions - just provide a direct text answer."
        )

        # Ask LLM to synthesize answer with explicit retries
        def make_synthesis_request():
            return self.client.models.generate_content(
                model=self.model,
                contents=context,
                config=types.GenerateContentConfig(
                    system_instruction=synthesis_system_instruction,
                    temperature=0.1,
                ),
            )

        response = retry_with_backoff(
            make_synthesis_request,
            max_retries=self.max_retries,
            extra_prompt="IMPORTANT: You MUST generate a clear, well-formatted TEXT response explaining the search results and answering the user's question. Do NOT attempt to call functions. Even if no documents were found, provide a helpful explanation.",
        )

        # Extract answer from response
        answer = self._extract_text_response(response)
        
        if answer:
            logger.info(f"Synthesis result: {len(answer)} chars")
            return answer
        else:
            logger.warning("LLM synthesis returned empty response - returning fallback")
            return "Unable to synthesize answer from search results."

    def _build_answer_context(self, user_question: str, state: IterationState) -> str:
        """Build comprehensive context for answer synthesis with full document details."""
        lines = [
            f"User's Question: {user_question}\n",
            f"Search History ({len(state.search_history)} searches):",
        ]
        
        # Add search history
        for i, (search_type, query, count) in enumerate(state.search_history, 1):
            lines.append(f"  {i}. {search_type}: '{query}' -> {count} results")

        # Add aggregation results (for statistics queries)
        if state.aggregations_collected:
            lines.append("\nAggregation Results:")
            for field, agg_data in state.aggregations_collected.items():
                if isinstance(agg_data, dict):
                    if "stats" in agg_data:
                        stats = agg_data["stats"]
                        lines.append(f"  {field} Statistics:")
                        lines.append(f"    - Average: {stats.get('avg', 'N/A')}")
                        lines.append(f"    - Minimum: {stats.get('min', 'N/A')}")
                        lines.append(f"    - Maximum: {stats.get('max', 'N/A')}")
                        lines.append(f"    - Sum: {stats.get('sum', 'N/A')}")
                    if "counts" in agg_data:
                        lines.append(f"  {field} Counts:")
                        for count_item in agg_data["counts"][:10]:  # Top 10
                            lines.append(f"    - {count_item.get('value', 'N/A')}: {count_item.get('count', 0)} vulnerabilities")

        # Add collected documents
        lines.append(f"\nCollected Documents ({len(state.documents_collected)}):")
        if state.documents_collected:
            for idx, (cve_id, doc) in enumerate(state.documents_collected.items(), 1):
                lines.append(f"\n{idx}. CVE: {cve_id}")
                lines.append(f"   Package: {doc.get('package_name', 'N/A')}")
                lines.append(f"   Ecosystem: {doc.get('ecosystem', 'N/A')}")
                lines.append(f"   Severity: {doc.get('severity', 'N/A')}")
                lines.append(f"   CVSS Score: {doc.get('cvss_score', 'N/A')}")
                lines.append(f"   Vulnerability Type: {doc.get('vulnerability_type', 'N/A')}")
                
                if doc.get("description"):
                    desc = doc['description']
                    lines.append(f"   Description: {desc[:500] if len(desc) > 500 else desc}")

                if doc.get("advisory_text"):
                    advisory = doc['advisory_text']
                    lines.append(f"   Advisory: {advisory[:500] if len(advisory) > 500 else advisory}")
        elif not state.aggregations_collected:
            lines.append("No documents found in searches.")

        # Add synthesis instructions (CRITICAL: enforce grounding and sourcing)
        lines.extend([
            "\n" + "="*80,
            "SYNTHESIS INSTRUCTIONS (CRITICAL - FOLLOW ALL):",
            "",
            "1. ANSWER THE QUESTION:",
            "   - Answer the user's question based on the data provided above",
            "   - If aggregation results are provided, use those statistics to answer the question",
            "   - If no relevant information was found, explain why and suggest alternative queries",
            "",
            "2. PROVIDE CITATIONS (MANDATORY):",
            "   - Always cite specific CVE IDs (e.g., CVE-2024-1234)",
            "   - Include package names and ecosystems (npm, pip, maven)",
            "   - Include CVSS scores and severity levels",
            "   - Reference affected versions and fixed versions",
            "   - If code examples are available, include vulnerable + fixed patterns",
            "",
            "3. INCLUDE GROUNDING STATEMENT (CRITICAL - DO NOT SKIP):",
            "   - ALWAYS end your answer with a source/grounding statement",
            "   - Count the documents/records you analyzed and include in statement",
            f"   - Examples (choose the appropriate one):",
            f"     * 'Source: Analyzed {len(state.documents_collected)} CVE records from the vulnerability database'",
            f"     * 'Source: {len(state.documents_collected)} CVE documents with detailed advisories'",
            f"     * 'Source: Retrieved {len(state.documents_collected)} vulnerability records'",
            f"   - If aggregations are included: 'Source: Analyzed {len(state.documents_collected)} CVE records; statistics computed from available data'",
            "",
            "4. FORMATTING:",
            "   - Use markdown headers (##, ###) for major sections",
            "   - Use bullet points for lists",
            "   - Use code blocks (```python, ```javascript, etc.) for code examples",
            "   - Aim for comprehensive answers (500+ words)",
            "   - Provide remediation steps, attack vectors, or explanations",
            "",
            "5. COMMON MISTAKES TO AVOID:",
            "   - DO NOT end without a grounding statement (Source: ...)",
            "   - DO NOT skip CVE IDs, CVSS scores, or package ecosystems",
            "   - DO NOT provide short, generic answers (be comprehensive)",
            "   - DO NOT suggest searches (the search is already done)",
            "="*80,
        ])

        return "\n".join(lines)
