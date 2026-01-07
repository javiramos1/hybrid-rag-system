#!/usr/bin/env python3
"""LLM agent with ReAct pattern for vulnerability question answering.

WHAT THIS AGENT DOES:

Orchestrates iterative search and synthesis of answers to vulnerability questions using
the ReAct (Reasoning + Acting) pattern:

1. User asks: "What npm vulnerabilities are Critical?"
2. Agent reasons: "I need structured data + aggregations. Use keyword search."
3. Agent acts: Calls search_vulnerabilities() with appropriate filters
4. Agent evaluates: "I got 5 documents + CVSS stats. That's enough."
5. Agent synthesizes: Generates final answer with citations (CVE IDs, versions, CVSS)
6. If insufficient data: Loop back to step 2 with refined search (max 6 iterations)

HOW IT'S IMPLEMENTED:

The agent uses low-level google-genai library to:
- Issue prompts to Gemini with tools (search_vulnerabilities declared as JSON schema)
- Parse function calls from LLM responses (extract search parameters)
- Execute searches and collect results into state
- Track iteration count, documents, and aggregations
- Detect when LLM returns "Final Answer:" and exit the loop
- Maintain chat history for multi-turn conversations

IMPORTANT: This is mostly boilerplate code. Most of the complexity here (response parsing,
retry logic, state management, chat history, function calling orchestration) is completely
unnecessary in production—it's only needed because the challenge requires low-level API control.

Frameworks like PydanticAI automatically handle:
- Function call parsing and validation (no manual string parsing)
- Automatic retries with exponential backoff (built-in)
- ReAct pattern orchestration (no manual iteration loops)
- Chat history and conversation memory (automatic)
- Tool calling and result collection (seamless)
- Type-safe response handling (no try/except chains)
- Rate limiting and quota management (built-in)

In Production, besides using high-level frameworks like PydanticAI, we would also leverage tracing tools like LangSmith 
for monitoring, debugging, and improving agent performance and other MCP servers for long term memory, web search, library search (Context7), etc.

FOCUS OF REVIEW: The real RAG logic is in search_tool.py (hybrid search, filters, 
aggregations) and prompts.py (routing decisions). This file is verbose scaffolding 
that makes implementation details explicit but isn't where the intelligence happens.

CURRENT TRADE-OFFS (intentional for learning):
- Limited error handling, manual response parsing, verbose explicit logic flow
- Makes decision logic transparent but less maintainable at scale
- Makes the code harder to follow compared to using a high-level framework
- Iteration tracking: Agent manually tracks when to search again vs. when to answer
"""

from typing import Optional, List
from dataclasses import dataclass, field

from google import genai
from google.genai import types

from config import Config
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
class ChatMessage:
    """Represents a single message in chat history."""

    user_question: str
    final_answer: str


@dataclass
class IterationState:
    """Tracks state during ReAct iteration."""

    iteration: int
    search_history: list  # List of (search_type, query, results_count)
    documents_collected: dict  # CVE ID -> document, for deduplication
    search_parameters: list = field(default_factory=list)  # Full search parameters for each search (used for dedup + LLM visibility)
    aggregations_collected: dict = None  # Field name -> aggregation data (optional, defaults to empty dict)
    question_embedding: Optional[List[float]] = None  # Cached embedding of original question
    final_answer: Optional[str] = None

    def __post_init__(self):
        """Initialize mutable defaults after dataclass creation."""
        if self.aggregations_collected is None:
            self.aggregations_collected = {}


class VulnerabilityAgent:
    """Query agent using ReAct pattern with Gemini function calling."""

    def __init__(self, config: Config):
        """Initialize agent with ReAct capabilities.

        Args:
            config: Config instance with all settings (API keys, model names, etc.)
        """
        self.config = config
        self.chat_history: List[ChatMessage] = []

        self.client = genai.Client(api_key=config.google_api_key)
        self.search_tool = VulnerabilitySearchTool(config)
        logger.info(f"Initialized agent: {config}")

    def search_heuristics(self, user_question: str, state: IterationState) -> None:
        """Apply search heuristics to optimize initial strategy.
        
        This method detects specific query patterns and pre-executes targeted searches
        to enhance the agent's capabilities. These are optional optimizations that help
        the agent find relevant results faster and with better precision.
        
        IMPORTANT: These heuristics are NOT mandatory rules imposed on the agent. They are
        suggestions and optimizations. The agent remains the decision-maker and can override
        these strategies if they don't yield results or don't match the query intent.
        
        Current heuristics:
        - Section-specific queries: Detects keywords (testing, remediation, best practices, details)
          and pre-executes targeted search filtered to that advisory section
        - General advisory queries: "documented/advisory/detailed" → filter to CVEs with advisory chunks
        
        Filter Syntax:
        - Typesense nested array filtering uses: field.{filter_conditions}
        - Example: "advisory_chunks.{section:=remediation}" filters nested chunks
        
        Args:
            user_question: The user's original query
            state: Iteration state to update with pre-collected results
        """
        q_lower = user_question.lower()
        
        # Check for section-specific keywords (primary heuristics)
        has_remediation = any(w in q_lower for w in [
            "remediation", "remediate", "fix", "fixed", "solution", "mitigation", "patch"
        ])
        has_testing = any(w in q_lower for w in [
            "testing", "test", "verify", "verification", "how to test", "test case"
        ])
        has_best_practices = any(w in q_lower for w in [
            "best practice", "best practices", "recommendation", "secure coding", "security best"
        ])
        has_details = any(w in q_lower for w in [
            "detail", "details", "information", "overview", "vulnerability details"
        ])
        
        # Check for general documentation/advisory requests (secondary heuristic)
        has_documented = any(w in q_lower for w in [
            "well-documented", "well documented", "documented", 
            "advisory", "comprehensive"
        ])
        
        # Determine which section to search for
        section_filter = None
        section_name = None
        
        if has_remediation:
            section_filter = "advisory_chunks.{section:=remediation}"
            section_name = "remediation"
        elif has_testing:
            section_filter = "advisory_chunks.{section:=testing}"
            section_name = "testing"
        elif has_best_practices:
            section_filter = "advisory_chunks.{section:=best_practices}"
            section_name = "best_practices"
        elif has_details:
            section_filter = "advisory_chunks.{section:=details}"
            section_name = "details"
        elif has_documented:
            # General advisory request without specific section
            section_name = "advisory"
        else:
            # No heuristic applies
            return
        
        # Build and execute heuristic search
        base_filter = "has_advisory:true"
        additional_filters = f"{base_filter} && {section_filter}" if section_filter else base_filter
        
        logger.info(f"📋 HEURISTIC: {section_name.upper()} section pattern detected")
        logger.info(f"   → Pre-executing advisory filter search (section={section_name})")
        
        result = self.search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters=additional_filters,
            facet_by="vulnerability_type,severity,ecosystem",
            per_page=20
        )
        
        state.search_history.append((f"keyword (advisory)", "*", result.total_found))
        state.aggregations_collected = result.aggregations or {}
        
        if result.documents:
            for doc in result.documents:
                cve_id = doc.get("cve_id") or doc.get("id")
                state.documents_collected[cve_id] = doc
        
        if result.total_found > 0:
            logger.info(f"✅ Heuristic search: {result.total_found} CVEs with {section_name} sections found")
        else:
            logger.info(f"⚠️  Heuristic search found 0 results for {section_name} - agent will refine")

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

        # Get tool and system instruction with chat history
        tool = types.Tool(function_declarations=[get_search_tool_declaration()])
        system_instruction = get_system_instruction(chat_history=self.chat_history)

        # Apply search heuristics: optimize initial search strategy
        self.search_heuristics(user_question, state)

        # Main ReAct loop
        while state.iteration < self.config.max_react_iterations:
            state.iteration += 1
            logger.info(f"\n>>> Iteration {state.iteration}/{self.config.max_react_iterations}")

            # Build prompt: first iteration uses question directly, later use full history
            if state.iteration == 1:
                prompt_content = user_question
            else:
                is_final_iteration = state.iteration >= self.config.max_react_iterations
                prompt_content = get_react_iteration_prompt(
                    user_question, 
                    state.iteration, 
                    state.search_history,
                    state.documents_collected,  # Pass actual documents
                    state.aggregations_collected,  # Pass actual aggregations
                    search_parameters=state.search_parameters,  # Pass search parameters for clarity
                    is_final_iteration=is_final_iteration  # Signal final iteration
                )

            # Ask LLM what to do next (search or answer)
            response = retry_with_backoff(
                lambda: self.client.models.generate_content(
                    model=self.config.gemini_model,
                    contents=prompt_content,
                    config=types.GenerateContentConfig(
                        tools=[tool],
                        system_instruction=system_instruction,
                        temperature=0.1,
                    ),
                ),
                max_retries=self.config.max_retries,
                extra_prompt="Decide whether to search again or provide final answer.",
            )

            # Check for function call (LLM wants to search)
            function_call = self._extract_function_call(response)

            if function_call and function_call.name == "search_vulnerabilities":
                self._execute_search_and_collect(function_call, state)

            else:
                # LLM decided not to call a function - check for final answer
                should_break = self._process_response(response, state)
                if should_break:
                    break

        if state.iteration >= self.config.max_react_iterations:
            logger.warning(f"Reached max iterations ({self.config.max_react_iterations})")
            if not state.final_answer:
                state.final_answer = "Sorry, we could not generate an answer. Please try a different question or refine your query."

        result = state.final_answer or "Could not generate answer."
        
        # Add to chat history and maintain max size
        self.chat_history.append(ChatMessage(
            user_question=user_question,
            final_answer=result
        ))
        
        # Keep only the last max_chat_history messages
        if len(self.chat_history) > self.config.max_chat_history:
            self.chat_history = self.chat_history[-self.config.max_chat_history:]
        
        logger.info(f"Chat history size: {len(self.chat_history)}/{self.config.max_chat_history}")
        logger.info(f"\n✅ Final answer ({len(result)} chars)\n\n")
        return result

    def _get_search_signature(self, args_dict: dict) -> tuple:
        """Generate signature for search parameters to detect duplicates.
        
        Signature includes core search logic (type, query, filters, constraints)
        but excludes refinement parameters (facet_by, per_page) which can vary
        without constituting a true duplicate search.
        
        Args:
            args_dict: Dictionary of search arguments
            
        Returns:
            Hashable tuple representing core search parameters
        """
        return (
            args_dict.get("search_type", "hybrid"),
            args_dict.get("query", "*"),
            args_dict.get("additional_filters", ""),
            tuple(sorted(args_dict.get("cve_ids", []) or [])),
            tuple(sorted(args_dict.get("ecosystems", []) or [])),
            tuple(sorted(args_dict.get("severity_levels", []) or [])),
            tuple(sorted(args_dict.get("vulnerability_types", []) or [])),
        )

    def _is_duplicate_search(self, search_sig: tuple, state: IterationState) -> bool:
        """Check if search signature matches any previous searches.
        
        Args:
            search_sig: Signature tuple from _get_search_signature()
            state: Iteration state containing previous search parameters
            
        Returns:
            True if this signature was already searched, False if new search
        """
        for prev_params in state.search_parameters:
            prev_sig = self._get_search_signature(prev_params)
            if prev_sig == search_sig:
                return True
        return False

    def _execute_search_and_collect(self, function_call, state: IterationState) -> None:
        """Execute search and collect documents/aggregations into state.
        
        Args:
            function_call: LLM function call with search arguments
            state: Current iteration state to update with search results
        """
        # Parse search arguments
        args_dict = dict(function_call.args) if function_call.args else {}
        
        # Check for duplicate search before executing
        search_sig = self._get_search_signature(args_dict)
        if self._is_duplicate_search(search_sig, state):
            logger.warning(
                f"⏭️  Skipping duplicate search: {args_dict.get('search_type', 'hybrid')} / "
                f"query='{args_dict.get('query', '*')}' / "
                f"filters='{args_dict.get('additional_filters', '')}' "
                f"(Already searched in previous iteration)"
            )
            return
        
        # Execute search with cached question embedding for performance
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
        
        # Track full search parameters for deduplication and LLM visibility
        state.search_parameters.append({
            "search_type": args_dict.get("search_type", "hybrid"),
            "query": args_dict.get("query", "*"),
            "filters": args_dict.get("additional_filters", ""),
            "cve_ids": args_dict.get("cve_ids", []),
            "ecosystems": args_dict.get("ecosystems", []),
            "severity_levels": args_dict.get("severity_levels", []),
            "vulnerability_types": args_dict.get("vulnerability_types", []),
            "results_found": search_result.total_found,
        })

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

    def _process_response(self, response, state: IterationState) -> bool:
        """Process LLM response and check if it contains a final answer.
        
        Args:
            response: LLM response object
            state: Current iteration state to update with final answer if found
            
        Returns:
            True if final answer was found and state updated, False to continue iteration
        """
        # Extract text response
        # NOTE: Exception handling here is intentionally broad. The response object
        # may vary (sometimes a string, sometimes an object with attributes).
        # We catch all exceptions and fall back to None, which triggers another
        # iteration. This is safe because the worst case is one extra iteration.
        try:
            text_response = response.text if hasattr(response, "text") else None
        except Exception as e:
            logger.warning(f"Failed to extract text from response: {e}")
            text_response = None
        
        if not text_response:
            logger.warning("Empty response from LLM - continuing to next iteration")
            return False
        
        # Check if "Final Answer:" appears anywhere in the response (case-insensitive)
        lower_text = text_response.lower()
        if "final answer:" in lower_text:
            logger.info("Final answer received from LLM")
            state.final_answer = self._strip_final_answer_prefix(text_response).strip()
            return True
        else:
            # LLM returned text but no final answer marker
            # Log first 200 chars to help debug what LLM is returning
            preview = text_response[:200].replace("\n", " ")
            logger.warning(
                f"LLM returned text without 'Final Answer:' prefix - continuing to next iteration | "
                f"response_preview={preview}"
            )
            return False

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

    def _strip_final_answer_prefix(self, text: str) -> str:
        """Strip 'Final Answer:' prefix from LLM response."""
        lower_text = text.lower()
        idx = lower_text.find("final answer:")
        if idx >= 0:
            return text[idx + len("final answer:"):].strip()
        return text
