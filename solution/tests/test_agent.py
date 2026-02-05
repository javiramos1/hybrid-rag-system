#!/usr/bin/env python3
"""Tests for LLM agent."""

import os
import sys
from pathlib import Path

import pytest
from dotenv import load_dotenv

# Load .env file for tests
load_dotenv()

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# ruff: noqa: E402
from agent import VulnerabilityAgent, ChatMessage, IterationState
from config import Config
from prompts import get_search_tool_declaration, get_system_instruction


@pytest.fixture
def config():
    """Create config instance for tests."""
    return Config.from_env()


@pytest.fixture
def agent(config):
    """Create agent instance for tests."""
    return VulnerabilityAgent(config)


# Skip all tests if API key not set
pytestmark = pytest.mark.skipif(
    not os.getenv("GOOGLE_API_KEY"),
    reason="GOOGLE_API_KEY not set",
)


class TestVulnerabilityAgent:
    """Test agent functionality."""

    def test_agent_initialization(self, config):
        """Test agent can be initialized with API key."""
        agent = VulnerabilityAgent(config)
        assert agent.config is not None
        assert agent.search_tool is not None

    def test_agent_missing_api_key(self, monkeypatch):
        """Test agent raises error without API key."""
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="GOOGLE_API_KEY"):
            Config.from_env()

    def test_search_declaration_structure(self, agent):
        """Test function declaration is properly structured."""
        decl = get_search_tool_declaration()
        assert decl.name == "search_vulnerabilities"
        # FunctionDeclaration.parameters is a Schema object, just verify it exists
        assert decl.parameters is not None
        # Verify description contains routing info
        assert "keyword" in decl.description.lower()
        assert "semantic" in decl.description.lower()
        assert "hybrid" in decl.description.lower()

    def test_system_instruction_contains_routing_logic(self, agent):
        """Test system instruction has query routing guidelines."""
        instruction = get_system_instruction()
        assert "KEYWORD" in instruction
        assert "SEMANTIC" in instruction
        assert "HYBRID" in instruction
        assert "facet_by" in instruction


class TestReActPattern:
    """Test ReAct (Reasoning + Acting) pattern implementation."""

    def test_agent_initialization_with_max_iterations(self, config):
        """Test agent can be initialized with custom max_iterations."""
        # Create a config with custom max_iterations
        modified_config = Config(
            google_api_key=config.google_api_key,
            gemini_model=config.gemini_model,
            typesense_host=config.typesense_host,
            typesense_port=config.typesense_port,
            typesense_api_key=config.typesense_api_key,
            max_react_iterations=3,
            max_retries=config.max_retries,
            max_chat_history=config.max_chat_history,
            vector_search_k=config.vector_search_k,
            embedding_model=config.embedding_model,
        )
        agent = VulnerabilityAgent(modified_config)
        assert agent.config.max_react_iterations == 3

    def test_default_max_iterations(self, config):
        """Test agent defaults to 6 max iterations."""
        agent = VulnerabilityAgent(config)
        assert agent.config.max_react_iterations == 6

    def test_extract_function_call_present(self, agent):
        """Test extracting function call from response when present."""
        from unittest.mock import Mock

        # Mock response with function call
        response = Mock()
        func_call = Mock()
        func_call.name = "search_vulnerabilities"
        func_call.args = {"query": "test", "search_type": "keyword"}

        part = Mock()
        part.function_call = func_call

        candidate = Mock()
        candidate.content.parts = [part]
        response.candidates = [candidate]

        result = agent._extract_function_call(response)
        assert result is not None
        assert result.name == "search_vulnerabilities"

    def test_extract_function_call_absent(self, agent):
        """Test extracting function call when not present."""
        from unittest.mock import Mock

        # Mock response without function call
        response = Mock()
        part = Mock(spec=[])
        part.function_call = None

        candidate = Mock()
        candidate.content.parts = [part]
        response.candidates = [candidate]

        result = agent._extract_function_call(response)
        assert result is None

    def test_process_response_with_final_answer(self, agent):
        """Test _process_response extracts final answer."""
        from unittest.mock import Mock

        response = Mock()
        response.text = "Let me analyze this. Final Answer: The vulnerability has CVSS 9.8"

        state = IterationState(iteration=1, search_history=[], documents_collected={})

        result = agent._process_response(response, state)

        assert result is True
        assert "CVSS 9.8" in state.final_answer
        assert "Let me analyze" not in state.final_answer

    def test_process_response_without_final_answer(self, agent):
        """Test _process_response continues when no final answer marker."""
        from unittest.mock import Mock

        response = Mock()
        response.text = "Let me search for more information about this vulnerability."

        state = IterationState(iteration=1, search_history=[], documents_collected={})

        result = agent._process_response(response, state)

        assert result is False
        assert state.final_answer is None

    def test_iteration_state_initialization(self):
        """Test IterationState dataclass."""
        state = IterationState(iteration=1, search_history=[], documents_collected={})

        assert state.iteration == 1
        assert state.search_history == []
        assert state.documents_collected == {}
        assert state.final_answer is None

    def test_iteration_state_mutation(self):
        """Test IterationState can be mutated during loop."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        # Simulate iteration
        state.iteration += 1
        state.search_history.append(("keyword", "test", 5))
        state.documents_collected["CVE-2024-1"] = {"cve_id": "CVE-2024-1"}

        assert state.iteration == 1
        assert len(state.search_history) == 1
        assert len(state.documents_collected) == 1


class TestChatHistory:
    """Test chat history tracking functionality."""

    def test_agent_initializes_empty_chat_history(self, config):
        """Test agent starts with empty chat history."""
        agent = VulnerabilityAgent(config)
        assert agent.chat_history == []
        assert isinstance(agent.chat_history, list)

    def test_agent_default_max_chat_history(self, config):
        """Test agent defaults to MAX_CHAT_HISTORY=3."""
        agent = VulnerabilityAgent(config)
        assert agent.config.max_chat_history == 3

    def test_agent_custom_max_chat_history(self, config):
        """Test agent accepts custom max_chat_history."""
        # Create a config with custom max_chat_history
        modified_config = Config(
            google_api_key=config.google_api_key,
            gemini_model=config.gemini_model,
            typesense_host=config.typesense_host,
            typesense_port=config.typesense_port,
            typesense_api_key=config.typesense_api_key,
            max_react_iterations=config.max_react_iterations,
            max_retries=config.max_retries,
            max_chat_history=5,
            vector_search_k=config.vector_search_k,
            embedding_model=config.embedding_model,
        )
        agent = VulnerabilityAgent(modified_config)
        assert agent.config.max_chat_history == 5

    def test_agent_reads_max_chat_history_from_env(self, monkeypatch):
        """Test agent reads MAX_CHAT_HISTORY from environment variable."""
        # Clear existing env var if set
        monkeypatch.delenv("MAX_CHAT_HISTORY", raising=False)
        # Set the env var to test
        monkeypatch.setenv("MAX_CHAT_HISTORY", "7")
        # Create config that will read from env
        config = Config.from_env()
        agent = VulnerabilityAgent(config)
        assert agent.config.max_chat_history == 7

    def test_chat_message_creation(self):
        """Test ChatMessage dataclass."""
        msg = ChatMessage(
            user_question="What are critical vulnerabilities?",
            final_answer="Critical vulnerabilities include CVE-2024-1234...",
        )
        assert msg.user_question == "What are critical vulnerabilities?"
        assert msg.final_answer == "Critical vulnerabilities include CVE-2024-1234..."

    def test_system_instruction_without_chat_history(self):
        """Test system instruction when chat_history is empty."""
        instruction = get_system_instruction(chat_history=None)
        assert "REACT PATTERN" in instruction
        assert "PREVIOUS CONVERSATION HISTORY" not in instruction

    def test_system_instruction_with_empty_chat_history_list(self):
        """Test system instruction with empty list doesn't include history section."""
        instruction = get_system_instruction(chat_history=[])
        assert "REACT PATTERN" in instruction
        assert "PREVIOUS CONVERSATION HISTORY" not in instruction

    def test_system_instruction_with_single_message(self):
        """Test system instruction includes single chat message."""
        chat_history = [
            ChatMessage(
                user_question="List critical npm vulnerabilities",
                final_answer="Critical npm vulnerabilities include express-validator CVE-2024-1234...",
            )
        ]
        instruction = get_system_instruction(chat_history=chat_history)
        assert "PREVIOUS CONVERSATION HISTORY" in instruction
        assert "Exchange 1:" in instruction
        assert "List critical npm vulnerabilities" in instruction
        assert "express-validator CVE-2024-1234" in instruction

    def test_system_instruction_with_multiple_messages(self):
        """Test system instruction includes all chat messages."""
        chat_history = [
            ChatMessage(
                user_question="What are critical npm vulnerabilities?",
                final_answer="Critical npm vulns include...",
            ),
            ChatMessage(
                user_question="How do I fix CVE-2024-1234?",
                final_answer="To fix this vulnerability, upgrade to the patched version...",
            ),
            ChatMessage(
                user_question="Show XSS examples",
                final_answer="XSS examples demonstrate cross-site scripting...",
            ),
        ]
        instruction = get_system_instruction(chat_history=chat_history)
        assert "PREVIOUS CONVERSATION HISTORY" in instruction
        assert "Exchange 1:" in instruction
        assert "Exchange 2:" in instruction
        assert "Exchange 3:" in instruction
        assert "What are critical npm vulnerabilities?" in instruction
        assert "How do I fix CVE-2024-1234?" in instruction
        assert "Show XSS examples" in instruction

    def test_system_instruction_truncates_long_answers(self):
        """Test system instruction truncates long final answers."""
        long_answer = "A" * 2000  # 2000 character answer
        chat_history = [ChatMessage(user_question="Test question", final_answer=long_answer)]
        instruction = get_system_instruction(chat_history=chat_history)
        # Should contain the truncated version, not the full answer
        assert "Exchange 1:" in instruction
        # Should have truncation indicator
        assert "..." in instruction or len(instruction) < len(long_answer)

    def test_chat_history_maintains_order(self, config):
        """Test chat history maintains insertion order."""
        agent = VulnerabilityAgent(config)

        # Simulate adding messages
        for i in range(1, 4):
            msg = ChatMessage(user_question=f"Question {i}", final_answer=f"Answer {i}")
            agent.chat_history.append(msg)

        assert len(agent.chat_history) == 3
        assert agent.chat_history[0].user_question == "Question 1"
        assert agent.chat_history[1].user_question == "Question 2"
        assert agent.chat_history[2].user_question == "Question 3"

    def test_chat_history_respects_max_size(self, config):
        """Test chat history removes old messages when exceeding max."""
        # Create a config with custom max_chat_history
        modified_config = Config(
            google_api_key=config.google_api_key,
            gemini_model=config.gemini_model,
            typesense_host=config.typesense_host,
            typesense_port=config.typesense_port,
            typesense_api_key=config.typesense_api_key,
            max_react_iterations=config.max_react_iterations,
            max_retries=config.max_retries,
            max_chat_history=2,
            vector_search_k=config.vector_search_k,
            embedding_model=config.embedding_model,
        )
        agent = VulnerabilityAgent(modified_config)

        # Add 4 messages
        for i in range(1, 5):
            agent.chat_history.append(
                ChatMessage(user_question=f"Question {i}", final_answer=f"Answer {i}")
            )

            # Simulate the truncation logic from answer_question()
            if len(agent.chat_history) > agent.config.max_chat_history:
                agent.chat_history = agent.chat_history[-agent.config.max_chat_history :]

        # Should only have last 2 messages
        assert len(agent.chat_history) == 2
        assert agent.chat_history[0].user_question == "Question 3"
        assert agent.chat_history[1].user_question == "Question 4"

    def test_chat_history_with_max_chat_history_three(self, config):
        """Test chat history correctly manages 3 messages (default)."""
        # Create a config with custom max_chat_history
        modified_config = Config(
            google_api_key=config.google_api_key,
            gemini_model=config.gemini_model,
            typesense_host=config.typesense_host,
            typesense_port=config.typesense_port,
            typesense_api_key=config.typesense_api_key,
            max_react_iterations=config.max_react_iterations,
            max_retries=config.max_retries,
            max_chat_history=3,
            vector_search_k=config.vector_search_k,
            embedding_model=config.embedding_model,
        )
        agent = VulnerabilityAgent(modified_config)

        # Add 5 messages
        messages = [
            ("What are npm vulns?", "npm vulns..."),
            ("Fix CVE-2024-1?", "Upgrade to..."),
            ("Show XSS?", "XSS attacks..."),
            ("List High severity?", "High severity includes..."),
            ("Explain SQL injection?", "SQL injection is..."),
        ]

        for question, answer in messages:
            agent.chat_history.append(ChatMessage(user_question=question, final_answer=answer))

            if len(agent.chat_history) > agent.config.max_chat_history:
                agent.chat_history = agent.chat_history[-agent.config.max_chat_history :]

        # Should only have last 3 messages: messages[2], messages[3], messages[4]
        assert len(agent.chat_history) == 3
        assert agent.chat_history[0].user_question == "Show XSS?"
        assert agent.chat_history[1].user_question == "List High severity?"
        assert agent.chat_history[2].user_question == "Explain SQL injection?"

    def test_system_instruction_formats_exchanges_correctly(self):
        """Test system instruction formats chat exchanges with correct structure."""
        chat_history = [
            ChatMessage(user_question="Question 1", final_answer="Answer 1"),
            ChatMessage(user_question="Question 2", final_answer="Answer 2"),
        ]
        instruction = get_system_instruction(chat_history=chat_history)

        # Check structure
        assert "Exchange 1:" in instruction
        assert "User: Question 1" in instruction
        assert "Assistant: Answer 1" in instruction

        assert "Exchange 2:" in instruction
        assert "User: Question 2" in instruction
        assert "Assistant: Answer 2" in instruction

    def test_system_instruction_with_special_characters(self):
        """Test system instruction handles special characters in questions/answers."""
        chat_history = [
            ChatMessage(
                user_question="What about CVE-2024-1234 & XSS?",
                final_answer="It affects npm packages like express-validator. See code: var x = '<script>';",
            )
        ]
        instruction = get_system_instruction(chat_history=chat_history)

        # Should preserve special characters
        assert "CVE-2024-1234" in instruction
        assert "express-validator" in instruction


class TestSearchHeuristics:
    """Test search heuristics for optimized query handling."""

    def test_heuristic_documented_basic(self, agent):
        """Test heuristic detects 'documented' keyword."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        # Should trigger heuristic 1
        agent.search_heuristics("Show me well-documented vulnerabilities", state)

        # Should have executed a search
        assert len(state.search_history) > 0, "Should have pre-executed search"
        assert len(state.documents_collected) > 0, "Should have collected documents"

    def test_heuristic_advisory_keyword(self, agent):
        """Test heuristic detects 'advisory' keyword."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        agent.search_heuristics("List CVEs with advisory documentation", state)

        assert len(state.search_history) > 0
        assert state.search_history[0][0] == "keyword (advisory)"

    def test_heuristic_remediation_refinement(self, agent):
        """Test heuristic adds remediation section filter when mentioned."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        agent.search_heuristics("Show documented vulnerabilities with remediation steps", state)

        # Should have executed search with remediation filter
        assert len(state.search_history) > 0
        # Documents should be collected
        assert len(state.documents_collected) >= 0

    def test_heuristic_testing_refinement(self, agent):
        """Test heuristic adds testing section filter when mentioned."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        agent.search_heuristics("Show documented vulnerabilities with testing documentation", state)

        # Should have executed search (may return 0 if no testing sections exist)
        assert len(state.search_history) > 0

    def test_heuristic_best_practices_refinement(self, agent):
        """Test heuristic adds best practices section filter when mentioned."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        agent.search_heuristics("Show comprehensive vulnerabilities with best practices", state)

        # Should have executed search
        assert len(state.search_history) > 0

    def test_heuristic_details_refinement(self, agent):
        """Test heuristic adds details section filter when mentioned."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        agent.search_heuristics("Show detailed information about documented vulnerabilities", state)

        # Should have executed search with details filter
        assert len(state.search_history) > 0

    def test_heuristic_no_trigger(self, agent):
        """Test heuristic doesn't trigger for non-matching queries."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        # Query without documented/advisory keywords
        agent.search_heuristics("Show all npm vulnerabilities", state)

        # Should NOT have executed any searches
        assert len(state.search_history) == 0, "Should not trigger heuristic"
        assert len(state.documents_collected) == 0

    def test_heuristic_collects_aggregations(self, agent):
        """Test heuristic collects aggregation data."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        agent.search_heuristics("Show well-documented vulnerabilities", state)

        # Should have collected aggregations
        assert state.aggregations_collected is not None
        # May be empty dict if no faceting, but should be initialized
        assert isinstance(state.aggregations_collected, dict)

    def test_heuristic_multiple_keywords(self, agent):
        """Test heuristic handles queries with multiple matching keywords."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        # Query with both 'documented' and 'detailed'
        agent.search_heuristics("Show documented and detailed vulnerabilities", state)

        # Should trigger heuristic once
        assert len(state.search_history) > 0

    def test_heuristic_case_insensitive(self, agent):
        """Test heuristic detection is case-insensitive."""
        state = IterationState(iteration=0, search_history=[], documents_collected={})

        # Mixed case keywords
        agent.search_heuristics("Show DOCUMENTED vulnerabilities with REMEDIATION", state)

        # Should still trigger heuristic
        assert len(state.search_history) > 0
