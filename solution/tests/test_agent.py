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

from agent import VulnerabilityAgent
from search_tool import SearchResult
from prompts import get_search_tool_declaration, get_system_instruction


@pytest.fixture
def agent():
    """Create agent instance for tests."""
    return VulnerabilityAgent()


# Skip all tests if API key not set
pytestmark = pytest.mark.skipif(
    not os.getenv("GOOGLE_API_KEY"),
    reason="GOOGLE_API_KEY not set",
)


class TestVulnerabilityAgent:
    """Test agent functionality."""

    def test_agent_initialization(self):
        """Test agent can be initialized with API key."""
        agent = VulnerabilityAgent()
        assert agent.model is not None
        assert agent.search_tool is not None

    def test_agent_missing_api_key(self, monkeypatch):
        """Test agent raises error without API key."""
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="GOOGLE_API_KEY"):
            VulnerabilityAgent()

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

    def test_agent_initialization_with_max_iterations(self):
        """Test agent can be initialized with custom max_iterations."""
        agent = VulnerabilityAgent(max_iterations=3)
        assert agent.max_iterations == 3

    def test_default_max_iterations(self):
        """Test agent defaults to 5 max iterations."""
        agent = VulnerabilityAgent()
        assert agent.max_iterations == 5

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

    def test_extract_text_response(self, agent):
        """Test extracting text response from LLM."""
        from unittest.mock import Mock

        response = Mock()
        response.text = "This is the answer"
        response.candidates = None  # Ensure no candidates list

        result = agent._extract_text_response(response)
        assert result == "This is the answer"

    def test_extract_text_response_concatenation(self, agent):
        """Test text extraction with direct .text property."""
        from unittest.mock import Mock

        response = Mock()
        response.text = "Part 1 Part 2"
        response.candidates = None  # Ensure no candidates list

        result = agent._extract_text_response(response)
        assert result == "Part 1 Part 2"

    def test_build_answer_context_empty_documents(self, agent):
        """Test answer context building with no documents."""
        from agent import IterationState

        state = IterationState(
            iteration=2,
            search_history=[
                ("keyword", "rust", 0),
                ("keyword", "*", 0),
            ],
            documents_collected={},
        )

        context = agent._build_answer_context("Show rust vulnerabilities", state)

        assert "rust vulnerabilities" in context
        assert "Search History (2 searches)" in context
        assert "Collected Documents (0)" in context
        assert "No documents found" in context

    def test_build_answer_context_with_documents(self, agent):
        """Test answer context building with collected documents."""
        from agent import IterationState

        state = IterationState(
            iteration=1,
            search_history=[("keyword", "npm Critical", 5)],
            documents_collected={
                "CVE-2024-1": {
                    "cve_id": "CVE-2024-1",
                    "package_name": "express",
                    "ecosystem": "npm",
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "description": "Test vulnerability",
                }
            },
        )

        context = agent._build_answer_context("Show npm Critical vulnerabilities", state)

        assert "CVE-2024-1" in context
        assert "express" in context
        assert "Critical" in context
        assert "9.8" in context
        assert "Collected Documents (1)" in context

    def test_iteration_state_initialization(self):
        """Test IterationState dataclass."""
        from agent import IterationState

        state = IterationState(iteration=1, search_history=[], documents_collected={})

        assert state.iteration == 1
        assert state.search_history == []
        assert state.documents_collected == {}
        assert state.final_answer is None

    def test_iteration_state_mutation(self):
        """Test IterationState can be mutated during loop."""
        from agent import IterationState

        state = IterationState(iteration=0, search_history=[], documents_collected={})

        # Simulate iteration
        state.iteration += 1
        state.search_history.append(("keyword", "test", 5))
        state.documents_collected["CVE-2024-1"] = {"cve_id": "CVE-2024-1"}

        assert state.iteration == 1
        assert len(state.search_history) == 1
        assert len(state.documents_collected) == 1
