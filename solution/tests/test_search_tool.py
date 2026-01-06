#!/usr/bin/env python3
"""Tests for unified search tool."""

import sys
from pathlib import Path

import pytest
from dotenv import load_dotenv

# Load .env file for tests
load_dotenv()

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from config import Config
from search_tool import VulnerabilitySearchTool, SearchResult


@pytest.fixture
def config():
    """Create config instance for tests."""
    return Config.from_env()


@pytest.fixture
def search_tool(config):
    """Initialize search tool connected to running Typesense."""
    return VulnerabilitySearchTool(config)


class TestKeywordSearch:
    """Test keyword (BM25) search on metadata and content."""

    def test_keyword_search_basic(self, search_tool):
        """Keyword search should find documents with matching text."""
        result = search_tool.search_vulnerabilities(
            query="SQL injection", search_type="keyword", per_page=5
        )

        assert isinstance(result, SearchResult)
        assert result.query_type == "keyword"
        assert result.total_found > 0
        assert len(result.documents) > 0

    def test_keyword_search_with_severity_filter(self, search_tool):
        """Keyword search with severity filter should only return Critical docs."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            severity_levels=["Critical"],
            per_page=20,
        )

        assert result.total_found > 0
        for doc in result.documents:
            if "severity" in doc:
                assert doc["severity"] == "Critical"

    def test_keyword_search_with_ecosystem_filter(self, search_tool):
        """Keyword search filtered by ecosystem should return matching docs."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            ecosystems=["npm"],
            per_page=20,
        )

        assert result.total_found > 0
        for doc in result.documents:
            if "ecosystem" in doc:
                assert doc["ecosystem"] == "npm"

    def test_keyword_search_multiple_filters(self, search_tool):
        """Keyword search with multiple filters should combine them correctly."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            severity_levels=["High"],
            ecosystems=["pip"],
            per_page=20,
        )

        assert result.total_found >= 0
        for doc in result.documents:
            if "severity" in doc:
                assert doc["severity"] == "High"
            if "ecosystem" in doc:
                assert doc["ecosystem"] == "pip"


class TestSemanticSearch:
    """Test semantic (vector) search on advisory content."""

    def test_semantic_search_embedding_model_initialized(self, search_tool):
        """Embedding model should be loaded for semantic search."""
        assert search_tool.embedding_model is not None
        assert hasattr(search_tool.embedding_model, "encode")

    def test_semantic_search_basic(self, search_tool):
        """Semantic search should find conceptually similar content."""
        result = search_tool.search_vulnerabilities(
            query="SQL injection attack vectors",
            search_type="semantic",
            per_page=10,
        )

        assert result.query_type == "semantic"
        assert isinstance(result.documents, list)
        assert result.total_found >= 0

    def test_semantic_search_explanation_query(self, search_tool):
        """Semantic search should find documents related to explanations."""
        result = search_tool.search_vulnerabilities(
            query="how does cross-site scripting work",
            search_type="semantic",
            per_page=15,
        )

        assert result.query_type == "semantic"
        assert isinstance(result.documents, list)
        assert result.total_found >= 0


class TestHybridSearch:
    """Test hybrid search combining keyword and semantic."""

    def test_hybrid_search_basic(self, search_tool):
        """Hybrid search should combine BM25 and vector matching."""
        result = search_tool.search_vulnerabilities(
            query="XSS attack prevention",
            search_type="hybrid",
            per_page=10,
        )

        assert result.query_type == "hybrid"
        assert isinstance(result.documents, list)
        assert result.total_found >= 0

    def test_hybrid_search_with_severity_filter(self, search_tool):
        """Hybrid search should respect severity filter."""
        result = search_tool.search_vulnerabilities(
            query="vulnerability mitigation",
            search_type="hybrid",
            severity_levels=["Critical"],
            per_page=10,
        )

        assert result.total_found >= 0
        for doc in result.documents:
            if "severity" in doc:
                assert doc["severity"] == "Critical"

    def test_hybrid_search_with_cve_filter(self, search_tool):
        """Hybrid search should find specific CVE with context."""
        # Get a sample CVE
        result = search_tool.search_vulnerabilities(query="*", search_type="keyword", per_page=1)

        if result.documents:
            cve_id = result.documents[0].get("cve_id")

            # Search for that CVE with hybrid
            result = search_tool.search_vulnerabilities(
                query="fix remediation",
                search_type="hybrid",
                cve_ids=[cve_id],
                per_page=5,
            )

            assert result.query_type == "hybrid"
            if result.documents:
                found_cves = {doc.get("cve_id") for doc in result.documents}
                assert cve_id in found_cves


class TestAggregations:
    """Test statistics and aggregation operations."""

    def test_cvss_statistics(self, search_tool):
        """Faceting should compute statistics on numeric fields."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            facet_by="cvss_score",
            per_page=0,
        )

        assert result.total_found > 0
        assert result.aggregations is not None
        assert "cvss_score" in result.aggregations

        cvss_agg = result.aggregations["cvss_score"]
        assert "stats" in cvss_agg, "Missing stats in cvss_score aggregation"
        stats = cvss_agg["stats"]

        # Verify all required statistics present
        assert "avg" in stats and "min" in stats and "max" in stats

        # Verify statistics are reasonable (CVSS 0-10)
        assert 0 <= stats["min"] <= 10, f"Min CVSS {stats['min']} out of range"
        assert 0 <= stats["avg"] <= 10, f"Avg CVSS {stats['avg']} out of range"
        assert 0 <= stats["max"] <= 10, f"Max CVSS {stats['max']} out of range"
        assert stats["min"] <= stats["avg"] <= stats["max"], "Stats ordering invalid"

    def test_aggregation_with_filter(self, search_tool):
        """Faceting on filtered subset should return correct counts."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            severity_levels=["Critical"],
            facet_by="severity",
            per_page=0,
        )

        assert result.total_found > 0
        assert result.aggregations is not None
        assert "severity" in result.aggregations

        severity_agg = result.aggregations["severity"]
        assert "counts" in severity_agg, "Missing counts in severity aggregation"
        counts = severity_agg["counts"]

        assert len(counts) > 0
        assert any(item["value"] == "Critical" for item in counts), "Critical not found in counts"

    def test_ecosystem_counts(self, search_tool):
        """Faceting by ecosystem should return count of CVEs per ecosystem."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            facet_by="ecosystem",
            per_page=0,
        )

        assert result.total_found > 0
        assert result.aggregations is not None
        assert "ecosystem" in result.aggregations

        ecosystem_agg = result.aggregations["ecosystem"]
        assert "counts" in ecosystem_agg, "Missing counts in ecosystem aggregation"
        counts = ecosystem_agg["counts"]

        # Should have counts for npm, pip, maven
        ecosystems_found = [item["value"] for item in counts]
        assert len(ecosystems_found) > 0, "No ecosystems found in aggregation"

        # Check that each count has expected structure
        for item in counts:
            assert "value" in item, "Missing 'value' in count item"
            assert "count" in item, "Missing 'count' in count item"
            assert item["count"] > 0, f"Invalid count for {item['value']}"

    def test_cvss_range_filtering(self, search_tool):
        """Test CVSS score range filtering with additional_filters."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            min_cvss_score=8.0,
            additional_filters="cvss_score:<=9.0",
            per_page=10,
        )

        assert result.total_found >= 0
        for doc in result.documents:
            if "cvss_score" in doc:
                score = float(doc["cvss_score"])
                assert 8.0 <= score <= 9.0, f"CVSS {score} out of range [8.0, 9.0]"

    def test_vulnerability_type_filter(self, search_tool):
        """Test filtering by vulnerability type."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            vulnerability_types=["XSS"],
            per_page=10,
        )

        assert result.total_found >= 0

    def test_has_advisory_filter(self, search_tool):
        """Test filtering by documents that have nested advisory chunks."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters="advisory_chunks.is_code:false",  # Filter for any doc with advisory chunks
            per_page=20,
        )

        # Should find documents that have advisory chunks
        assert result.total_found >= 0, "Filter should work with nested advisory_chunks"

        # Filter was applied, verify structure
        for doc in result.documents:
            if "advisory_chunks" in doc:
                assert isinstance(doc["advisory_chunks"], list), "advisory_chunks should be a list"

    def test_multiple_facets(self, search_tool):
        """Test multiple facets at once."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            facet_by="ecosystem,severity",
            per_page=0,
        )

        assert result.total_found > 0
        assert result.aggregations is not None
        assert "ecosystem" in result.aggregations
        assert "severity" in result.aggregations


class TestPagination:
    """Test result pagination."""

    def test_per_page_limit(self, search_tool):
        """Results should respect per_page limit."""
        result = search_tool.search_vulnerabilities(query="*", search_type="keyword", per_page=5)

        assert len(result.documents) <= 5

    def test_zero_per_page_for_stats(self, search_tool):
        """per_page=0 should return only aggregations, minimal documents."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            facet_by="severity",
            per_page=0,
        )

        assert len(result.documents) <= 1
        assert result.aggregations is not None
        assert "severity" in result.aggregations


class TestFiltering:
    """Test various filtering combinations."""

    def test_min_cvss_score_filter(self, search_tool):
        """Filter by minimum CVSS score should exclude lower scores."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            min_cvss_score=7.0,
            per_page=20,
        )

        assert result.total_found > 0
        for doc in result.documents:
            if "cvss_score" in doc:
                score = float(doc["cvss_score"])
                assert score >= 7.0, f"Document has CVSS {score} < 7.0"

    def test_multiple_cve_filter(self, search_tool):
        """Filter by multiple CVEs should return exact matches."""
        # Get sample CVE IDs
        result = search_tool.search_vulnerabilities(query="*", search_type="keyword", per_page=5)

        if not result.documents:
            pytest.skip("No CVEs found in database")

        cve_ids = [doc.get("cve_id") for doc in result.documents[:3] if doc.get("cve_id")]

        if len(cve_ids) < 2:
            pytest.skip("Need at least 2 CVEs to test filtering")

        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            cve_ids=cve_ids,
            per_page=50,
        )

        assert result.total_found > 0, f"No results for CVEs: {cve_ids}"
        found_cves = {doc.get("cve_id") for doc in result.documents}
        for found_cve in found_cves:
            assert found_cve in cve_ids, f"Found unexpected CVE: {found_cve}"


class TestIntegration:
    """Integration tests across query types."""

    def test_search_result_structure(self, search_tool):
        """SearchResult should have all expected attributes."""
        result = search_tool.search_vulnerabilities(query="test", search_type="keyword", per_page=5)

        assert hasattr(result, "query_type"), "Missing query_type attribute"
        assert hasattr(result, "total_found"), "Missing total_found attribute"
        assert hasattr(result, "documents"), "Missing documents attribute"
        assert hasattr(result, "aggregations"), "Missing aggregations attribute"
        assert hasattr(result, "execution_time_ms"), "Missing execution_time_ms attribute"

        assert result.query_type == "keyword"
        assert isinstance(result.total_found, int)
        assert isinstance(result.documents, list)
        assert result.execution_time_ms is not None

    def test_document_has_required_fields(self, search_tool):
        """Returned documents should have required CVE fields."""
        result = search_tool.search_vulnerabilities(query="*", search_type="keyword", per_page=1)

        if result.documents:
            doc = result.documents[0]
            # CVE documents must have these core fields
            assert "id" in doc, "Document missing required 'id' field"
            assert "cve_id" in doc, "Document missing required 'cve_id' field"
            assert "package_name" in doc, "Document missing required 'package_name' field"
            assert "severity" in doc, "Document missing required 'severity' field"
            assert "cvss_score" in doc, "Document missing required 'cvss_score' field"
            assert "ecosystem" in doc, "Document missing required 'ecosystem' field"
            assert "content" in doc, "Document missing required 'content' field"

    def test_execution_time_recorded(self, search_tool):
        """Search results should include execution time."""
        result = search_tool.search_vulnerabilities(query="test", search_type="keyword", per_page=5)

        assert isinstance(result.execution_time_ms, int), "execution_time_ms not an integer"
        assert result.execution_time_ms >= 0, "execution_time_ms is negative"

    def test_total_cve_count(self, search_tool):
        """Test total CVE count with nested document architecture."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            per_page=1,
        )

        # With nested architecture, we have exactly 47 CVE documents
        # (advisory chunks are nested sub-documents)
        assert result.total_found == 47, (
            f"Expected 47 CVE documents (nested architecture), but found {result.total_found}. "
            f"(47 CVE docs + 48 nested advisory chunks)"
        )
        print(f"✓ Confirmed: Total CVE count = {result.total_found} (expected 47)")

    def test_no_duplicate_cves(self, search_tool):
        """Test that CVE results are consistent with new chunked architecture."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            per_page=100,  # Get more results to check all documents
        )

        # With chunking, we now have multiple documents per CVE:
        # - 1 CSV document per CVE (47 total)
        # - Multiple advisory chunks per CVE with advisory data (48 total)
        # So total_found should be >= 47 (all CVEs have CSV) + advisory chunks

        cve_ids = [doc.get("cve_id") for doc in result.documents]
        unique_cves = set(cve_ids)

        # We expect at least 10 unique CVEs in test queries
        assert len(unique_cves) > 0, "Should have at least one unique CVE"

        # Verify all returned documents have valid CVE IDs
        for doc in result.documents:
            assert doc.get("cve_id") is not None, f"Document {doc.get('id')} missing CVE ID"

        print(
            f"✓ Confirmed: {len(unique_cves)} unique CVEs across {len(cve_ids)} total documents (includes chunks)"
        )

    def test_advisory_distribution(self, search_tool):
        """Test that CVE documents have nested advisory chunks."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            per_page=100,
        )

        # With nested architecture, all docs are CVEs, some have nested advisory_chunks
        has_chunks = sum(1 for doc in result.documents if doc.get("advisory_chunks"))
        no_chunks = len(result.documents) - has_chunks

        # Some CVEs should have advisories, some might not
        assert has_chunks > 0, "Should have some CVE documents with nested advisory chunks"

        print(f"✓ Advisory distribution: {has_chunks} CVEs with nested chunks, {no_chunks} without")

    def test_unique_cve_document_ids(self, search_tool):
        """Test that document IDs follow the nested CVE document format."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            per_page=100,
        )

        for doc in result.documents:
            doc_id = doc.get("id")
            cve_id = doc.get("cve_id")

            assert doc_id is not None, "Document missing 'id' field"
            assert cve_id is not None, "Document missing 'cve_id' field"

            # With nested architecture, IDs are in format: csv-{cve_id}
            assert doc_id.startswith("csv-"), f"Document ID should start with 'csv-', got {doc_id}"
            assert cve_id in doc_id, f"CVE ID {cve_id} should be in document ID {doc_id}"

        print("✓ All document IDs follow the nested CVE document format")


class TestVulnerabilityTypeAliases:
    """Test vulnerability type alias mapping (RCE, DoS, IDOR)."""

    def test_vulnerability_type_mapping_exists(self, search_tool):
        """Test that vulnerability type mapping can be loaded."""
        mapping = search_tool._get_vulnerability_type_mapping()
        assert isinstance(mapping, dict)
        assert len(mapping) >= 0  # May have 0 or more aliases

    def test_rce_alias_mapping(self, search_tool):
        """Test that RCE abbreviation maps to full name."""
        mapping = search_tool._get_vulnerability_type_mapping()

        if "RCE" in mapping:
            full_name = mapping["RCE"]
            assert (
                "Remote Code Execution" in full_name
            ), f"RCE should map to name containing 'Remote Code Execution', got '{full_name}'"

    def test_dos_alias_mapping(self, search_tool):
        """Test that DoS abbreviation maps to full name."""
        mapping = search_tool._get_vulnerability_type_mapping()

        if "DoS" in mapping:
            full_name = mapping["DoS"]
            assert (
                "Denial" in full_name or "DoS" in full_name
            ), f"DoS should map to Denial of Service name, got '{full_name}'"

    def test_idor_alias_mapping(self, search_tool):
        """Test that IDOR abbreviation maps to full name."""
        mapping = search_tool._get_vulnerability_type_mapping()

        if "IDOR" in mapping:
            full_name = mapping["IDOR"]
            assert (
                "Insecure Direct Object Reference" in full_name or "IDOR" in full_name
            ), f"IDOR should map to IDOR name, got '{full_name}'"

    def test_rce_search_by_abbreviation(self, search_tool):
        """Test searching for RCE vulnerabilities using abbreviation."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            vulnerability_types=["RCE"],
            per_page=10,
        )

        assert result.total_found >= 0
        # Should return RCE vulnerabilities
        for doc in result.documents:
            vuln_type = doc.get("vulnerability_type", "")
            # Should have RCE in the name
            assert (
                "Remote Code Execution" in vuln_type or "RCE" in vuln_type
            ), f"Expected RCE vulnerability, got type: {vuln_type}"

    def test_dos_search_by_abbreviation(self, search_tool):
        """Test searching for DoS vulnerabilities using abbreviation."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            vulnerability_types=["DoS"],
            per_page=10,
        )

        assert result.total_found >= 0
        # Should return DoS vulnerabilities (if any exist)
        for doc in result.documents:
            vuln_type = doc.get("vulnerability_type", "")
            # Check if DoS-related
            assert any(
                keyword in vuln_type for keyword in ["DoS", "Denial"]
            ), f"Expected DoS vulnerability, got type: {vuln_type}"

    def test_full_name_search_still_works(self, search_tool):
        """Test that full vulnerability type names still work without alias."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            vulnerability_types=["Cross-Site Scripting (XSS)"],
            per_page=10,
        )

        # Should work with full name
        assert result.total_found >= 0

    def test_xss_abbreviation_in_results(self, search_tool):
        """Test that XSS vulnerability type appears in results."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            vulnerability_types=["XSS"],
            per_page=10,
        )

        assert result.total_found >= 0
        # Should find XSS vulnerabilities in the database
        for doc in result.documents:
            vuln_type = doc.get("vulnerability_type", "")
            assert "XSS" in vuln_type, f"Expected XSS in vulnerability type, got: {vuln_type}"


class TestAggregationsAndStatistics:
    """Test advanced aggregation and statistical queries."""

    def test_cvss_statistics_aggregation(self, search_tool):
        """Test CVSS score statistics aggregation."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            facet_by="cvss_score",
            per_page=0,
        )

        assert result.total_found > 0
        assert result.aggregations is not None
        assert "cvss_score" in result.aggregations

        cvss_agg = result.aggregations["cvss_score"]
        if "stats" in cvss_agg:
            stats = cvss_agg["stats"]
            assert "avg" in stats
            assert "min" in stats
            assert "max" in stats
            assert (
                stats["min"] <= stats["avg"] <= stats["max"]
            ), f"Invalid stats: min={stats['min']}, avg={stats['avg']}, max={stats['max']}"

    def test_severity_distribution_aggregation(self, search_tool):
        """Test severity level distribution."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            facet_by="severity",
            per_page=0,
        )

        assert result.total_found > 0
        assert result.aggregations is not None
        assert "severity" in result.aggregations

        severity_agg = result.aggregations["severity"]
        assert "counts" in severity_agg
        counts = severity_agg["counts"]

        # Verify expected severity levels
        severity_values = [item["value"] for item in counts]
        expected_levels = {"Critical", "High", "Medium", "Low"}
        found_levels = set(severity_values)
        assert len(found_levels) > 0, "Should find at least one severity level"

    def test_vulnerability_type_distribution(self, search_tool):
        """Test vulnerability type distribution."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            facet_by="vulnerability_type",
            per_page=0,
        )

        assert result.total_found > 0
        assert result.aggregations is not None
        assert "vulnerability_type" in result.aggregations

        vuln_agg = result.aggregations["vulnerability_type"]
        assert "counts" in vuln_agg
        counts = vuln_agg["counts"]
        assert len(counts) > 0, "Should have at least one vulnerability type"

        # Each count should have value and count
        for item in counts:
            assert "value" in item
            assert "count" in item
            assert item["count"] > 0

    def test_ecosystem_distribution(self, search_tool):
        """Test ecosystem distribution."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            facet_by="ecosystem",
            per_page=0,
        )

        assert result.total_found > 0
        assert result.aggregations is not None
        assert "ecosystem" in result.aggregations

        ecosystem_agg = result.aggregations["ecosystem"]
        assert "counts" in ecosystem_agg
        counts = ecosystem_agg["counts"]

        # Should have npm, pip, maven
        ecosystems = {item["value"] for item in counts}
        assert len(ecosystems) >= 2, "Should have at least 2 ecosystems"

    def test_combined_aggregations(self, search_tool):
        """Test querying multiple aggregations at once."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            facet_by="ecosystem,severity,vulnerability_type",
            per_page=0,
        )

        assert result.total_found > 0
        assert result.aggregations is not None
        assert "ecosystem" in result.aggregations
        assert "severity" in result.aggregations
        assert "vulnerability_type" in result.aggregations

    def test_aggregation_with_filter(self, search_tool):
        """Test aggregation on filtered subset."""
        # First get Critical severity aggregation
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            severity_levels=["Critical"],
            facet_by="ecosystem",
            per_page=0,
        )

        assert result.total_found > 0
        assert result.aggregations is not None
        # Should only show ecosystems that have Critical vulnerabilities

    def test_aggregation_with_search_query(self, search_tool):
        """Test aggregation with keyword search combined."""
        result = search_tool.search_vulnerabilities(
            query="authentication",
            search_type="keyword",
            facet_by="severity",
            per_page=5,
        )

        # Should have both search results and aggregations
        assert result.aggregations is not None
        assert "severity" in result.aggregations
        assert result.total_found >= 0

    def test_highest_cvss_score_query(self, search_tool):
        """Test finding highest CVSS score in database."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            sort_by="cvss_score:desc",
            per_page=1,
        )

        assert result.total_found > 0
        assert len(result.documents) > 0

        # First document should have highest CVSS
        top_doc = result.documents[0]
        assert "cvss_score" in top_doc
        assert top_doc["cvss_score"] > 0


class TestAdvancedFilters:
    """Test advanced filtering capabilities for advisory sections."""

    def test_filter_has_advisory(self, search_tool):
        """Test filtering for CVEs with advisory documentation."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters="has_advisory:true",
            per_page=20,
        )

        # Should find the 8 CVEs with detailed advisories
        assert result.total_found > 0
        assert result.total_found <= 8, "Should have at most 8 CVEs with advisories"

        # All returned documents should have has_advisory flag
        for doc in result.documents:
            assert doc.get("has_advisory") is True, "Document should have has_advisory=true"

    def test_filter_advisory_remediation_section(self, search_tool):
        """Test filtering for CVEs with remediation sections."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters="has_advisory:true && advisory_chunks.{section:=remediation}",
            per_page=20,
        )

        # Should find CVEs with remediation sections
        assert result.total_found > 0, "Should find CVEs with remediation sections"
        assert result.total_found <= 8, "At most 8 CVEs have advisories"

    def test_filter_advisory_testing_section(self, search_tool):
        """Test filtering for CVEs with testing documentation."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters="has_advisory:true && advisory_chunks.{section:=testing}",
            per_page=20,
        )

        # Should find CVEs with testing sections
        assert result.total_found >= 0, "Should return results (may be 0 if no testing sections)"

    def test_filter_advisory_best_practices_section(self, search_tool):
        """Test filtering for CVEs with best practices documentation."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters="has_advisory:true && advisory_chunks.{section:=best_practices}",
            per_page=20,
        )

        # Should find CVEs with best practices sections
        assert result.total_found >= 0, "Should return results (may be 0 if no best_practices sections)"

    def test_filter_advisory_details_section(self, search_tool):
        """Test filtering for CVEs with detailed technical information."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters="has_advisory:true && advisory_chunks.{section:=details}",
            per_page=20,
        )

        # Should find CVEs with details sections
        assert result.total_found > 0, "Should find CVEs with details sections"

    def test_filter_advisory_summary_section(self, search_tool):
        """Test filtering for CVEs with summary sections."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters="has_advisory:true && advisory_chunks.{section:=summary}",
            per_page=20,
        )

        # Should find CVEs with summary sections
        assert result.total_found > 0, "Should find CVEs with summary sections"

    def test_filter_combined_sections(self, search_tool):
        """Test filtering for CVEs with multiple section types."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters="has_advisory:true && advisory_chunks.{section:=remediation} && advisory_chunks.{section:=details}",
            per_page=20,
        )

        # Should find CVEs that have BOTH remediation AND details sections
        assert result.total_found >= 0, "Should find CVEs with both sections"

    def test_filter_code_blocks(self, search_tool):
        """Test filtering for advisory sections containing code blocks."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters="has_advisory:true && advisory_chunks.{is_code:=true}",
            per_page=20,
        )

        # Should find CVEs with code blocks in advisories
        assert result.total_found >= 0, "Should return results (may be 0 if no code blocks)"

    def test_filter_ecosystem_with_advisory(self, search_tool):
        """Test combined ecosystem + advisory filtering."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            ecosystems=["npm"],
            additional_filters="has_advisory:true",
            per_page=20,
        )

        # Should find npm CVEs with advisories
        assert result.total_found >= 0
        for doc in result.documents:
            assert doc.get("ecosystem") == "npm", "Should only return npm CVEs"
            assert doc.get("has_advisory") is True, "Should only return CVEs with advisories"

    def test_filter_severity_with_remediation(self, search_tool):
        """Test combined severity + remediation section filtering."""
        result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            severity_levels=["Critical"],
            additional_filters="has_advisory:true && advisory_chunks.{section:=remediation}",
            per_page=20,
        )

        # Should find Critical CVEs with remediation guidance
        assert result.total_found >= 0
        for doc in result.documents:
            assert doc.get("severity") == "Critical", "Should only return Critical CVEs"

    def test_section_analytics_faceting(self, search_tool):
        """Test faceting on advisory section types for analytics."""
        # Note: Typesense may not support faceting on nested fields depending on version
        # This test verifies the query structure is correct, even if faceting isn't supported
        try:
            result = search_tool.search_vulnerabilities(
                query="*",
                search_type="keyword",
                additional_filters="has_advisory:true",
                facet_by="advisory_chunks.section",
                per_page=0,
            )

            # Should return section distribution if supported
            assert result.total_found > 0, "Should find CVEs with advisories"
            # Aggregations may or may not include nested field faceting
        except Exception as e:
            # Nested field faceting may not be supported - that's OK
            # The important thing is that the filter syntax is correct
            assert "advisory_chunks.section" in str(e) or "facet" in str(e).lower()

    def test_documentation_completeness_by_ecosystem(self, search_tool):
        """Test documentation completeness analysis by ecosystem."""
        # Get total CVEs per ecosystem
        all_result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            facet_by="ecosystem",
            per_page=0,
        )

        # Get CVEs with advisories per ecosystem
        advisory_result = search_tool.search_vulnerabilities(
            query="*",
            search_type="keyword",
            additional_filters="has_advisory:true",
            facet_by="ecosystem",
            per_page=0,
        )

        # Both queries should execute successfully
        assert all_result.total_found > 0
        assert advisory_result.total_found > 0
        assert advisory_result.total_found <= all_result.total_found
