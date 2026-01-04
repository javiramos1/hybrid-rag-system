#!/usr/bin/env python3
"""Test the ingestion pipeline."""

import sys
from pathlib import Path
import tempfile

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ingest import (
    _extract_metadata,
    load_csv_data,
    parse_advisories,
)


def test_extract_metadata():
    """Test advisory metadata extraction."""
    content = """# Advisory
**CVE ID:** CVE-2024-1234
**Package:** express-validator
**Ecosystem:** npm
**Severity:** High
**CVSS Score:** 7.5
"""
    metadata = _extract_metadata(content)
    assert metadata["cve_id"] == "CVE-2024-1234"
    assert metadata["package_name"] == "express-validator"
    assert metadata["ecosystem"] == "npm"
    assert metadata["severity"] == "High"
    assert metadata["cvss_score"] == 7.5
    print("✓ Metadata extraction works")


def test_load_csv_data():
    """Test CSV loading and denormalization."""
    # Create temporary CSV files
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # Create minimal CSV files
        (tmppath / "vulnerabilities.csv").write_text(
            "cve_id,package_id,vulnerability_type_id,severity_id,cvss_score,"
            "affected_versions,fixed_version,description,published_date\n"
            "CVE-2024-1234,1,1,1,7.5,<4.5.0,4.5.0,Test vulnerability,2024-01-15\n"
        )

        (tmppath / "packages.csv").write_text(
            "package_id,name,ecosystem\n1,express-validator,npm\n"
        )

        (tmppath / "vulnerability_types.csv").write_text(
            "type_id,type_name,description\n1,XSS,Test XSS\n"
        )

        (tmppath / "severity_levels.csv").write_text(
            "severity_id,severity_name,min_cvss,max_cvss\n1,High,7.0,8.9\n"
        )

        # Load CSV data without config
        data = load_csv_data(tmppath)

        assert len(data) == 1
        assert data[0, "cve_id"] == "CVE-2024-1234"
        assert data[0, "package_name"] == "express-validator"
        assert data[0, "severity"] == "High"
        print("✓ CSV loading and denormalization works")


def test_parse_advisories():
    """Test advisory parsing with section-based chunking."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        advisory_dir = tmppath / "advisories"
        advisory_dir.mkdir()

        # Create two test advisory files with sections
        advisory1 = """# Security Advisory: XSS Vulnerability

**CVE ID:** CVE-2024-5678
**Package:** jquery
**Ecosystem:** npm
**Severity:** High
**CVSS Score:** 8.2
**Published:** January 15, 2024

## Summary

This is a detailed advisory about XSS.

## Details

Cross-site scripting (XSS) is a security vulnerability.

## Code Examples

```javascript
// Vulnerable code
document.innerHTML = userInput;
```
"""
        advisory2 = """# Security Advisory: SQL Injection

**CVE ID:** CVE-2024-9012
**Package:** mysql-connector
**Ecosystem:** pip
**Severity:** Critical
**CVSS Score:** 9.1
**Published:** January 20, 2024

## Summary

This is a detailed advisory about SQL Injection.

## Attack Vector

SQL injection vulnerabilities can be exploited.
"""

        (advisory_dir / "advisory-001.md").write_text(advisory1)
        (advisory_dir / "advisory-002.md").write_text(advisory2)

        # Parse advisories (returns list of chunks)
        advisory_chunks = parse_advisories(tmppath)

        # Should have multiple chunks from the advisories
        assert len(advisory_chunks) > 0

        # Verify chunk structure
        cve_ids = {chunk["cve_id"] for chunk in advisory_chunks}
        assert "CVE-2024-5678" in cve_ids
        assert "CVE-2024-9012" in cve_ids

        # Verify content is preserved in chunks
        all_content = " ".join(chunk["content"] for chunk in advisory_chunks)
        assert "XSS" in all_content
        assert "SQL Injection" in all_content

        print("✓ Advisory parsing with section-based chunking works")


if __name__ == "__main__":
    test_extract_metadata()
    test_load_csv_data()
    test_parse_advisories()
    print("\n✅ All ingestion tests passed!")
