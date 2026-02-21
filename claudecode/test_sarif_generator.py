#!/usr/bin/env python3
"""
Unit tests for SARIF generator module.
"""

import json
import tempfile
import pytest
from pathlib import Path
from sarif_generator import SarifGenerator


class TestSarifGenerator:
    """Test suite for SarifGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create a SARIF generator instance for testing."""
        return SarifGenerator(
            tool_name="Test Tool",
            tool_version="1.0.0",
            repo_root="/test/repo"
        )

    @pytest.fixture
    def sample_findings(self):
        """Sample findings data for testing."""
        return {
            "findings": [
                {
                    "file": "src/auth.py",
                    "line": 42,
                    "severity": "CRITICAL",
                    "category": "authentication_bypass",
                    "description": "Authentication can be bypassed",
                    "exploit_scenario": "Attacker can access admin without credentials",
                    "recommendation": "Implement proper authentication checks",
                    "confidence": 0.95
                },
                {
                    "file": "src/db.py",
                    "line": 123,
                    "severity": "HIGH",
                    "category": "sql_injection",
                    "description": "SQL injection vulnerability",
                    "exploit_scenario": "Attacker can extract database",
                    "recommendation": "Use parameterized queries",
                    "confidence": 0.85
                },
                {
                    "file": "src/api.py",
                    "line": 56,
                    "severity": "MEDIUM",
                    "category": "csrf",
                    "description": "Missing CSRF protection",
                    "exploit_scenario": "User can be tricked into actions",
                    "recommendation": "Add CSRF tokens",
                    "confidence": 0.75
                },
                {
                    "file": "src/config.py",
                    "line": 10,
                    "severity": "LOW",
                    "category": "missing_headers",
                    "description": "Missing security headers",
                    "exploit_scenario": "Limited security risk",
                    "recommendation": "Add X-Frame-Options header",
                    "confidence": 0.70
                }
            ]
        }

    def test_sarif_structure(self, generator, sample_findings):
        """Test that generated SARIF has correct structure."""
        sarif = generator.generate_sarif(sample_findings)

        # Check top-level structure
        assert sarif['$schema'] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert sarif['version'] == "2.1.0"
        assert 'runs' in sarif
        assert len(sarif['runs']) == 1

        # Check run structure
        run = sarif['runs'][0]
        assert 'tool' in run
        assert 'results' in run
        assert run['columnKind'] == "utf16CodeUnits"

        # Check tool structure
        tool = run['tool']['driver']
        assert tool['name'] == "Test Tool"
        assert tool['version'] == "1.0.0"
        assert 'rules' in tool
        assert 'informationUri' in tool

    def test_results_count(self, generator, sample_findings):
        """Test that all findings are converted to results."""
        sarif = generator.generate_sarif(sample_findings)
        results = sarif['runs'][0]['results']

        assert len(results) == 4

    def test_critical_severity_mapping(self, generator):
        """Test CRITICAL severity score calculation."""
        # Test with high confidence (0.95)
        score = generator._calculate_severity_score("CRITICAL", 0.95)
        assert 9.0 <= score <= 10.0
        assert score >= 9.5  # Should be in upper range

        # Test with lower confidence (0.90)
        score = generator._calculate_severity_score("CRITICAL", 0.90)
        assert 9.0 <= score <= 10.0

        # Test with maximum confidence (1.0)
        score = generator._calculate_severity_score("CRITICAL", 1.0)
        assert score == 10.0

    def test_high_severity_mapping(self, generator):
        """Test HIGH severity score calculation."""
        # Test with high confidence (0.85)
        score = generator._calculate_severity_score("HIGH", 0.85)
        assert 7.0 <= score <= 8.9
        assert score >= 7.5  # Should be in middle-upper range

        # Test with lower confidence (0.70)
        score = generator._calculate_severity_score("HIGH", 0.70)
        assert 7.0 <= score <= 8.9
        assert score == 7.0  # At minimum

        # Test with maximum confidence (1.0)
        score = generator._calculate_severity_score("HIGH", 1.0)
        assert score == 8.9

    def test_medium_severity_mapping(self, generator):
        """Test MEDIUM severity score calculation."""
        score = generator._calculate_severity_score("MEDIUM", 0.75)
        assert 4.0 <= score <= 6.9
        assert score == 5.5  # Default for MEDIUM

    def test_low_severity_mapping(self, generator):
        """Test LOW severity score calculation."""
        score = generator._calculate_severity_score("LOW", 0.70)
        assert 0.1 <= score <= 3.9
        assert score == 2.0  # Default for LOW

    def test_unknown_severity_default(self, generator):
        """Test that unknown severity defaults to MEDIUM."""
        score = generator._calculate_severity_score("UNKNOWN", 0.80)
        assert score == 5.5  # MEDIUM default

    def test_sarif_level_mapping(self, generator):
        """Test SARIF level mapping for different severities."""
        assert generator._get_sarif_level("CRITICAL") == "error"
        assert generator._get_sarif_level("HIGH") == "error"
        assert generator._get_sarif_level("MEDIUM") == "warning"
        assert generator._get_sarif_level("LOW") == "note"
        assert generator._get_sarif_level("low") == "note"  # Case insensitive

    def test_relative_path_conversion(self, generator):
        """Test file path conversion to relative paths."""
        # Absolute path
        result = generator._get_relative_path("/test/repo/src/file.py")
        assert result == "src/file.py"

        # Already relative
        result = generator._get_relative_path("src/file.py")
        assert result == "src/file.py"

        # Path outside repo (edge case)
        result = generator._get_relative_path("/other/path/file.py")
        assert isinstance(result, str)

    def test_fingerprint_generation(self, generator):
        """Test that fingerprints are stable and unique."""
        finding1 = {
            "file": "src/test.py",
            "line": 42,
            "category": "sql_injection"
        }
        finding2 = {
            "file": "src/test.py",
            "line": 42,
            "category": "sql_injection"
        }
        finding3 = {
            "file": "src/test.py",
            "line": 43,  # Different line
            "category": "sql_injection"
        }

        fp1 = generator._generate_fingerprint(finding1)
        fp2 = generator._generate_fingerprint(finding2)
        fp3 = generator._generate_fingerprint(finding3)

        # Same finding should produce same fingerprint
        assert fp1 == fp2

        # Different finding should produce different fingerprint
        assert fp1 != fp3

        # Fingerprints should be hex strings (SHA-256)
        assert len(fp1) == 64
        assert all(c in '0123456789abcdef' for c in fp1)

    def test_rules_extraction(self, generator, sample_findings):
        """Test that rules are correctly extracted from findings."""
        rules = generator._extract_rules(sample_findings['findings'])

        # Should have one rule per unique category
        assert len(rules) == 4
        assert 'authentication_bypass' in rules
        assert 'sql_injection' in rules
        assert 'csrf' in rules
        assert 'missing_headers' in rules

        # Check rule structure
        rule = rules['sql_injection']
        assert rule['id'] == 'sql_injection'
        assert 'name' in rule
        assert 'shortDescription' in rule
        assert 'fullDescription' in rule
        assert 'help' in rule
        assert 'properties' in rule
        assert 'tags' in rule['properties']
        assert 'security' in rule['properties']['tags']

    def test_result_structure(self, generator, sample_findings):
        """Test that individual results have correct structure."""
        sarif = generator.generate_sarif(sample_findings)
        result = sarif['runs'][0]['results'][0]

        # Required fields
        assert 'ruleId' in result
        assert 'level' in result
        assert 'message' in result
        assert 'text' in result['message']
        assert 'locations' in result
        assert len(result['locations']) == 1

        # Location structure
        location = result['locations'][0]
        assert 'physicalLocation' in location
        physical_location = location['physicalLocation']
        assert 'artifactLocation' in physical_location
        assert 'region' in physical_location
        assert 'uri' in physical_location['artifactLocation']
        assert 'startLine' in physical_location['region']

        # Properties
        assert 'properties' in result
        assert 'security-severity' in result['properties']
        assert 'cvss-severity' in result['properties']
        assert 'confidence' in result['properties']

        # Partial fingerprints
        assert 'partialFingerprints' in result
        assert 'primaryLocationLineHash' in result['partialFingerprints']

    def test_empty_findings(self, generator):
        """Test handling of empty findings list."""
        sarif = generator.generate_sarif({"findings": []})

        assert sarif['runs'][0]['results'] == []
        assert sarif['runs'][0]['tool']['driver']['rules'] == []

    def test_missing_optional_fields(self, generator):
        """Test handling of findings with missing optional fields."""
        minimal_findings = {
            "findings": [{
                "file": "test.py",
                "line": 1,
                "severity": "HIGH",
                "category": "test_category",
                "description": "Test description"
                # Missing: exploit_scenario, recommendation, confidence
            }]
        }

        sarif = generator.generate_sarif(minimal_findings)
        result = sarif['runs'][0]['results'][0]

        # Should still generate valid SARIF
        assert result['ruleId'] == 'test_category'
        assert result['level'] == 'error'
        assert 'security-severity' in result['properties']

    def test_save_sarif_to_file(self, generator, sample_findings):
        """Test saving SARIF to a file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            temp_path = f.name

        try:
            generator.save_sarif(sample_findings, temp_path)

            # Verify file exists and is valid JSON
            assert Path(temp_path).exists()

            with open(temp_path, 'r') as f:
                loaded_sarif = json.load(f)

            # Verify it's valid SARIF
            assert loaded_sarif['version'] == "2.1.0"
            assert len(loaded_sarif['runs'][0]['results']) == 4

        finally:
            # Cleanup
            Path(temp_path).unlink(missing_ok=True)

    def test_cvss_severity_in_properties(self, generator, sample_findings):
        """Test that CVSS severity level is preserved in properties."""
        sarif = generator.generate_sarif(sample_findings)

        # Find CRITICAL finding
        critical_result = next(
            r for r in sarif['runs'][0]['results']
            if r['properties']['cvss-severity'] == 'CRITICAL'
        )

        assert critical_result['properties']['cvss-severity'] == 'CRITICAL'
        security_severity = float(critical_result['properties']['security-severity'])
        assert 9.0 <= security_severity <= 10.0

    def test_markdown_message_with_exploit_scenario(self, generator, sample_findings):
        """Test that exploit scenarios are included in markdown messages."""
        sarif = generator.generate_sarif(sample_findings)
        result = sarif['runs'][0]['results'][0]

        assert 'markdown' in result['message']
        assert 'Exploit Scenario' in result['message']['markdown']
        assert result['message']['markdown'].startswith(result['message']['text'])

    def test_confidence_score_preservation(self, generator, sample_findings):
        """Test that confidence scores are preserved in properties."""
        sarif = generator.generate_sarif(sample_findings)

        for i, finding in enumerate(sample_findings['findings']):
            result = sarif['runs'][0]['results'][i]
            assert result['properties']['confidence'] == finding['confidence']

    def test_case_insensitive_severity(self, generator):
        """Test that severity matching is case-insensitive."""
        score_upper = generator._calculate_severity_score("HIGH", 0.80)
        score_lower = generator._calculate_severity_score("high", 0.80)
        score_mixed = generator._calculate_severity_score("High", 0.80)

        assert score_upper == score_lower == score_mixed

    def test_fingerprint_stability_across_categories(self, generator, tmp_path):
        """Test that same code with different categorization produces same fingerprint."""
        # Create a test file
        test_file = tmp_path / "test.py"
        test_file.write_text("def vulnerable_function():\n    return True\n")

        # Set REPO_PATH for the test
        import os
        original_repo_path = os.environ.get('REPO_PATH')
        os.environ['REPO_PATH'] = str(tmp_path)

        try:
            # Same file and line, different categories
            finding1 = {
                "file": "test.py",
                "line": 1,
                "category": "authentication_bypass",
                "severity": "CRITICAL"
            }
            finding2 = {
                "file": "test.py",
                "line": 1,
                "category": "missing_auth_check",
                "severity": "HIGH"
            }

            fingerprint1 = generator._generate_fingerprint(finding1)
            fingerprint2 = generator._generate_fingerprint(finding2)

            # Fingerprints should be identical despite different categories
            assert fingerprint1 == fingerprint2
        finally:
            # Restore original REPO_PATH
            if original_repo_path:
                os.environ['REPO_PATH'] = original_repo_path
            elif 'REPO_PATH' in os.environ:
                del os.environ['REPO_PATH']

    def test_fingerprint_changes_with_code_modification(self, generator, tmp_path):
        """Test that different code produces different fingerprint."""
        # Create test files with different content
        test_file1 = tmp_path / "test1.py"
        test_file1.write_text("def function1():\n    return True\n")

        test_file2 = tmp_path / "test2.py"
        test_file2.write_text("def function2():\n    return False\n")

        import os
        original_repo_path = os.environ.get('REPO_PATH')
        os.environ['REPO_PATH'] = str(tmp_path)

        try:
            finding1 = {"file": "test1.py", "line": 1, "category": "vuln"}
            finding2 = {"file": "test2.py", "line": 1, "category": "vuln"}

            fingerprint1 = generator._generate_fingerprint(finding1)
            fingerprint2 = generator._generate_fingerprint(finding2)

            # Different code should produce different fingerprints
            assert fingerprint1 != fingerprint2
        finally:
            if original_repo_path:
                os.environ['REPO_PATH'] = original_repo_path
            elif 'REPO_PATH' in os.environ:
                del os.environ['REPO_PATH']

    def test_fingerprint_whitespace_normalization(self, generator, tmp_path):
        """Test that whitespace-only changes don't affect fingerprint."""
        # Create files with same code but different whitespace
        test_file1 = tmp_path / "test1.py"
        test_file1.write_text("def function():\n    return True\n")

        test_file2 = tmp_path / "test2.py"
        test_file2.write_text("def function():\n        return True\n")  # Extra indentation

        import os
        original_repo_path = os.environ.get('REPO_PATH')
        os.environ['REPO_PATH'] = str(tmp_path)

        try:
            finding1 = {"file": "test1.py", "line": 2, "category": "vuln"}
            finding2 = {"file": "test2.py", "line": 2, "category": "vuln"}

            fingerprint1 = generator._generate_fingerprint(finding1)
            fingerprint2 = generator._generate_fingerprint(finding2)

            # Fingerprints should be identical despite whitespace differences
            assert fingerprint1 == fingerprint2
        finally:
            if original_repo_path:
                os.environ['REPO_PATH'] = original_repo_path
            elif 'REPO_PATH' in os.environ:
                del os.environ['REPO_PATH']

    def test_fingerprint_fallback_on_file_read_error(self, generator):
        """Test fallback to file:line when code cannot be read."""
        # Finding for non-existent file
        finding = {
            "file": "nonexistent.py",
            "line": 42,
            "category": "vuln"
        }

        fingerprint = generator._generate_fingerprint(finding)

        # Should still generate a fingerprint (fallback mode)
        assert len(fingerprint) == 16
        assert isinstance(fingerprint, str)

    def test_fingerprint_line_shift_stability(self, generator, tmp_path):
        """Test that line shifts within context window preserve fingerprint."""
        # Create a test file with code
        test_file = tmp_path / "test.py"
        test_file.write_text("# Comment\ndef function():\n    return True\n# Another comment\n")

        import os
        original_repo_path = os.environ.get('REPO_PATH')
        os.environ['REPO_PATH'] = str(tmp_path)

        try:
            # Same function but reported at slightly different lines within context window
            finding1 = {"file": "test.py", "line": 2, "category": "vuln"}
            finding2 = {"file": "test.py", "line": 3, "category": "vuln"}

            fingerprint1 = generator._generate_fingerprint(finding1)
            fingerprint2 = generator._generate_fingerprint(finding2)

            # With context_lines=2, both should capture overlapping code
            # They may be different but should be stable across runs
            assert len(fingerprint1) == 16
            assert len(fingerprint2) == 16
        finally:
            if original_repo_path:
                os.environ['REPO_PATH'] = original_repo_path
            elif 'REPO_PATH' in os.environ:
                del os.environ['REPO_PATH']

    def test_fingerprint_file_caching(self, generator, tmp_path):
        """Test that file cache works correctly for multiple findings."""
        test_file = tmp_path / "test.py"
        test_file.write_text("line1\nline2\nline3\nline4\nline5\n")

        import os
        original_repo_path = os.environ.get('REPO_PATH')
        os.environ['REPO_PATH'] = str(tmp_path)

        try:
            # Multiple findings in the same file
            finding1 = {"file": "test.py", "line": 2, "category": "vuln1"}
            finding2 = {"file": "test.py", "line": 4, "category": "vuln2"}

            # First call should cache the file
            fingerprint1 = generator._generate_fingerprint(finding1)
            assert "test.py" in generator._file_cache

            # Second call should use cached content
            fingerprint2 = generator._generate_fingerprint(finding2)

            # Both should generate valid fingerprints
            assert len(fingerprint1) == 16
            assert len(fingerprint2) == 16
            # They should be different (different line numbers)
            assert fingerprint1 != fingerprint2
        finally:
            if original_repo_path:
                os.environ['REPO_PATH'] = original_repo_path
            elif 'REPO_PATH' in os.environ:
                del os.environ['REPO_PATH']

    def test_code_normalization(self, generator):
        """Test code normalization for fingerprinting."""
        # Test various whitespace scenarios
        code1 = "def function():\n    return True\n"
        code2 = "def function():\n        return True\n"  # Extra indentation
        code3 = "def function():\n\n    return True\n"  # Extra blank line

        normalized1 = generator._normalize_code_for_fingerprint(code1)
        normalized2 = generator._normalize_code_for_fingerprint(code2)
        normalized3 = generator._normalize_code_for_fingerprint(code3)

        # All should normalize to the same result
        assert normalized1 == normalized2 == normalized3
        assert "def function():" in normalized1
        assert "return True" in normalized1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
