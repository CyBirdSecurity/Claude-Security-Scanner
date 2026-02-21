#!/usr/bin/env python3
"""
SARIF Generator for Claude Code Security Review
Converts security findings to SARIF 2.1.0 format aligned with CVSS 4.0 severity ratings.
"""

import json
import hashlib
from typing import Dict, Any, List
from pathlib import Path


class SarifGenerator:
    """Generates SARIF 2.1.0 compliant output from security findings."""

    # CVSS 4.0 severity ranges
    SEVERITY_RANGES = {
        "CRITICAL": (9.0, 10.0),
        "HIGH": (7.0, 8.9),
        "MEDIUM": (4.0, 6.9),
        "LOW": (0.1, 3.9)
    }

    # Default severity scores (used when confidence is not available or for non-CRITICAL/HIGH)
    DEFAULT_SCORES = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.5,
        "LOW": 2.0
    }

    def __init__(self, tool_name: str = "Claude Code Security Review",
                 tool_version: str = "1.0.0",
                 repo_root: str = None):
        """
        Initialize SARIF generator.

        Args:
            tool_name: Name of the analysis tool
            tool_version: Version of the tool
            repo_root: Root directory of the repository (for relative paths)
        """
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.repo_root = Path(repo_root) if repo_root else Path.cwd()

    def _calculate_severity_score(self, severity: str, confidence: float = None) -> float:
        """
        Calculate CVSS 4.0 aligned security-severity score.

        For CRITICAL and HIGH findings, uses confidence to map within the range.
        For MEDIUM and LOW, uses default values.

        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            confidence: Confidence score (0.0-1.0), optional

        Returns:
            Float score between 0.1 and 10.0
        """
        severity = severity.upper()

        if severity not in self.SEVERITY_RANGES:
            # Unknown severity, default to MEDIUM
            return self.DEFAULT_SCORES["MEDIUM"]

        # For CRITICAL and HIGH, map confidence to score range
        if severity in ["CRITICAL", "HIGH"] and confidence is not None:
            min_score, max_score = self.SEVERITY_RANGES[severity]

            # For CRITICAL: confidence 0.9-1.0 maps to 9.0-10.0
            if severity == "CRITICAL":
                # Normalize confidence from 0.9-1.0 range to 0.0-1.0 range
                normalized_confidence = max(0.0, min(1.0, (confidence - 0.9) / 0.1))
                return min_score + (normalized_confidence * (max_score - min_score))

            # For HIGH: confidence 0.7-1.0 maps to 7.0-8.9
            elif severity == "HIGH":
                # Normalize confidence from 0.7-1.0 range to 0.0-1.0 range
                normalized_confidence = max(0.0, min(1.0, (confidence - 0.7) / 0.3))
                return min_score + (normalized_confidence * (max_score - min_score))

        # For MEDIUM, LOW, or when confidence not available, use defaults
        return self.DEFAULT_SCORES.get(severity, self.DEFAULT_SCORES["MEDIUM"])

    def _get_sarif_level(self, severity: str) -> str:
        """
        Map severity to SARIF level.

        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            SARIF level (error, warning, note)
        """
        severity = severity.upper()

        if severity in ["CRITICAL", "HIGH"]:
            return "error"
        elif severity == "MEDIUM":
            return "warning"
        else:
            return "note"

    def _get_relative_path(self, file_path: str) -> str:
        """
        Convert file path to relative path from repo root.

        Args:
            file_path: Absolute or relative file path

        Returns:
            Relative path from repo root
        """
        try:
            path = Path(file_path)
            if path.is_absolute():
                return str(path.relative_to(self.repo_root))
            return file_path
        except (ValueError, Exception):
            # If path is already relative or can't be made relative, return as-is
            return file_path

    def _generate_fingerprint(self, finding: Dict[str, Any]) -> str:
        """
        Generate a stable fingerprint for finding deduplication.

        GitHub uses fingerprints to match results across runs.

        Args:
            finding: Finding dictionary

        Returns:
            SHA-256 hash as fingerprint
        """
        # Create fingerprint from file, line, and category
        fingerprint_string = f"{finding.get('file', '')}:{finding.get('line', 0)}:{finding.get('category', '')}"
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()

    def _extract_rules(self, findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Extract unique rules from findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary mapping rule IDs to rule definitions
        """
        rules = {}

        for finding in findings:
            category = finding.get('category', 'unknown')

            if category not in rules:
                # Create rule definition
                rules[category] = {
                    "id": category,
                    "name": category.replace('_', ' ').title(),
                    "shortDescription": {
                        "text": finding.get('description', 'Security vulnerability detected')[:1024]
                    },
                    "fullDescription": {
                        "text": finding.get('description', 'Security vulnerability detected')
                    },
                    "help": {
                        "text": finding.get('recommendation', 'Review and remediate this security issue'),
                        "markdown": f"**Recommendation:** {finding.get('recommendation', 'Review and remediate this security issue')}"
                    },
                    "properties": {
                        "tags": [
                            "security",
                            category.split('_')[0] if '_' in category else category
                        ],
                        "precision": "high"
                    }
                }

        return rules

    def generate_sarif(self, findings_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate SARIF 2.1.0 document from findings.

        Args:
            findings_data: Complete findings data including 'findings' array

        Returns:
            SARIF document as dictionary
        """
        findings = findings_data.get('findings', [])

        # Extract rules from findings
        rules = self._extract_rules(findings)

        # Build results array
        results = []
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM').upper()
            confidence = finding.get('confidence', None)

            # Calculate security-severity score
            security_severity = self._calculate_severity_score(severity, confidence)

            # Get relative file path
            file_path = self._get_relative_path(finding.get('file', 'unknown'))

            # Build result object
            result = {
                "ruleId": finding.get('category', 'unknown'),
                "level": self._get_sarif_level(severity),
                "message": {
                    "text": finding.get('description', 'Security vulnerability detected')
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": finding.get('line', 1),
                            "startColumn": 1
                        }
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": self._generate_fingerprint(finding)
                },
                "properties": {
                    "security-severity": str(security_severity),
                    "cvss-severity": severity,
                    "confidence": confidence if confidence is not None else 0.8
                }
            }

            # Add exploit scenario and recommendation if available
            if finding.get('exploit_scenario'):
                result['message']['markdown'] = f"{finding['description']}\n\n**Exploit Scenario:** {finding['exploit_scenario']}"

            if finding.get('recommendation'):
                result['properties']['recommendation'] = finding['recommendation']

            results.append(result)

        # Build SARIF document
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "informationUri": "https://github.com/anthropics/claude-code-security-review",
                        "rules": list(rules.values())
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits"
            }]
        }

        return sarif

    def save_sarif(self, findings_data: Dict[str, Any], output_path: str) -> None:
        """
        Generate and save SARIF document to file.

        Args:
            findings_data: Complete findings data
            output_path: Path to save SARIF file
        """
        sarif = self.generate_sarif(findings_data)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)


def main():
    """CLI entry point for SARIF generation."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python sarif_generator.py <findings.json> [output.sarif]", file=sys.stderr)
        sys.exit(1)

    findings_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "results.sarif"

    # Load findings
    with open(findings_file, 'r', encoding='utf-8') as f:
        findings_data = json.load(f)

    # Generate SARIF
    generator = SarifGenerator()
    generator.save_sarif(findings_data, output_file)

    print(f"SARIF file generated: {output_file}", file=sys.stderr)
    print(f"Total findings: {len(findings_data.get('findings', []))}", file=sys.stderr)


if __name__ == "__main__":
    main()
