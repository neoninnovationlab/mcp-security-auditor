import os
import sys
import ast
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

from .models import Finding, ScanResult, Severity
from .rules import ALL_RULES

IGNORED_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "site-packages",
    "tests",
    "test",
    "__tests__",
    "spec",
    "specs",
}

SCANNABLE_EXTENSIONS = {
    ".py",
    ".ts",
    ".js",
    ".mjs",
    ".cjs",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    "Dockerfile",
}

def calculate_score(findings: List[Finding]) -> tuple[int, str]:
    score = 100
    for f in findings:
        if f.severity == Severity.CRITICAL:
            score -= 30
        elif f.severity == Severity.HIGH:
            score -= 15
        elif f.severity == Severity.MEDIUM:
            score -= 8
        elif f.severity == Severity.LOW:
            score -= 3

    score = max(0, min(100, score))

    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "F"

    return score, grade

class MCPScanner:
    def __init__(self, rules=None):
        self.rules = rules or ALL_RULES

    def scan_file(self, file_path: Path, root_path: Path) -> List[Finding]:
        findings = []
        rel_path = str(file_path.relative_to(root_path))

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return findings

        # Run text checks across all rules
        for rule in self.rules:
            try:
                findings.extend(rule.scan_text(rel_path, content))
            except Exception:
                pass

        # If python file, parse AST and run AST checks
        if file_path.suffix == ".py":
            try:
                tree = ast.parse(content, filename=str(file_path))
                for rule in self.rules:
                    try:
                        findings.extend(rule.scan_python_ast(rel_path, tree, content))
                    except Exception:
                        pass
            except SyntaxError:
                pass

        # Deduplicate findings
        unique_findings = []
        seen = set()
        for f in findings:
            key = (f.rule_id, f.file_path, f.line_number, f.title)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def scan_directory(self, target_dir: Path) -> ScanResult:
        target_dir = target_dir.resolve()
        target_name = target_dir.name
        total_files = 0
        all_findings: List[Finding] = []

        for root, dirs, files in os.walk(target_dir):
            # Prune ignored directories
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

            for file in files:
                file_path = Path(root) / file
                if file_path.suffix in SCANNABLE_EXTENSIONS or file == "Dockerfile":
                    total_files += 1
                    file_findings = self.scan_file(file_path, target_dir)
                    all_findings.extend(file_findings)

        score, grade = calculate_score(all_findings)

        return ScanResult(
            target_path=str(target_dir),
            target_name=target_name,
            total_files_scanned=total_files,
            trust_score=score,
            grade=grade,
            findings=all_findings,
            metadata={
                "engine_version": "1.0.0",
                "rules_count": len(self.rules),
            }
        )

def generate_markdown_report(result: ScanResult) -> str:
    s = result.findings
    crit = [f for f in s if f.severity == Severity.CRITICAL]
    high = [f for f in s if f.severity == Severity.HIGH]
    med = [f for f in s if f.severity == Severity.MEDIUM]
    low = [f for f in s if f.severity == Severity.LOW]

    md = []
    md.append(f"# MCP Security Audit Report: {result.target_name}\n")
    md.append(f"**Trust Score:** `{result.trust_score}/100` | **Security Grade:** **`{result.grade}`**\n")
    md.append(f"- **Target Path:** `{result.target_path}`")
    md.append(f"- **Files Scanned:** {result.total_files_scanned}")
    md.append(f"- **Total Findings:** {len(result.findings)} (Critical: {len(crit)}, High: {len(high)}, Medium: {len(med)}, Low: {len(low)})\n")

    md.append("## Vulnerability Summary\n")
    md.append("| Severity | CWE | Rule ID | File | Line | Title |")
    md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")

    for f in result.findings:
        md.append(f"| **{f.severity.value}** | {f.cwe_id} | `{f.rule_id}` | `{f.file_path}` | {f.line_number} | {f.title} |")

    if not result.findings:
        md.append("\n> ✅ **No security vulnerabilities detected.** All static security checks passed cleanly.\n")
    else:
        md.append("\n## Detailed Findings & Remediation Guidance\n")
        for i, f in enumerate(result.findings, 1):
            md.append(f"### {i}. [{f.severity.value}] {f.title}")
            md.append(f"- **CWE:** {f.cwe_id} | **Rule:** `{f.rule_id}` | **Confidence:** {f.confidence}")
            md.append(f"- **Location:** `{f.file_path}:{f.line_number}`")
            md.append(f"- **Description:** {f.description}")
            if f.snippet:
                md.append(f"```text\n{f.snippet}\n```")
            md.append(f"- **Remediation:** {f.remediation}\n")

    return "\n".join(md)

def main():
    parser = argparse.ArgumentParser(description="MCP Trust & Security Static Auditor")
    parser.add_argument("target", help="Path to the MCP server directory to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--output", "-o", help="File to write markdown or JSON report to")

    args = parser.parse_args()
    target_path = Path(args.target)

    if not target_path.exists():
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    scanner = MCPScanner()
    result = scanner.scan_directory(target_path)

    if args.json:
        output_str = json.dumps(result.to_dict(), indent=2)
    else:
        output_str = generate_markdown_report(result)

    if args.output:
        Path(args.output).write_text(output_str, encoding="utf-8")
        print(f"Report written to: {args.output}")
    else:
        print(output_str)

if __name__ == "__main__":
    main()
