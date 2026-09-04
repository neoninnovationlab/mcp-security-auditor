import ast
import re
from typing import List
from .base import BaseRule
from ..models import Finding, Severity

ADVERSARIAL_PATTERNS = [
    (re.compile(r'ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions', re.I), "Prompt Injection: Ignore Previous Instructions"),
    (re.compile(r'(?:you\s+are\s+now\s+in|switch\s+to)\s+developer\s+mode', re.I), "Prompt Injection: Developer Mode Override"),
    (re.compile(r'<\/?(?:system|instruction|admin|override)>', re.I), "Prompt Injection: System Tag Mimicry"),
    (re.compile(r'\[SYSTEM(?:\s+PROMPT)?\]', re.I), "Prompt Injection: Fake System Prompt Header"),
    (re.compile(r'(?:exfiltrate|secretly\s+send|upload\s+(?:all\s+)?keys\s+to)', re.I), "Adversarial Tool Poisoning: Data Exfiltration Directive"),
]

class ToolPoisoningRule(BaseRule):
    rule_id: str = "MCP-SEC-005"
    title: str = "Tool Poisoning & Prompt Injection Risk"
    severity: Severity = Severity.HIGH
    cwe_id: str = "CWE-1384" # Improper Neutralization of Intent/Directives in LLM Prompts

    def scan_python_ast(self, file_path: str, tree: ast.AST, content: str) -> List[Finding]:
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            # Check docstrings of tool functions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                docstring = ast.get_docstring(node)
                if docstring:
                    for pattern, title in ADVERSARIAL_PATTERNS:
                        match = pattern.search(docstring)
                        if match:
                            line_no = node.lineno
                            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    title=title,
                                    severity=Severity.HIGH,
                                    cwe_id=self.cwe_id,
                                    file_path=file_path,
                                    line_number=line_no,
                                    snippet=snippet,
                                    description=f"Function '{node.name}' contains adversarial prompt injection directives in its docstring/description: '{match.group(0)}'. This will be passed to the LLM as tool metadata and can hijack the agent's behavior.",
                                    remediation="Remove adversarial directives from tool descriptions and sanitize metadata before exposing to LLM.",
                                    confidence="HIGH"
                                )
                            )

        return findings

    def scan_text(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        # Check tool definitions in JSON, TS, or JS (Python handled via AST)
        if not any(file_path.endswith(ext) for ext in (".json", ".ts", ".js")):
            return findings

        # Check for zero-width characters (homoglyph/steganography attack)
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        for i, line in enumerate(content.splitlines(), 1):
            for zwc in zero_width_chars:
                if zwc in line:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title="Zero-Width Hidden Character in Tool Metadata",
                            severity=Severity.HIGH,
                            cwe_id="CWE-1384",
                            file_path=file_path,
                            line_number=i,
                            snippet=line.strip()[:80],
                            description="Detected zero-width unicode characters, commonly used to hide prompt injection directives from human reviewers while remaining visible to tokenizers.",
                            remediation="Strip all non-printable and zero-width unicode characters from tool descriptions.",
                            confidence="HIGH"
                        )
                    )
                    break

            for pattern, title in ADVERSARIAL_PATTERNS:
                match = pattern.search(line)
                if match:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=title,
                            severity=Severity.HIGH,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=i,
                            snippet=line.strip()[:100],
                            description=f"Adversarial prompt injection pattern detected in description/configuration: '{match.group(0)}'.",
                            remediation="Sanitize tool descriptions to strictly state functional behavior without prompt instructions.",
                            confidence="HIGH"
                        )
                    )

        return findings
