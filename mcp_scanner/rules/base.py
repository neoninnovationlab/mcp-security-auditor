from abc import ABC, abstractmethod
from typing import List, Optional, Any
import ast
from ..models import Finding, Severity

class BaseRule(ABC):
    rule_id: str = "BASE"
    title: str = "Base Rule"
    severity: Severity = Severity.MEDIUM
    cwe_id: str = "CWE-000"

    @abstractmethod
    def scan_python_ast(self, file_path: str, tree: ast.AST, content: str) -> List[Finding]:
        """Scan a Python AST for vulnerabilities."""
        return []

    @abstractmethod
    def scan_text(self, file_path: str, content: str) -> List[Finding]:
        """Scan raw text content (JS, TS, JSON, config) for vulnerabilities."""
        return []
