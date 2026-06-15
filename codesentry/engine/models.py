from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1}[self.value]


@dataclass
class Issue:
    file: str
    line: int
    severity: Severity
    category: str
    message: str
    source: str = ""
    rule_id: str = ""
    ai_explanation: Optional[str] = None
    fix_suggestion: Optional[str] = None


@dataclass
class ScanResult:
    filename: str
    issues: list[Issue] = field(default_factory=list)
    maintainability_score: float = 0.0
    scanners_used: list[str] = field(default_factory=list)

    def deduplicate(self):
        """去重：同一文件、同一行、同一规则只保留最高严重度。"""
        seen: dict[str, Issue] = {}
        for issue in self.issues:
            key = f"{issue.file}:{issue.line}:{issue.rule_id}"
            if key not in seen or issue.severity.rank > seen[key].severity.rank:
                seen[key] = issue
        self.issues = sorted(seen.values(), key=lambda i: (-i.severity.rank, i.line))

    def to_dict(self) -> dict:
        """单次遍历计算计数。"""
        high = medium = low = 0
        for i in self.issues:
            if i.severity == Severity.HIGH:
                high += 1
            elif i.severity == Severity.MEDIUM:
                medium += 1
            else:
                low += 1

        return {
            "filename": self.filename,
            "maintainability_score": round(self.maintainability_score, 1),
            "high": high,
            "medium": medium,
            "low": low,
            "total": len(self.issues),
            "engines_used": self.scanners_used,
            "issues": [
                {
                    "line": i.line,
                    "severity": i.severity.value,
                    "category": i.category,
                    "message": i.message,
                    "source": i.source,
                    "rule_id": i.rule_id,
                }
                for i in self.issues
            ],
        }
