from dataclasses import asdict, dataclass
from typing import Any

EVIDENCE_TYPES = ("directly_observed", "deterministically_derived", "ml_inferred", "unknown")
RANK = {"unknown": 0, "ml_inferred": 1, "directly_observed": 2, "deterministically_derived": 3}


@dataclass
class Evidence:
    field: str
    value: Any
    evidence_type: str
    confidence: float
    source: str
    detail: str = ""

    def __post_init__(self):
        if self.evidence_type not in EVIDENCE_TYPES:
            raise ValueError(self.evidence_type)
        if self.evidence_type == "unknown":
            self.confidence = 0.0

    def json(self):
        return asdict(self)


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    status: str
    description: str
    evidence: list
    recommendation: str
    confidence: float

    def json(self):
        return asdict(self)
