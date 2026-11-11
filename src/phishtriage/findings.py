"""Finding model, severity scoring and the MITRE ATT&CK technique catalogue."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Techniques referenced by findings. Names follow ATT&CK Enterprise.
ATTACK_TECHNIQUES: dict[str, str] = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1656": "Impersonation",
    "T1672": "Email Spoofing",
    "T1036.002": "Masquerading: Right-to-Left Override",
    "T1036.007": "Masquerading: Double File Extension",
    "T1036.008": "Masquerading: Masquerade File Type",
    "T1027.006": "Obfuscated Files or Information: HTML Smuggling",
    "T1027.013": "Obfuscated Files or Information: Encrypted/Encoded File",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1553.005": "Subvert Trust Controls: Mark-of-the-Web Bypass",
}

SEVERITY_SCORE = {"info": 0, "low": 1, "medium": 3, "high": 5}
SEVERITY_ORDER = ["high", "medium", "low", "info"]


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    message: str
    attack: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_SCORE:
            raise ValueError(f"unknown severity {self.severity!r}")
        unknown = [t for t in self.attack if t not in ATTACK_TECHNIQUES]
        if unknown:
            raise ValueError(f"unknown ATT&CK technique(s) {unknown}")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attack"] = list(self.attack)
        return d


def score(findings: list[Finding]) -> int:
    return sum(SEVERITY_SCORE[f.severity] for f in findings)


def verdict(total: int) -> str:
    """Triage hint, not a classification. Thresholds are deliberately simple."""
    if total >= 10:
        return "likely malicious"
    if total >= 4:
        return "suspicious"
    return "no strong indicators"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.id))


def attack_summary(findings: list[Finding]) -> list[dict]:
    ids = sorted({t for f in findings for t in f.attack})
    return [{"id": t, "name": ATTACK_TECHNIQUES[t]} for t in ids]
