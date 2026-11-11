"""Metadata checks for the KQL analytics rules in detections/.

Query syntax and column names are checked separately by scripts/check_kql.cjs (Kusto.Language).
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "detections").glob("*.kql"))

# Techniques used by the rules and the tactics (Sentinel spelling) they belong to.
TECHNIQUE_TACTICS = {
    "T1110.001": {"CredentialAccess"},  # Brute Force: Password Guessing
    "T1110.003": {"CredentialAccess"},  # Brute Force: Password Spraying
    "T1566.002": {"InitialAccess"},  # Phishing: Spearphishing Link
    "T1204.001": {"Execution"},  # User Execution: Malicious Link
    "T1564.008": {"DefenseEvasion"},  # Hide Artifacts: Email Hiding Rules
    "T1114.003": {"Collection"},  # Email Collection: Email Forwarding Rule
}
REQUIRED = ["Title", "ATT&CK", "Tactics", "Severity", "Data sources", "Schedule", "Entities"]


def header(path: Path) -> dict[str, str]:
    """Read the leading `// Key: value` comment block; indented lines continue the last key."""
    fields: dict[str, str] = {}
    key = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("//"):
            break
        body = line[2:].strip()
        m = re.match(r"([A-Za-z&][\w& ]*?):\s+(.*)", body)
        if m and not line[2:].startswith("   "):
            key = m.group(1)
            fields[key] = m.group(2)
        elif key:
            fields[key] += " " + body
    return fields


def test_three_rules_present():
    assert len(RULES) == 3


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.name)
def test_header_complete(rule):
    fields = header(rule)
    missing = [k for k in REQUIRED if not fields.get(k)]
    assert not missing, f"{rule.name}: missing header fields {missing}"


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.name)
def test_attack_mapping_consistent(rule):
    fields = header(rule)
    techniques = [t.strip() for t in fields["ATT&CK"].split(",")]
    tactics = {t.strip() for t in fields["Tactics"].split(",")}
    assert techniques
    for t in techniques:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", t), t
        assert t in TECHNIQUE_TACTICS, f"{t} not in the technique table"
    expected = set().union(*(TECHNIQUE_TACTICS[t] for t in techniques))
    assert tactics == expected, f"{rule.name}: tactics {tactics} != {expected}"


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.name)
def test_rule_emits_severity_and_entities(rule):
    """Severity override and entity mapping must point at columns the query projects."""
    text = rule.read_text(encoding="utf-8")
    final = text[text.rindex("| project") :]
    fields = header(rule)
    columns = ["Severity"] + re.findall(r"= (\w+)", fields["Entities"])
    for col in columns:
        assert re.search(rf"\b{col}\b", final), f"{rule.name}: {col} not in final projection"


def test_rules_documented():
    readme = (ROOT / "detections" / "README.md").read_text(encoding="utf-8")
    for rule in RULES:
        assert rule.name in readme
