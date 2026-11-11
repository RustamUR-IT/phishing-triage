"""Run the Sigma hunting rules in hunting/sigma/ against exported Sysmon events.

This is a small offline runner for the lab: export Sysmon events from the VM with
simulation/Export-SysmonEvents.ps1, copy the JSONL file over and run

    python hunting/hunt.py sim-events.jsonl

It implements the part of Sigma the rules here use: field maps (AND), lists of
values or maps (OR), the modifiers contains/startswith/endswith/all/re, wildcards
in plain values, and conditions with and/or/not, parentheses, "1 of" and
"all of". Matching is case-insensitive, as in Sigma. For a SIEM, convert the
same rules with sigma-cli or use the hand-written queries in hunting/queries/.

Needs PyYAML (pip install pyyaml).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent / "sigma"

# Sysmon event IDs per Sigma logsource category, for the categories used here.
CATEGORY_EVENT_IDS = {"process_creation": {1}}

Event = dict[str, object]
Predicate = Callable[[Event], bool]


# --------------------------------------------------------------------------- rules


@dataclass
class Rule:
    id: str
    title: str
    level: str
    tags: list[str]
    event_ids: set[int] | None
    match: Predicate
    path: Path

    @property
    def attack(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if re.match(r"attack\.t\d", t)]


def _value_matcher(value: object, modifiers: list[str]) -> Callable[[str], bool]:
    text = "" if value is None else str(value)
    if "re" in modifiers:
        rx = re.compile(text, re.IGNORECASE)
        return lambda s: rx.search(s) is not None
    needle = text.lower()
    if "contains" in modifiers:
        return lambda s: needle in s.lower()
    if "startswith" in modifiers:
        return lambda s: s.lower().startswith(needle)
    if "endswith" in modifiers:
        return lambda s: s.lower().endswith(needle)
    if "*" in needle or "?" in needle:
        rx = re.compile(fnmatch.translate(needle), re.IGNORECASE | re.DOTALL)
        return lambda s: rx.match(s) is not None
    return lambda s: s.lower() == needle


def _field_predicate(key: str, values: object) -> Predicate:
    field, *modifiers = key.split("|")
    unknown = set(modifiers) - {"contains", "startswith", "endswith", "all", "re"}
    if unknown:
        raise ValueError(f"unsupported Sigma modifier(s) {sorted(unknown)} in {key!r}")
    items = values if isinstance(values, list) else [values]
    matchers = [_value_matcher(v, modifiers) for v in items]
    combine = all if "all" in modifiers else any

    def pred(event: Event) -> bool:
        actual = event.get(field)
        if actual is None:
            return False
        s = str(actual)
        return combine(m(s) for m in matchers)

    return pred


def _selection_predicate(selection: object) -> Predicate:
    if isinstance(selection, list):  # list of maps -> OR
        preds = [_selection_predicate(item) for item in selection]
        return lambda e: any(p(e) for p in preds)
    if isinstance(selection, dict):  # map -> AND over fields
        preds = [_field_predicate(k, v) for k, v in selection.items()]
        return lambda e: all(p(e) for p in preds)
    raise ValueError(f"unsupported selection: {selection!r}")


_TOKEN = re.compile(r"\s*(\(|\)|[\w*]+)")


def _tokenize(condition: str) -> list[str]:
    tokens, pos = [], 0
    condition = condition.strip()
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            raise ValueError(f"cannot parse condition at: {condition[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def _compile_condition(condition: str, selections: dict[str, Predicate]) -> Predicate:
    tokens = _tokenize(condition)
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def names(pattern: str) -> list[Predicate]:
        if pattern == "them":
            pattern = "*"
        found = [p for n, p in selections.items() if fnmatch.fnmatchcase(n, pattern)]
        if not found:
            raise ValueError(f"condition references unknown selection {pattern!r}")
        return found

    def parse_or() -> Predicate:
        left = parse_and()
        while peek() == "or":
            take()
            right = parse_and()
            left = (lambda a, b: lambda e: a(e) or b(e))(left, right)
        return left

    def parse_and() -> Predicate:
        left = parse_not()
        while peek() == "and":
            take()
            right = parse_not()
            left = (lambda a, b: lambda e: a(e) and b(e))(left, right)
        return left

    def parse_not() -> Predicate:
        if peek() == "not":
            take()
            inner = parse_not()
            return lambda e: not inner(e)
        return parse_atom()

    def parse_atom() -> Predicate:
        tok = peek()
        if tok is None:
            raise ValueError(f"unexpected end of condition: {condition!r}")
        if tok == "(":
            take()
            inner = parse_or()
            if peek() != ")":
                raise ValueError(f"missing ')' in condition: {condition!r}")
            take()
            return inner
        if tok in {"1", "all"} and pos + 1 < len(tokens) and tokens[pos + 1].lower() == "of":
            quantifier = take().lower()
            take()  # "of"
            preds = names(take())
            if quantifier == "all":
                return lambda e: all(p(e) for p in preds)
            return lambda e: any(p(e) for p in preds)
        name = take()
        if name not in selections:
            raise ValueError(f"condition references unknown selection {name!r}")
        return selections[name]

    pred = parse_or()
    if pos != len(tokens):
        raise ValueError(f"trailing tokens in condition: {tokens[pos:]}")
    return pred


def load_rule(path: Path) -> Rule:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    detection = dict(doc["detection"])
    condition = detection.pop("condition")
    if isinstance(condition, list):
        condition = " or ".join(f"({c})" for c in condition)
    selections = {name: _selection_predicate(sel) for name, sel in detection.items()}
    category = doc.get("logsource", {}).get("category")
    return Rule(
        id=doc.get("id", path.stem),
        title=doc["title"],
        level=doc.get("level", "unknown"),
        tags=doc.get("tags", []),
        event_ids=CATEGORY_EVENT_IDS.get(category),
        match=_compile_condition(condition, selections),
        path=path,
    )


def load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    return [load_rule(p) for p in sorted(rules_dir.glob("*.yml"))]


# -------------------------------------------------------------------------- events


def normalize_event(raw: dict) -> Event:
    """Flatten the shapes we accept into one dict of Sysmon field -> value.

    Accepted: the flat output of Export-SysmonEvents.ps1, records with an
    "EventData" dict, and Winlogbeat/Elastic records with winlog.event_data.
    """
    event: Event = {}
    winlog = raw.get("winlog")
    if isinstance(winlog, dict):
        event.update(winlog.get("event_data") or {})
        event.setdefault("EventID", winlog.get("event_id"))
        event.setdefault("Computer", winlog.get("computer_name"))
    if isinstance(raw.get("EventData"), dict):
        event.update(raw["EventData"])
    event.update({k: v for k, v in raw.items() if not isinstance(v, dict)})
    if event.get("EventID") is not None:
        event["EventID"] = int(str(event["EventID"]))
    return event


def read_events(path: Path) -> Iterator[Event]:
    # utf-8-sig: Windows PowerShell 5.1 writes a BOM with -Encoding utf8.
    with path.open(encoding="utf-8-sig") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield normalize_event(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: not valid JSON ({exc.msg})") from exc


# ---------------------------------------------------------------------------- hunt


@dataclass
class Hit:
    rule: Rule
    event: Event


@dataclass
class HuntResult:
    hits: list[Hit]
    chains: list[tuple[Hit, list[Hit]]]  # stage-1 hit -> stage-2 hits it spawned
    events_scanned: int


STAGE1_ID = "5b0f6c1e-2d7a-4f3e-9a51-7c8e2b4d9f10"
STAGE2_ID = "9e3a7d42-6c18-4b0e-8f2d-1a5c4e7b3d26"


def hunt(events: Iterable[Event], rules: list[Rule]) -> HuntResult:
    hits: list[Hit] = []
    count = 0
    for event in events:
        count += 1
        for rule in rules:
            if rule.event_ids is not None and event.get("EventID") not in rule.event_ids:
                continue
            if rule.match(event):
                hits.append(Hit(rule, event))

    stage2_by_parent: dict[str, list[Hit]] = {}
    for h in hits:
        if h.rule.id == STAGE2_ID and h.event.get("ParentProcessGuid"):
            stage2_by_parent.setdefault(str(h.event["ParentProcessGuid"]).lower(), []).append(h)
    chains = [
        (h, stage2_by_parent.get(str(h.event.get("ProcessGuid", "")).lower(), []))
        for h in hits
        if h.rule.id == STAGE1_ID
    ]
    return HuntResult(hits=hits, chains=chains, events_scanned=count)


# -------------------------------------------------------------------------- output


def _short(value: object, width: int = 110) -> str:
    s = " ".join(str(value or "-").split())
    return s if len(s) <= width else s[: width - 1] + "…"


def _basename(path: object) -> str:
    return str(path or "-").replace("/", "\\").rsplit("\\", 1)[-1]


def render(result: HuntResult) -> str:
    out = [f"Scanned {result.events_scanned} events, {len(result.hits)} rule hit(s)."]
    if not result.hits:
        return "\n".join(out)

    out += ["", "Hits"]
    for h in result.hits:
        e = h.event
        out.append(
            f"  [{h.rule.level.upper():6}] {e.get('UtcTime', '-')}  {e.get('Computer', '-')}  "
            f"{_basename(e.get('ParentImage'))} -> {_basename(e.get('Image'))}  "
            f"({h.rule.title})"
        )
        out.append(f"           {_short(e.get('CommandLine'))}")

    if result.chains:
        out += ["", "Chains (stage 1 -> stage 2, linked by ProcessGuid)"]
        for stage1, children in result.chains:
            e = stage1.event
            out.append(
                f"  {e.get('UtcTime', '-')}  {e.get('User', '-')}  "
                f"{_basename(e.get('ParentImage'))} -> {_basename(e.get('Image'))}"
            )
            out.append(f"    {_short(e.get('CommandLine'))}")
            if not children:
                out.append("    (no stage-2 child seen)")
            for c in children:
                out.append(
                    f"    └─ {_basename(c.event.get('Image'))}: "
                    f"{_short(c.event.get('CommandLine'), 100)}"
                )

    techniques = sorted({t for h in result.hits for t in h.rule.attack})
    out += ["", "ATT&CK: " + ", ".join(techniques)]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("events", type=Path, nargs="+", help="JSONL file(s) with Sysmon events")
    parser.add_argument("--rules", type=Path, default=RULES_DIR, help="directory of Sigma .yml")
    parser.add_argument(
        "--expect-chain",
        action="store_true",
        help="exit 1 unless at least one stage-1 hit has a stage-2 child (for the lab test)",
    )
    args = parser.parse_args(argv)

    rules = load_rules(args.rules)
    events = (e for path in args.events for e in read_events(path))
    result = hunt(events, rules)
    print(render(result))
    if args.expect_chain and not any(children for _, children in result.chains):
        print("\nFAIL: no complete stage-1 -> stage-2 chain found", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
