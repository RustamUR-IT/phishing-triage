"""Static checks for the Sentinel Logic App playbook template (no Azure access needed)."""

import json
import re
from pathlib import Path

import pytest

PLAYBOOKS = Path(__file__).resolve().parent.parent / "playbooks"
TEMPLATES = sorted(PLAYBOOKS.glob("*/azuredeploy.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _strings(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)
    elif isinstance(node, str):
        yield node


def _workflow(template: dict) -> dict:
    return next(r for r in template["resources"] if r["type"] == "Microsoft.Logic/workflows")


def _action_scopes(actions: dict):
    """Yield every dict of sibling actions (top level, If branches, nested scopes)."""
    yield actions
    for action in actions.values():
        if "actions" in action:
            yield from _action_scopes(action["actions"])
        if "else" in action:
            yield from _action_scopes(action["else"].get("actions", {}))


def test_template_exists():
    assert TEMPLATES, "no playbooks/*/azuredeploy.json found"


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.parent.name)
def test_arm_parameters_and_variables_are_defined(path):
    template = _load(path)
    text = path.read_text(encoding="utf-8")
    for name in re.findall(r"parameters\('([^'$]+)'\)", text):
        # lower-camel names are Logic App workflow parameters, checked separately
        if name[0].isupper():
            assert name in template["parameters"], f"undefined ARM parameter {name}"
    for name in re.findall(r"variables\('([^']+)'\)", text):
        if name not in {"IncidentUrl", "IncidentNumber"}:
            assert name in template["variables"], f"undefined ARM variable {name}"


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.parent.name)
def test_no_accidental_arm_expressions(path):
    # ARM evaluates any string starting with "[" as an expression.
    for value in _strings(_load(path)):
        if value.startswith("[") and not value.startswith("[["):
            assert value.endswith("]"), f"unterminated ARM expression: {value[:60]}"


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.parent.name)
def test_workflow_parameters_are_declared_and_supplied(path):
    workflow = _workflow(_load(path))["properties"]
    declared = set(workflow["definition"]["parameters"])
    supplied = set(workflow["parameters"])
    assert supplied <= declared
    used = set(re.findall(r"parameters\('([a-z$][^']*)'\)", json.dumps(workflow["definition"])))
    assert used <= declared, f"undeclared workflow parameters: {used - declared}"


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.parent.name)
def test_run_after_and_references_resolve(path):
    definition = _workflow(_load(path))["properties"]["definition"]
    all_actions = set()
    for scope in _action_scopes(definition["actions"]):
        all_actions |= set(scope)
        for name, action in scope.items():
            for dep in action.get("runAfter", {}):
                assert dep in scope, f"{name} runs after {dep}, which is not a sibling"
    text = json.dumps(definition)
    for ref in re.findall(r"(?:body|outputs)\('([^']+)'\)", text):
        assert ref in all_actions, f"reference to unknown action {ref}"
    declared_vars = set()
    for scope in _action_scopes(definition["actions"]):
        for action in scope.values():
            if action["type"] == "InitializeVariable":
                declared_vars |= {v["name"] for v in action["inputs"]["variables"]}
    for ref in re.findall(r"variables\('([^']+)'\)", text):
        assert ref in declared_vars, f"variable {ref} is never initialized"


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.parent.name)
def test_notification_survives_incident_failure(path):
    actions = _workflow(_load(path))["properties"]["definition"]["actions"]
    statuses = actions["Send_email_notification"]["runAfter"]["Create_incident_if_severe_enough"]
    assert "Failed" in statuses
