import importlib.util
import json
import sys
from pathlib import Path

import pytest

HUNTING = Path(__file__).resolve().parent.parent / "hunting"
_spec = importlib.util.spec_from_file_location("hunt", HUNTING / "hunt.py")
hunt = importlib.util.module_from_spec(_spec)
sys.modules["hunt"] = hunt
_spec.loader.exec_module(hunt)

ATTACK = HUNTING / "testdata" / "simulated_attack.jsonl"
BENIGN = HUNTING / "testdata" / "benign_baseline.jsonl"


@pytest.fixture(scope="module")
def rules():
    return hunt.load_rules()


def run(rules, *events):
    return hunt.hunt([hunt.normalize_event(e) for e in events], rules)


def stage1_event(**overrides):
    event = {
        "EventID": 1,
        "Image": r"C:\Windows\System32\wscript.exe",
        "OriginalFileName": "wscript.exe",
        "ParentImage": r"C:\Windows\explorer.exe",
        "CommandLine": r'"C:\Windows\System32\WScript.exe" "C:\Users\a\Downloads\x.js"',
        "ProcessGuid": "{A}",
    }
    event.update(overrides)
    return event


def test_rules_load_with_unique_ids_and_attack_tags(rules):
    assert {r.id for r in rules} == {hunt.STAGE1_ID, hunt.STAGE2_ID}
    for r in rules:
        assert r.event_ids == {1}
        assert r.attack, r.title


def test_simulated_attack_produces_both_chains(rules):
    result = hunt.hunt(hunt.read_events(ATTACK), rules)
    assert len(result.chains) == 2
    children = [sorted(hunt._basename(c.event["Image"]) for c in kids) for _, kids in result.chains]
    assert children == [["cmd.exe", "powershell.exe"], ["powershell.exe"]]
    # whoami.exe (child of cmd.exe, not of the script host) is not a hit
    assert not any(h.event["Image"].endswith("whoami.exe") for h in result.hits)


def test_benign_baseline_has_no_stage1_hit(rules):
    result = hunt.hunt(hunt.read_events(BENIGN), rules)
    assert result.chains == []
    # The logon script calling cmd.exe is a known stage-2-only false positive:
    # it is why the hunt reports chains, not single stage-2 hits.
    assert [h.rule.id for h in result.hits] == [hunt.STAGE2_ID]
    assert "NETLOGON" in result.hits[0].event["ParentCommandLine"]


def test_expect_chain_exit_codes(capsys):
    assert hunt.main([str(ATTACK), "--expect-chain"]) == 0
    assert "stage 1 -> stage 2" in capsys.readouterr().out
    assert hunt.main([str(BENIGN), "--expect-chain"]) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"Image": r"C:\Users\a\AppData\Local\Temp\svc.exe"},  # renamed copy of wscript
        {"Image": r"C:\WINDOWS\SYSTEM32\WSCRIPT.EXE"},  # case-insensitive
        {
            "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            "CommandLine": r"wscript C:\Users\a\AppData\Local\Microsoft\Windows\INetCache"
            r"\Content.Outlook\AB12CD34\Rechnung.vbs",
        },
        {
            "Image": r"C:\Windows\System32\mshta.exe",
            "OriginalFileName": "MSHTA.EXE",
            "ParentImage": r"C:\Program Files\WinRAR\WinRAR.exe",
            "CommandLine": r'mshta "C:\Users\a\AppData\Local\Temp\Rar$EXa1234.5678\invoice.hta"',
        },
    ],
)
def test_stage1_variants_match(rules, overrides):
    result = run(rules, stage1_event(**overrides))
    assert len(result.chains) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"CommandLine": r"wscript C:\Tools\inventory.vbs"},  # not a user download location
        {"ParentImage": r"C:\Windows\System32\cmd.exe"},  # not started by a user-facing launcher
        {"Image": r"C:\Windows\notepad.exe", "OriginalFileName": "NOTEPAD.EXE"},
        {"EventID": 3},  # network connection, not process creation
    ],
)
def test_stage1_near_misses_do_not_match(rules, overrides):
    assert run(rules, stage1_event(**overrides)).hits == []


def test_missing_field_does_not_match(rules):
    event = stage1_event()
    del event["CommandLine"]
    assert run(rules, event).hits == []


def test_winlogbeat_shape_is_normalized(rules):
    raw = {
        "@timestamp": "2026-11-11T09:02:14.311Z",
        "winlog": {"event_id": "1", "computer_name": "LAB", "event_data": stage1_event()},
    }
    raw["winlog"]["event_data"].pop("EventID")
    event = hunt.normalize_event(raw)
    assert event["EventID"] == 1 and event["Computer"] == "LAB"
    assert len(hunt.hunt([event], rules).chains) == 1


def test_read_events_accepts_bom_and_blank_lines(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_text("\n" + json.dumps(stage1_event()) + "\n\n", encoding="utf-8-sig")
    assert len(list(hunt.read_events(path))) == 1


def test_read_events_reports_bad_line(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_text("{not json\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"e\.jsonl:1"):
        list(hunt.read_events(path))


# --- Sigma subset ------------------------------------------------------------------------------


def write_rule(tmp_path, detection: str) -> "hunt.Rule":
    path = tmp_path / "r.yml"
    path.write_text(
        "title: t\nlogsource: {category: process_creation}\ndetection:\n" + detection,
        encoding="utf-8",
    )
    return hunt.load_rule(path)


def test_condition_operators(tmp_path):
    rule = write_rule(
        tmp_path,
        "  sel_a: {A: x}\n  sel_b: {B: y}\n  filter: {C: z}\n"
        "  condition: (1 of sel_*) and not filter\n",
    )
    assert rule.match({"A": "X"})
    assert rule.match({"B": "y"})
    assert not rule.match({"A": "x", "C": "z"})
    assert not rule.match({"D": "x"})


def test_all_of_and_all_modifier_and_wildcards(tmp_path):
    rule = write_rule(
        tmp_path,
        "  sel_a:\n    CommandLine|contains|all: ['-nop', '-w hidden']\n"
        "  sel_b:\n    Image: '*\\powershell.exe'\n"
        "  condition: all of sel_*\n",
    )
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert rule.match({"Image": ps, "CommandLine": "powershell -NoP -W Hidden -c x"})
    assert not rule.match({"Image": ps, "CommandLine": "powershell -nop"})


def test_unknown_modifier_and_selection_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="unsupported Sigma modifier"):
        write_rule(tmp_path, "  sel: {A|base64offset: x}\n  condition: sel\n")
    with pytest.raises(ValueError, match="unknown selection"):
        write_rule(tmp_path, "  sel: {A: x}\n  condition: sel and other\n")
