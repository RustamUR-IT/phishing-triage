import json

import pytest

from phishtriage.cli import main
from phishtriage.triage import analyze

ALLOW = {"example.com", "example.org"}


def test_credential_phish_sample(sample_bytes):
    r = analyze(sample_bytes("credential_phish.eml"), allowlist=ALLOW)
    assert r["summary"]["verdict"] == "likely malicious"
    assert r["authentication"]["dmarc"] == "fail"
    assert r["summary"]["originating_ip"] == "198.51.100.23"
    techniques = {t["id"] for t in r["attack"]}
    assert {"T1566.002", "T1656", "T1672"} <= techniques


def test_attachment_phish_sample(sample_bytes):
    r = analyze(sample_bytes("attachment_phish.eml"), allowlist=ALLOW)
    kinds = {a["filename"]: a["type"] for a in r["attachments"]}
    assert kinds["Rechnung_2026-0117.pdf.exe"] == "pe-executable"
    assert kinds["Lieferschein_0117.pdf"] == "zip"
    assert kinds["Rechnung_Details.docm"] == "ooxml-word"
    assert all(len(a["sha256"]) == 64 for a in r["attachments"])
    assert "T1566.001" in {t["id"] for t in r["attack"]}


def test_benign_sample_is_quiet(sample_bytes):
    r = analyze(sample_bytes("benign_newsletter.eml"), allowlist=ALLOW)
    assert r["findings"] == []
    assert r["summary"]["verdict"] == "no strong indicators"


def test_cli_writes_markdown_and_json(tmp_path, capsys):
    rc = main(["samples/credential_phish.eml", "-a", "allowlist.example.txt", "-o", str(tmp_path)])
    assert rc == 0
    stdout = capsys.readouterr().out
    assert stdout.startswith("## Phishing triage:")
    assert "hxxps://examp1e-it[.]test" in stdout
    assert "https://examp1e-it.test" not in stdout  # nothing clickable in the ticket
    data = json.loads((tmp_path / "credential_phish.json").read_text())
    assert data["summary"]["score"] > 0
    assert (tmp_path / "credential_phish.md").exists()


def test_cli_json_to_stdout(capsys):
    assert main(["samples/benign_newsletter.eml", "-f", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["tool"]["name"] == "phishtriage"


def test_cli_missing_file(capsys):
    assert main(["does-not-exist.eml"]) == 2
    assert "phishtriage:" in capsys.readouterr().err


def test_cli_rejects_unknown_format():
    with pytest.raises(SystemExit):
        main(["samples/benign_newsletter.eml", "-f", "xml"])
