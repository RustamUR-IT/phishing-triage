"""Render a report dict as JSON or ticket-ready Markdown (all IOCs defanged)."""

from __future__ import annotations

import json

from phishtriage.domains import defang_address, defang_domain

_SEV_LABEL = {"high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def _cell(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return lines


def _addr(value: str | None) -> str | None:
    return defang_address(value) if value else None


def to_markdown(report: dict) -> str:
    s, snd, auth = report["summary"], report["sender"], report["authentication"]
    from_line = _addr(snd["from_address"])
    if snd["from_name"]:
        from_line = f'"{defang_domain(snd["from_name"])}" <{from_line}>'
    out = [
        f"## Phishing triage: {_cell(snd['subject'])}",
        "",
        f"**Verdict:** {s['verdict'].upper()} (score {s['score']}, "
        f"{s['findings']} findings) · triage hint, not a final classification",
        "",
    ]
    out += _table(
        ["Field", "Value"],
        [
            ["From", from_line],
            ["Reply-To", _addr(snd["reply_to"])],
            ["Return-Path", _addr(snd["return_path"])],
            ["Date", snd["date"]],
            ["Message-ID", _addr(snd["message_id"])],
            ["SPF / DKIM / DMARC", f"{auth['spf']} / {auth['dkim']} / {auth['dmarc']}"],
            ["Originating IP", s["originating_ip"]],
            ["Source file", f"{report['source']['file']} (sha256 {report['source']['sha256']})"],
        ],
    )

    out += ["", "### Findings", ""]
    if report["findings"]:
        out += _table(
            ["Sev", "Finding", "ATT&CK"],
            [
                [_SEV_LABEL[f["severity"]], f["message"], ", ".join(f["attack"])]
                for f in report["findings"]
            ],
        )
    else:
        out.append("No findings.")

    out += ["", "### Received chain (origin first)", ""]
    if report["received"]:
        out += _table(
            ["#", "From", "IP", "By", "Time", "Delay"],
            [
                [
                    h["hop"],
                    defang_domain(h["from"] or "") or None,
                    f"{h['ip']} ({h['ip_class']})" if h["ip"] else None,
                    defang_domain(h["by"] or "") or None,
                    h["timestamp"],
                    f"{h['delay_seconds']}s" if h["delay_seconds"] is not None else None,
                ]
                for h in report["received"]
            ],
        )
    else:
        out.append("No Received headers.")

    out += ["", "### URLs", ""]
    if report["urls"]:
        out += _table(
            ["URL (defanged)", "Allowlisted", "Flags"],
            [
                [f"`{u['defanged']}`", "yes" if u["allowlisted"] else "no", ", ".join(u["flags"])]
                for u in report["urls"]
            ],
        )
    else:
        out.append("No URLs.")

    out += ["", "### Attachments", ""]
    if report["attachments"]:
        out += _table(
            ["Filename", "Size", "Detected type", "SHA-256"],
            [
                [a["filename"], a["size"], a["type"], f"`{a['sha256']}`"]
                for a in report["attachments"]
            ],
        )
    else:
        out.append("No attachments.")

    enr = report.get("enrichment")
    if enr:
        out += ["", "### Enrichment", ""]
        for r in enr.get("virustotal") or []:
            if r.get("found"):
                out.append(
                    f"- VirusTotal `{r['sha256'][:16]}...`: {r['malicious']} malicious, "
                    f"{r['suspicious']} suspicious ({r['link']})"
                )
            else:
                out.append(f"- VirusTotal `{r['sha256'][:16]}...`: {r.get('error', 'not found')}")
        for r in enr.get("abuseipdb") or []:
            if "error" in r:
                out.append(f"- AbuseIPDB {r['ip']}: {r['error']}")
            else:
                out.append(
                    f"- AbuseIPDB {r['ip']}: confidence {r['abuse_confidence']}%, "
                    f"{r['total_reports']} reports, {r['country']}, {r['isp']}"
                )
        for skipped in enr.get("skipped", []):
            out.append(f"- skipped: {skipped}")

    if report["attack"]:
        out += ["", "### MITRE ATT&CK", ""]
        out += [f"- {t['id']} {t['name']}" for t in report["attack"]]

    tool = report["tool"]
    out += ["", f"<sub>{tool['name']} {tool['version']} · {report['generated_at']}</sub>", ""]
    return "\n".join(out)
