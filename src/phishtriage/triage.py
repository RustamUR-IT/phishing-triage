"""Orchestrates parsing and analysis of one message into a report dict."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser

from phishtriage import __version__
from phishtriage.attachments import analyze_attachments, attachment_findings
from phishtriage.enrich import Fetch, enrich, http_get_json
from phishtriage.findings import attack_summary, score, sort_findings, verdict
from phishtriage.headers import (
    header_findings,
    originating_ip,
    parse_authentication,
    parse_received,
    parse_sender,
)
from phishtriage.urls import extract_urls, url_findings


def analyze(
    raw: bytes,
    *,
    source: str = "<stdin>",
    allowlist: set[str] | None = None,
    do_enrich: bool = False,
    env: dict | None = None,
    fetch: Fetch = http_get_json,
) -> dict:
    allowlist = allowlist or set()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    sender = parse_sender(msg)
    auth = parse_authentication(msg)
    hops = parse_received(msg)
    urls, mismatches = extract_urls(msg, allowlist)
    attachments = analyze_attachments(msg)

    findings = header_findings(sender, auth, allowlist) + url_findings(urls, mismatches)
    findings += attachment_findings(attachments)

    enrichment = None
    if do_enrich:
        public_ips = [h["ip"] for h in hops if h["ip_class"] == "public"]
        kwargs = {"env": env} if env is not None else {}
        enrichment, intel = enrich(
            [a["sha256"] for a in attachments], public_ips, fetch=fetch, **kwargs
        )
        findings += intel

    findings = sort_findings(findings)
    total = score(findings)
    return {
        "tool": {"name": "phishtriage", "version": __version__},
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "source": {"file": source, "sha256": hashlib.sha256(raw).hexdigest()},
        "summary": {
            "verdict": verdict(total),
            "score": total,
            "findings": len(findings),
            "urls": len(urls),
            "attachments": len(attachments),
            "originating_ip": originating_ip(hops),
        },
        "sender": sender,
        "authentication": auth,
        "received": hops,
        "urls": urls,
        "anchor_mismatches": mismatches,
        "attachments": attachments,
        "findings": [f.to_dict() for f in findings],
        "attack": attack_summary(findings),
        "enrichment": enrichment,
    }
