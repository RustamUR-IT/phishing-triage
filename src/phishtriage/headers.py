"""Sender headers, SPF/DKIM/DMARC results and the Received chain."""

from __future__ import annotations

import ipaddress
import re
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime

from phishtriage.domains import (
    base_domain,
    defang_domain,
    domain_of,
    is_allowlisted,
    looks_like_domain,
)
from phishtriage.findings import Finding

_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_FROM_RE = re.compile(r"^\s*from\s+(\S+)", re.I)
_BY_RE = re.compile(r"\bby\s+(\S+)", re.I)
_BRACKET_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_PAREN_RE = re.compile(r"\(([^()]*)\)")
_BARE_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_DOMAIN_IN_TEXT_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)

_INTERNAL_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]
_DOC_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]

# result -> (severity, human label); "pass" produces no finding
_AUTH_SEVERITY = {
    "spf": {
        "fail": "medium",
        "softfail": "low",
        "none": "low",
        "neutral": "low",
        "permerror": "low",
        "temperror": "info",
    },
    "dkim": {
        "fail": "medium",
        "none": "low",
        "neutral": "low",
        "policy": "low",
        "permerror": "low",
        "temperror": "info",
    },
    "dmarc": {"fail": "high", "none": "low", "permerror": "low", "temperror": "info"},
}


def classify_ip(ip: str) -> str:
    """'internal', 'documentation' (RFC 5737/3849 test ranges) or 'public'."""
    addr = ipaddress.ip_address(ip)
    if any(addr in n for n in _INTERNAL_NETS):
        return "internal"
    if any(addr in n for n in _DOC_NETS):
        return "documentation"
    return "public"


def _clean(value: object) -> str:
    return re.sub(r"\s+", " ", str(value)).strip() if value is not None else ""


def parse_authentication(msg: Message) -> dict:
    """Use the top-most Authentication-Results header (added by the receiving MTA)."""
    raw = [_clean(v) for v in msg.get_all("Authentication-Results", [])]
    results: dict[str, str | None] = {"spf": None, "dkim": None, "dmarc": None}
    if raw:
        dkim_seen = []
        for mech, res in _AUTH_RE.findall(raw[0]):
            mech, res = mech.lower(), res.lower()
            if mech == "dkim":
                dkim_seen.append(res)
            elif results[mech] is None:
                results[mech] = res
        if dkim_seen:
            # any valid signature counts; otherwise report the first result
            results["dkim"] = "pass" if "pass" in dkim_seen else dkim_seen[0]
    if results["spf"] is None:
        received_spf = _clean(msg.get("Received-SPF"))
        if received_spf:
            results["spf"] = received_spf.split()[0].lower()
    return {**results, "authentication_results": raw}


def _extract_ip(text: str) -> str | None:
    """Prefer the IP the receiving MTA recorded, e.g. "from helo (rdns [IP])".

    The HELO name right after "from" is chosen by the sender and may itself be a
    bracketed IP literal, so it is only used as a fallback.
    """
    recorded = " ".join(_PAREN_RE.findall(text))
    candidates = _BRACKET_IP_RE.findall(recorded) + _BARE_IPV4_RE.findall(recorded)
    candidates += _BRACKET_IP_RE.findall(text) + _BARE_IPV4_RE.findall(text)
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def parse_received(msg: Message) -> list[dict]:
    """Return hops ordered from origin to final mailbox."""
    hops = []
    for raw in reversed(msg.get_all("Received", [])):
        text = _clean(raw)
        head, _, date_part = text.rpartition(";")
        head = head or text
        from_part = head.split(" by ", 1)[0]
        from_m = _FROM_RE.search(head)
        by_m = _BY_RE.search(head)
        ip = _extract_ip(from_part)
        ts = None
        try:
            ts = parsedate_to_datetime(date_part.strip()) if date_part else None
        except (TypeError, ValueError):
            ts = None
        hops.append(
            {
                "from": from_m.group(1) if from_m else None,
                "ip": ip,
                "ip_class": classify_ip(ip) if ip else None,
                "by": by_m.group(1).rstrip(";") if by_m else None,
                "timestamp": ts.isoformat() if ts else None,
                "_ts": ts,
            }
        )
    prev = None
    for i, hop in enumerate(hops, start=1):
        hop["hop"] = i
        ts = hop.pop("_ts")
        hop["delay_seconds"] = None
        if ts and prev and ts.tzinfo and prev.tzinfo:
            hop["delay_seconds"] = int((ts - prev).total_seconds())
        prev = ts or prev
    return hops


def originating_ip(hops: list[dict]) -> str | None:
    for hop in hops:
        if hop["ip"] and hop["ip_class"] != "internal":
            return hop["ip"]
    return None


def parse_sender(msg: Message) -> dict:
    from_name, from_addr = parseaddr(_clean(msg.get("From")))
    _, reply_to = parseaddr(_clean(msg.get("Reply-To")))
    _, return_path = parseaddr(_clean(msg.get("Return-Path")))
    return {
        "from_name": from_name or None,
        "from_address": from_addr.lower() or None,
        "reply_to": reply_to.lower() or None,
        "return_path": return_path.lower() or None,
        "to": _clean(msg.get("To")) or None,
        "subject": _clean(msg.get("Subject")) or None,
        "date": _clean(msg.get("Date")) or None,
        "message_id": _clean(msg.get("Message-ID")) or None,
    }


def header_findings(sender: dict, auth: dict, allowlist: set[str] | None = None) -> list[Finding]:
    allowlist = allowlist or set()
    out: list[Finding] = []
    dmarc_pass = auth.get("dmarc") == "pass"
    for mech in ("spf", "dkim", "dmarc"):
        res = auth.get(mech)
        if res is None:
            out.append(Finding(f"auth.{mech}_missing", "low", f"No {mech.upper()} result found"))
            continue
        sev = _AUTH_SEVERITY[mech].get(res)
        if not sev:
            continue
        msg = f"{mech.upper()} result: {res}"
        if dmarc_pass and mech in ("spf", "dkim"):
            # DMARC passed, so the other mechanism was aligned and valid. A broken
            # SPF/DKIM result alone is then typical for forwarding and mailing lists.
            sev, msg = "info", f"{msg} (DMARC passed via the other mechanism)"
        out.append(Finding(f"auth.{mech}_{res}", sev, msg, ("T1672",)))

    from_dom = domain_of(sender["from_address"])
    rp_dom = domain_of(sender["return_path"])
    rt_dom = domain_of(sender["reply_to"])
    if (
        from_dom
        and rp_dom
        and not dmarc_pass  # aligned DKIM covers bounces handled by a mailing service
        and base_domain(from_dom) != base_domain(rp_dom)
    ):
        out.append(
            Finding(
                "sender.return_path_mismatch",
                "low",
                f"Return-Path domain ({defang_domain(rp_dom)}) differs from From domain "
                f"({defang_domain(from_dom)}); "
                "common with mailing services, relevant together with failed DMARC",
                ("T1672",),
            )
        )
    if (
        from_dom
        and rt_dom
        and base_domain(from_dom) != base_domain(rt_dom)
        and not is_allowlisted(rt_dom, allowlist)  # e.g. your own ticket system
    ):
        out.append(
            Finding(
                "sender.reply_to_mismatch",
                "medium",
                f"Replies go to a different domain ({defang_domain(rt_dom)}) "
                f"than the sender ({defang_domain(from_dom)})",
                ("T1656",),
            )
        )
    name = sender["from_name"] or ""
    claimed = {base_domain(d) for d in _DOMAIN_IN_TEXT_RE.findall(name) if looks_like_domain(d)}
    if from_dom and claimed and base_domain(from_dom) not in claimed:
        out.append(
            Finding(
                "sender.display_name_spoof",
                "high",
                f"Display name references {', '.join(defang_domain(d) for d in sorted(claimed))} "
                f"but the address is at {defang_domain(from_dom)}",
                ("T1656", "T1566"),
            )
        )
    return out
