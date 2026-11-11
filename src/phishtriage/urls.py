"""URL extraction from text and HTML bodies, defanging and allowlist checks."""

from __future__ import annotations

import ipaddress
import re
from email.message import EmailMessage
from html.parser import HTMLParser
from urllib.parse import urlsplit

from phishtriage.domains import defang_domain, defang_url, is_allowlisted, normalize
from phishtriage.findings import Finding

_URL_RE = re.compile(r"""(?:https?|ftp)://[^\s<>"'(){}\[\]]+|\bwww\.[^\s<>"'(){}\[\]]+""", re.I)
_TRAILING = ".,;:!?'\""
_LOOKS_LIKE_URL = re.compile(
    r"^\s*(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?\s*$", re.I
)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "rb.gy",
    "t.ly",
    "shorturl.at",
    "s.id",
    "tiny.cc",
}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []  # (url, source)
        self.anchors: list[tuple[str, str]] = []  # (href, visible text)
        self.text: list[str] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if value and name in ("href", "src", "action", "background"):
                self.links.append((value.strip(), f"html-{name}"))
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._anchor_text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.anchors.append((self._href.strip(), "".join(self._anchor_text).strip()))
            self._href = None

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def _body_parts(msg: EmailMessage):
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        yield ctype, content


def _from_text(text: str) -> list[str]:
    found = []
    for m in _URL_RE.findall(text):
        url = m.rstrip(_TRAILING)
        if url.lower().startswith("www."):
            url = "http://" + url
        found.append(url)
    return found


def _host(url: str) -> str:
    try:
        return normalize(urlsplit(url).hostname)
    except ValueError:
        return ""


def _url_flags(url: str, host: str) -> list[str]:
    flags = []
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return ["malformed"]
    try:
        ipaddress.ip_address(host)
        flags.append("ip-literal")
    except ValueError:
        pass
    if any(label.startswith("xn--") for label in host.split(".")) or not host.isascii():
        flags.append("punycode/idn")
    if host in SHORTENERS:
        flags.append("shortener")
    if "@" in parts.netloc:
        flags.append("userinfo-in-url")
    if port and port not in (80, 443):
        flags.append(f"port-{port}")
    if parts.scheme.lower() == "http":
        flags.append("plain-http")
    return flags


def extract_urls(msg: EmailMessage, allowlist: set[str]) -> tuple[list[dict], list[dict]]:
    """Return (urls, anchor_mismatches)."""
    seen: dict[str, dict] = {}
    mismatches: list[dict] = []

    def add(url: str, source: str) -> None:
        if not re.match(r"^(?:https?|ftp)://", url, re.I):
            return  # mailto:, cid:, tel:, relative links
        host = _host(url)
        if not host:
            return
        entry = seen.get(url)
        if entry is None:
            entry = seen[url] = {
                "url": url,
                "defanged": defang_url(url),
                "domain": host,
                "domain_defanged": defang_domain(host),
                "allowlisted": is_allowlisted(host, allowlist),
                "flags": _url_flags(url, host),
                "sources": [],
            }
        if source not in entry["sources"]:
            entry["sources"].append(source)

    for ctype, content in _body_parts(msg):
        if ctype == "text/html":
            parser = _LinkParser()
            parser.feed(content)
            for url, source in parser.links:
                add(url, source)
            for url in _from_text(" ".join(parser.text)):
                add(url, "html-text")
            for href, text in parser.anchors:
                m = _LOOKS_LIKE_URL.match(text)
                href_host = _host(href)
                if not (m and href_host):
                    continue
                shown = normalize(m.group(1))
                if shown != href_host and not href_host.endswith("." + shown):
                    mismatches.append(
                        {
                            "shown": text,
                            "shown_domain": shown,
                            "actual": defang_url(href),
                            "actual_domain": href_host,
                        }
                    )
        else:
            for url in _from_text(content):
                add(url, "text")
    return list(seen.values()), mismatches


def url_findings(urls: list[dict], mismatches: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    link = ("T1566.002", "T1204.001")
    for m in mismatches:
        out.append(
            Finding(
                "url.anchor_mismatch",
                "high",
                f"Link text shows {defang_domain(m['shown_domain'])} "
                f"but points to {defang_domain(m['actual_domain'])}",
                ("T1566.002", "T1598.003", "T1656"),
            )
        )
    rules = {
        "ip-literal": ("url.ip_literal", "medium", "URL uses a raw IP address"),
        "punycode/idn": ("url.punycode", "medium", "Punycode/IDN domain (possible homograph)"),
        "shortener": ("url.shortener", "low", "URL shortener hides the real target"),
        "userinfo-in-url": ("url.userinfo", "high", "URL contains user@host (obscures target)"),
    }
    for url in urls:
        for flag in url["flags"]:
            if flag in rules:
                fid, sev, msg = rules[flag]
                out.append(Finding(fid, sev, f"{msg}: {url['defanged']}", link))
            elif flag.startswith("port-"):
                out.append(
                    Finding(
                        "url.nonstandard_port", "low", f"Non-standard port: {url['defanged']}", link
                    )
                )
    foreign = sorted({u["domain"] for u in urls if not u["allowlisted"]})
    if foreign:
        out.append(
            Finding(
                "url.not_allowlisted",
                "info",
                f"{len(foreign)} linked domain(s) not on allowlist: "
                + ", ".join(defang_domain(d) for d in foreign),
                link,
            )
        )
    return out
