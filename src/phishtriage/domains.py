"""Domain helpers: defanging, approximate base-domain, allowlist matching."""

from __future__ import annotations

import re
from pathlib import Path

# Small set of two-label public suffixes so that e.g. shop.example.co.uk
# reduces to example.co.uk. Deliberately not a full Public Suffix List to keep
# the tool dependency-free; good enough for sender/URL comparison in triage.
_TWO_LABEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "co.nz",
    "com.br",
    "com.cn",
    "com.tr",
    "co.za",
    "com.mx",
    "co.at",
    "or.at",
    "ac.at",
    "gv.at",
}

_SCHEME_RE = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.-]*)://(?P<netloc>[^/?#]*)(?P<rest>.*)$", re.I)
_SCHEME_DEFANG = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_url(url: str) -> str:
    """http://evil.test/a.php -> hxxp://evil[.]test/a.php (path is left intact)."""
    m = _SCHEME_RE.match(url)
    if not m:
        return defang_domain(url)
    scheme = m["scheme"]
    scheme = _SCHEME_DEFANG.get(scheme.lower(), scheme)
    return f"{scheme}://{defang_domain(m['netloc'])}{m['rest']}"


def defang_address(addr: str) -> str:
    """user@evil.test -> user@evil[.]test"""
    if "@" not in addr:
        return addr
    local, _, domain = addr.rpartition("@")
    return f"{local}@{defang_domain(domain)}"


def normalize(domain: str | None) -> str:
    return (domain or "").strip().strip(".").lower()


def base_domain(domain: str | None) -> str:
    d = normalize(domain)
    labels = d.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_of(address: str | None) -> str:
    if not address or "@" not in address:
        return ""
    return normalize(address.rpartition("@")[2].strip(">"))


def load_allowlist(path: str | Path | None) -> set[str]:
    if path is None:
        return set()
    entries = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.add(normalize(line))
    return entries


def is_allowlisted(domain: str, allowlist: set[str]) -> bool:
    d = normalize(domain)
    return any(d == a or d.endswith("." + a) for a in allowlist)
