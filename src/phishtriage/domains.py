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
    # Shared hosting where every customer gets a subdomain (PSL "private" section).
    # Treating them as suffixes keeps victim.github.io and attacker.github.io apart.
    "github.io",
    "blogspot.com",
    "herokuapp.com",
    "azurewebsites.net",
    "sharepoint.com",
    "web.app",
    "firebaseapp.com",
    "appspot.com",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "vercel.app",
}

# TLDs that a domain mentioned in free text (e.g. a display name) must end in to
# count as a domain. Without this, "max.mustermann" or "j.doe" in a display name
# would be read as domains. Includes the RFC 2606/6761 reserved test TLDs.
KNOWN_TLDS = frozenset(
    """
    com net org info biz edu gov mil int io co ai app dev cloud online site shop store
    xyz top club live email tech eu de at ch li uk fr it es nl be lu dk se no fi pl cz sk
    hu ro bg gr pt ie ru ua tr us ca mx br ar au nz jp cn hk kr in sg za
    test example invalid localhost
    """.split()  # noqa: SIM905 - a word list is easier to review than 70 quoted strings
)

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


def looks_like_domain(text: str) -> bool:
    """True if text ends in a known TLD (used for domains found in free text)."""
    return normalize(text).rpartition(".")[2] in KNOWN_TLDS


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
