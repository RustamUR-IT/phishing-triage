import pytest

from phishtriage.domains import (
    base_domain,
    defang_address,
    defang_url,
    is_allowlisted,
    load_allowlist,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://evil.test/a.php?x=1.2", "hxxp://evil[.]test/a.php?x=1.2"),
        ("https://sub.evil.test:8443/", "hxxps://sub[.]evil[.]test:8443/"),
        ("HTTPS://Evil.test", "hxxps://Evil[.]test"),
        ("ftp://203.0.113.9/f", "fxp://203[.]0[.]113[.]9/f"),
    ],
)
def test_defang_url(url, expected):
    assert defang_url(url) == expected


def test_defang_address_keeps_local_part():
    assert defang_address("first.last@evil.test") == "first.last@evil[.]test"


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("mail.example.com", "example.com"),
        ("shop.example.co.uk", "example.co.uk"),
        ("Example.COM.", "example.com"),
    ],
)
def test_base_domain(domain, expected):
    assert base_domain(domain) == expected


def test_allowlist_matches_subdomains_but_not_lookalikes(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("# trusted\nexample.com\n\nexample.org  # partner\n")
    allow = load_allowlist(f)
    assert allow == {"example.com", "example.org"}
    assert is_allowlisted("cdn.example.com", allow)
    assert is_allowlisted("EXAMPLE.org", allow)
    assert not is_allowlisted("notexample.com", allow)
    assert not is_allowlisted("example.com.evil.test", allow)
    assert not is_allowlisted("examp1e.com", allow)
