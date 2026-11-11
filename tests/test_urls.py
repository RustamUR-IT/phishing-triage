from phishtriage.urls import extract_urls, url_findings

HTML_MSG = """\
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<a href="https://login.evil.test/x">https://portal.example.com/login</a>
<a href="https://portal.example.com/help">portal.example.com</a>
<a href="mailto:a@example.com">mail</a>
<img src="cid:logo">
<a href="https://user.example.com@evil.test/">click</a>
"""


def test_text_extraction_strips_punctuation_and_handles_www(parse):
    msg = parse(
        "Subject: x\n\nGo to https://a.test/p?q=1. Or www.b.test, or (http://203.0.113.4:81/)."
    )
    urls, _ = extract_urls(msg, set())
    assert [u["url"] for u in urls] == [
        "https://a.test/p?q=1",
        "http://www.b.test",
        "http://203.0.113.4:81/",
    ]
    assert urls[0]["defanged"] == "hxxps://a[.]test/p?q=1"
    assert {"ip-literal", "port-81", "plain-http"} <= set(urls[2]["flags"])


def test_html_anchor_mismatch_and_ignored_schemes(parse):
    urls, mismatches = extract_urls(parse(HTML_MSG), {"example.com"})
    domains = {u["domain"] for u in urls}
    assert domains == {"login.evil.test", "portal.example.com", "evil.test"}
    assert len(mismatches) == 1
    assert mismatches[0]["shown_domain"] == "portal.example.com"
    assert mismatches[0]["actual_domain"] == "login.evil.test"
    allow = {u["domain"]: u["allowlisted"] for u in urls}
    assert allow["portal.example.com"] is True
    assert allow["login.evil.test"] is False


def test_url_findings(parse):
    urls, mismatches = extract_urls(parse(HTML_MSG), {"example.com"})
    ids = [f.id for f in url_findings(urls, mismatches)]
    assert "url.anchor_mismatch" in ids
    assert "url.userinfo" in ids
    assert "url.not_allowlisted" in ids


def test_punycode_and_shortener(parse):
    msg = parse("Subject: x\n\nhttps://xn--exmple-cua.test/ https://bit.ly/abc")
    urls, _ = extract_urls(msg, set())
    flags = {u["domain"]: u["flags"] for u in urls}
    assert "punycode/idn" in flags["xn--exmple-cua.test"]
    assert "shortener" in flags["bit.ly"]
