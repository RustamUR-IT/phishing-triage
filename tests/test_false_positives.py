"""Regression tests for false positives found while tuning the rules.

Each test pairs a benign message that used to raise a finding with the
malicious variant that must still be caught, so a fix cannot silently turn
into a blind spot. docs/RULES.md links each rule to its test here.
"""

import io
import zipfile

from phishtriage.attachments import attachment_findings, detect_type
from phishtriage.domains import base_domain
from phishtriage.enrich import enrich
from phishtriage.headers import header_findings, parse_authentication, parse_sender
from phishtriage.urls import extract_urls, url_findings


def _header_ids(parse, headers: str, allowlist=None) -> dict[str, str]:
    msg = parse(headers + "\n\nbody")
    found = header_findings(parse_sender(msg), parse_authentication(msg), allowlist)
    return {f.id: f.severity for f in found}


def _url_ids(parse, html: str, allowlist=frozenset()) -> set[str]:
    msg = parse(f"MIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n{html}")
    urls, mismatches = extract_urls(msg, set(allowlist))
    return {f.id for f in url_findings(urls, mismatches)}


def _attachment(ext: str, data: bytes) -> dict:
    return {"filename": f"file.{ext}", "extension": ext, **detect_type(data)}


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


# --- authentication -------------------------------------------------------


def test_forwarded_mail_with_dmarc_pass_does_not_score_spf_fail(parse):
    forwarded = "Authentication-Results: mx; spf=fail; dkim=pass; dmarc=pass"
    assert _header_ids(parse, forwarded)["auth.spf_fail"] == "info"
    spoofed = "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail"
    ids = _header_ids(parse, spoofed)
    assert ids["auth.spf_fail"] == "medium"
    assert ids["auth.dmarc_fail"] == "high"


# --- sender ---------------------------------------------------------------


def test_display_name_with_dotted_person_name_is_not_a_domain(parse):
    benign = "From: max.mustermann <max@example.com>"
    assert "sender.display_name_spoof" not in _header_ids(parse, benign)
    spoof = 'From: "Support paypal.com" <support@x.test>'
    assert "sender.display_name_spoof" in _header_ids(parse, spoof)


def test_return_path_of_mailing_service_is_ignored_when_dmarc_passes(parse):
    newsletter = (
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        "From: News <news@example.org>\nReturn-Path: <bounce-1@esp.test>"
    )
    assert "sender.return_path_mismatch" not in _header_ids(parse, newsletter)
    spoof = (
        "Authentication-Results: mx; spf=pass; dkim=none; dmarc=fail\n"
        "From: News <news@example.org>\nReturn-Path: <bounce-1@esp.test>"
    )
    assert "sender.return_path_mismatch" in _header_ids(parse, spoof)


def test_reply_to_own_ticket_system_is_not_flagged_when_allowlisted(parse):
    headers = "From: IT <it@example.com>\nReply-To: <help@tickets.test>"
    assert "sender.reply_to_mismatch" not in _header_ids(parse, headers, {"tickets.test"})
    assert "sender.reply_to_mismatch" in _header_ids(parse, headers, set())


def test_reply_to_subdomain_of_sender_is_not_flagged(parse):
    headers = "From: Shop <shop@example.com>\nReply-To: <service@support.example.com>"
    assert "sender.reply_to_mismatch" not in _header_ids(parse, headers)


# --- URLs -----------------------------------------------------------------


def test_link_text_without_www_is_not_a_mismatch():
    assert base_domain("www.example.com") == base_domain("example.com")


def test_anchor_text_www_and_target_apex_are_the_same_site(parse):
    assert "url.anchor_mismatch" not in _url_ids(
        parse, '<a href="https://example.com/a">www.example.com</a>'
    )
    assert "url.anchor_mismatch" in _url_ids(
        parse, '<a href="https://example.com.evil.test/a">www.example.com</a>'
    )


def test_allowlisted_click_tracker_is_not_a_mismatch(parse):
    html = '<a href="https://click.tracker.test/r?id=1">www.example.com</a>'
    assert "url.anchor_mismatch" not in _url_ids(parse, html, {"tracker.test"})
    assert "url.anchor_mismatch" in _url_ids(parse, html)


def test_shared_hosting_subdomains_are_different_sites(parse):
    html = '<a href="https://attacker.github.io/">victim.github.io</a>'
    assert "url.anchor_mismatch" in _url_ids(parse, html)


def test_allowlisted_idn_domain_is_not_flagged_as_homograph(parse):
    html = '<a href="https://xn--mller-kva.example/">Shop</a>'
    assert "url.punycode" not in _url_ids(parse, html, {"xn--mller-kva.example"})
    assert "url.punycode" in _url_ids(parse, html)


def test_plain_http_alone_is_not_a_finding(parse):
    assert _url_ids(parse, '<a href="http://example.com/">x</a>', {"example.com"}) == set()


# --- attachments ----------------------------------------------------------


def test_opendocument_and_epub_are_zip_but_not_a_mismatch():
    for ext in ("odt", "ods", "epub"):
        att = _attachment(ext, _zip({"mimetype": b"application/x"}))
        assert attachment_findings([att]) == [], ext
    fake_pdf = _attachment("pdf", _zip({"a.txt": b"x"}))
    assert "att.type_mismatch" in {f.id for f in attachment_findings([fake_pdf])}


def test_forwarded_outlook_item_is_info_not_medium():
    ole2 = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    msg = {f.id: f.severity for f in attachment_findings([_attachment("msg", ole2)])}
    assert msg == {"att.legacy_office": "info"}
    doc = {f.id: f.severity for f in attachment_findings([_attachment("doc", ole2)])}
    assert doc == {"att.legacy_office": "medium"}


def test_csv_and_txt_are_not_reported_as_type_mismatch():
    for ext in ("csv", "txt", "log"):
        assert attachment_findings([_attachment(ext, b"a;b;c\n1;2;3\n")]) == [], ext


def test_version_number_in_filename_is_not_a_double_extension():
    att = {**_attachment("pdf", b"%PDF-1.7\n"), "filename": "Bericht v2.1.pdf"}
    assert attachment_findings([att]) == []


# --- enrichment -----------------------------------------------------------


def _vt(malicious: int):
    stats = {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious}}}}
    return lambda url, headers: (200, stats)


def test_single_virustotal_engine_is_low_not_high():
    _, findings = enrich(["a" * 64], [], env={"VT_API_KEY": "k"}, fetch=_vt(1))
    assert [(f.id, f.severity) for f in findings] == [("intel.vt_malicious", "low")]
    _, findings = enrich(["a" * 64], [], env={"VT_API_KEY": "k"}, fetch=_vt(5))
    assert [(f.id, f.severity) for f in findings] == [("intel.vt_malicious", "high")]
