from phishtriage.headers import (
    classify_ip,
    header_findings,
    originating_ip,
    parse_authentication,
    parse_received,
    parse_sender,
)

MSG = """\
Received: from mx.example.com (mx.example.com [192.0.2.10])
\tby store.example.com; Tue, 10 Nov 2026 08:00:10 +0100
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=x.test;
\tdkim=fail header.d=x.test; dkim=pass header.d=y.test; dmarc=fail header.from=x.test
Authentication-Results: forged.test; spf=pass; dkim=pass; dmarc=pass
Received: from [10.0.0.5] (unknown [198.51.100.23])
\tby mx.example.com with ESMTP; Tue, 10 Nov 2026 07:00:00 +0000
From: "Support paypal.com" <support@x.test>
Reply-To: <attacker@freemail.test>
Return-Path: <bounce@x.test>
Subject: test

body
"""


def test_top_authentication_results_header_wins(parse):
    auth = parse_authentication(parse(MSG))
    # the lower header was added before reaching our MTA and is untrusted
    assert auth["spf"] == "fail"
    assert auth["dmarc"] == "fail"
    # one valid DKIM signature is enough
    assert auth["dkim"] == "pass"
    assert len(auth["authentication_results"]) == 2


def test_received_spf_fallback(parse):
    msg = parse("Received-SPF: softfail (domain does not designate)\nSubject: x\n\nb")
    assert parse_authentication(msg)["spf"] == "softfail"


def test_received_chain_order_delay_and_client_ip(parse):
    hops = parse_received(parse(MSG))
    assert [h["hop"] for h in hops] == [1, 2]
    # attacker-controlled HELO literal [10.0.0.5] must not be taken as client IP
    assert hops[0]["ip"] == "198.51.100.23"
    assert hops[0]["by"] == "mx.example.com"
    assert hops[1]["delay_seconds"] == 10
    assert originating_ip(hops) == "198.51.100.23"


def test_classify_ip():
    assert classify_ip("10.1.2.3") == "internal"
    assert classify_ip("203.0.113.5") == "documentation"
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("fe80::1") == "internal"


def test_sender_findings(parse):
    msg = parse(MSG)
    ids = {f.id for f in header_findings(parse_sender(msg), parse_authentication(msg))}
    assert {"auth.spf_fail", "auth.dmarc_fail", "sender.display_name_spoof"} <= ids
    assert "sender.reply_to_mismatch" in ids
    assert "sender.return_path_mismatch" not in ids  # same domain
    assert "auth.dkim_pass" not in ids


def test_clean_sender_has_no_findings(parse):
    msg = parse(
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        "From: Example News <news@example.org>\n"
        "Return-Path: <bounce@lists.example.org>\n\nhi"
    )
    assert header_findings(parse_sender(msg), parse_authentication(msg)) == []
