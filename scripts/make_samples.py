"""Generate the synthetic sample messages in samples/.

Everything here is invented: domains use reserved TLDs (.test, RFC 2606) or
example.com/org, IPs come from documentation ranges (RFC 5737), and the
attachments are inert byte stubs, not malware. Re-run to rebuild samples:

    python scripts/make_samples.py
"""

from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"


def b64(data: bytes) -> str:
    enc = base64.b64encode(data).decode()
    return "\n".join(enc[i : i + 76] for i in range(0, len(enc), 76))


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 2, 9, 0, 0))
            zf.writestr(info, data)
    return buf.getvalue()


CREDENTIAL_PHISH = """\
Return-Path: <bounce-7781@mailer-7781.test>
Received: from mx01.example.com (mx01.example.com [192.0.2.10])
\tby mailstore.example.com with LMTP; Tue, 10 Nov 2026 08:14:07 +0100
Authentication-Results: mx01.example.com;
\tspf=softfail (domain of bounce-7781@mailer-7781.test does not designate 203.0.113.45 as permitted sender) smtp.mailfrom=bounce-7781@mailer-7781.test;
\tdkim=none (message not signed);
\tdmarc=fail (p=quarantine dis=quarantine) header.from=examp1e-it.test
Received: from mail.examp1e-it.test (unknown [203.0.113.45])
\tby mx01.example.com (Postfix) with ESMTP id 4F2A1C0011
\tfor <max.mustermann@example.com>; Tue, 10 Nov 2026 08:14:05 +0100
Received: from [10.13.37.5] (unknown [198.51.100.23])
\tby mail.examp1e-it.test with ESMTPSA id 77AB12;
\tTue, 10 Nov 2026 07:13:58 +0000
From: "IT-Servicedesk example.com" <servicedesk@examp1e-it.test>
Reply-To: helpdesk-reset@freemail.test
To: Max Mustermann <max.mustermann@example.com>
Subject: =?utf-8?q?Ihr_Postfach_ist_zu_98=25_voll_=E2=80=93_Aktion_erforderlich?=
Date: Tue, 10 Nov 2026 07:13:58 +0000
Message-ID: <20261110071358.77AB12@mail.examp1e-it.test>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b1_alt"

--b1_alt
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

Sehr geehrte/r Mitarbeiter/in,

Ihr Postfach hat 98 % der Speichergrenze erreicht. Bestätigen Sie Ihr Konto
innerhalb von 24 Stunden, sonst werden eingehende Nachrichten abgewiesen:

https://outlook.example.com/owa

Alternativ: https://xn--exmple-cua.test/reset oder https://bit.ly/3xQmpl3

IT-Servicedesk

--b1_alt
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: 8bit

<html><body>
<img src="https://cdn.example.com/brand/logo.png" alt="example.com">
<p>Sehr geehrte/r Mitarbeiter/in,</p>
<p>Ihr Postfach hat <b>98 %</b> der Speichergrenze erreicht. Bestätigen Sie Ihr
Konto innerhalb von 24 Stunden:</p>
<p><a href="https://examp1e-it.test/owa/auth/login.php?u=max.mustermann%40example.com">https://outlook.example.com/owa</a></p>
<p>Falls der Link nicht funktioniert: <a href="http://203.0.113.45:8080/verify">Konto bestätigen</a></p>
<p>IT-Servicedesk</p>
</body></html>

--b1_alt--
"""

# Inert stubs: correct magic bytes, no executable code.
FAKE_PE = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"synthetic test stub - not an executable\n"
FAKE_JS = b"// synthetic test file for phishtriage - does nothing\n"
FAKE_ZIP = zip_bytes({"Lieferschein_0117.js": FAKE_JS})
FAKE_DOCM = zip_bytes(
    {
        "[Content_Types].xml": b"<?xml version='1.0'?><Types/>",
        "word/document.xml": b"<?xml version='1.0'?><document/>",
        "word/vbaProject.bin": b"synthetic placeholder, no VBA code",
    }
)

ATTACHMENT_PHISH = f"""\
Return-Path: <rechnung@billing-portal.test>
Received: from mx01.example.com (mx01.example.com [192.0.2.10])
\tby mailstore.example.com with LMTP; Mon, 09 Nov 2026 14:02:41 +0100
Authentication-Results: mx01.example.com;
\tspf=pass smtp.mailfrom=billing-portal.test;
\tdkim=pass header.d=billing-portal.test;
\tdmarc=pass header.from=billing-portal.test
Received: from smtp.billing-portal.test (smtp.billing-portal.test [198.51.100.77])
\tby mx01.example.com (Postfix) with ESMTPS id 9C3D2E0042
\tfor <buchhaltung@example.com>; Mon, 09 Nov 2026 14:02:39 +0100
From: Buchhaltung Lieferant <rechnung@billing-portal.test>
To: buchhaltung@example.com
Subject: Offene Rechnung 2026-0117 - Zahlungserinnerung
Date: Mon, 09 Nov 2026 13:02:30 +0000
Message-ID: <inv-2026-0117@billing-portal.test>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b2_mix"

--b2_mix
Content-Type: text/plain; charset=utf-8

Guten Tag,

anbei die offene Rechnung sowie der Lieferschein. Bitte begleichen Sie den
Betrag bis Freitag. Die Rechnung mit Makros bitte "Inhalt aktivieren".

Mit freundlichen Grüßen

--b2_mix
Content-Type: application/pdf; name="Rechnung_2026-0117.pdf.exe"
Content-Disposition: attachment; filename="Rechnung_2026-0117.pdf.exe"
Content-Transfer-Encoding: base64

{b64(FAKE_PE)}

--b2_mix
Content-Type: application/pdf; name="Lieferschein_0117.pdf"
Content-Disposition: attachment; filename="Lieferschein_0117.pdf"
Content-Transfer-Encoding: base64

{b64(FAKE_ZIP)}

--b2_mix
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Rechnung_Details.docm"
Content-Disposition: attachment; filename="Rechnung_Details.docm"
Content-Transfer-Encoding: base64

{b64(FAKE_DOCM)}

--b2_mix--
"""

BENIGN_NEWSLETTER = """\
Return-Path: <news-bounces@lists.example.org>
Received: from mx01.example.com (mx01.example.com [192.0.2.10])
\tby mailstore.example.com with LMTP; Wed, 04 Nov 2026 10:00:09 +0100
Authentication-Results: mx01.example.com;
\tspf=pass smtp.mailfrom=lists.example.org;
\tdkim=pass header.d=example.org header.s=news2026;
\tdmarc=pass (p=reject) header.from=example.org
Received: from out.lists.example.org (out.lists.example.org [198.51.100.5])
\tby mx01.example.com (Postfix) with ESMTPS id 1A2B3C4D5E
\tfor <max.mustermann@example.com>; Wed, 04 Nov 2026 10:00:07 +0100
From: Example Org Newsletter <news@example.org>
To: max.mustermann@example.com
Subject: Monatlicher Newsletter November 2026
Date: Wed, 04 Nov 2026 09:00:00 +0000
Message-ID: <nl-2026-11@example.org>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<h1>Neuigkeiten im November</h1>
<p>Alle Artikel finden Sie auf <a href="https://www.example.org/news/2026-11">www.example.org</a>.</p>
<p><a href="https://www.example.org/unsubscribe">Abmelden</a></p>
</body></html>
"""


def main() -> None:
    OUT.mkdir(exist_ok=True)
    samples = {
        "credential_phish.eml": CREDENTIAL_PHISH,
        "attachment_phish.eml": ATTACHMENT_PHISH,
        "benign_newsletter.eml": BENIGN_NEWSLETTER,
    }
    for name, text in samples.items():
        (OUT / name).write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
        print(f"wrote samples/{name}")


if __name__ == "__main__":
    main()
