import io
import zipfile

import pytest

from phishtriage.attachments import attachment_findings, detect_type


def _zip(files, encrypted=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypted:  # set general-purpose bit 0 in each central directory entry
        pos = raw.find(b"PK\x01\x02")
        while pos != -1:
            raw[pos + 8] |= 0x1
            pos = raw.find(b"PK\x01\x02", pos + 4)
    return bytes(raw)


def _att(name, data):
    ext = name.rsplit(".", 1)[-1].lower()
    return {"filename": name, "extension": ext, "sha256": "0" * 64, **detect_type(data)}


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (b"%PDF-1.7\n...", "pdf"),
        (b"MZ\x90\x00", "pe-executable"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8, "ole2"),
        (b"\x00" * 0x8001 + b"CD001", "iso-image"),
        (b"\xef\xbb\xbf  <!DOCTYPE html><html>", "html"),
        (b"plain old text", "text"),
        (b"\x00\x01\x02\xff\xfe", "unknown"),
    ],
)
def test_detect_type_by_magic(data, kind):
    assert detect_type(data)["type"] == kind


def test_ooxml_with_macros_is_detected():
    data = _zip(
        {"[Content_Types].xml": b"x", "word/document.xml": b"x", "word/vbaProject.bin": b"x"}
    )
    d = detect_type(data)
    assert d["type"] == "ooxml-word"
    assert d["archive"]["macros"] is True
    assert "docx" in d["expected_extensions"]


def test_pdf_that_is_really_a_zip_with_script():
    att = _att("invoice.pdf", _zip({"invoice.js": b"//"}))
    ids = {f.id for f in attachment_findings([att])}
    assert {"att.type_mismatch", "att.archive_payload"} <= ids


def test_double_extension_and_rtlo():
    findings = attachment_findings([_att("scan.pdf.exe", b"MZ"), _att("cod‮exe.pdf", b"MZ")])
    ids = [f.id for f in findings]
    assert "att.double_extension" in ids
    assert "att.rtlo" in ids
    assert any("T1036.007" in f.attack for f in findings)


def test_encrypted_archive_flag():
    att = _att("docs.zip", _zip({"a.txt": b"x"}, encrypted=True))
    assert "att.encrypted_archive" in {f.id for f in attachment_findings([att])}


def test_harmless_pdf_has_no_findings():
    assert attachment_findings([_att("report.pdf", b"%PDF-1.4 hello")]) == []
