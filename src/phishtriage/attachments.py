"""Attachment hashing and file type detection from magic bytes."""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from email.message import EmailMessage
from pathlib import PurePosixPath

from phishtriage.findings import Finding

# (offset, magic, label, expected extensions)
_SIGNATURES: list[tuple[int, bytes, str, frozenset[str]]] = [
    (0, b"%PDF-", "pdf", frozenset({"pdf"})),
    (0, b"MZ", "pe-executable", frozenset({"exe", "dll", "scr", "com", "cpl", "sys"})),
    (0, b"\x7fELF", "elf-executable", frozenset({"elf", "so", "bin"})),
    (
        0,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "ole2",
        frozenset({"doc", "xls", "ppt", "msi", "msg"}),
    ),
    (0, b"PK\x03\x04", "zip", frozenset({"zip"})),
    (0, b"PK\x05\x06", "zip", frozenset({"zip"})),
    (0, b"Rar!\x1a\x07", "rar", frozenset({"rar"})),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", frozenset({"7z"})),
    (0, b"\x1f\x8b", "gzip", frozenset({"gz", "tgz"})),
    (0, b"MSCF", "cab", frozenset({"cab"})),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "lnk-shortcut", frozenset({"lnk"})),
    (0x8001, b"CD001", "iso-image", frozenset({"iso", "img"})),
    (0, b"{\\rtf", "rtf", frozenset({"rtf", "doc"})),
    (0, b"\x89PNG\r\n\x1a\n", "png", frozenset({"png"})),
    (0, b"\xff\xd8\xff", "jpeg", frozenset({"jpg", "jpeg"})),
    (0, b"GIF87a", "gif", frozenset({"gif"})),
    (0, b"GIF89a", "gif", frozenset({"gif"})),
]

_OOXML = {
    "word/": ("ooxml-word", frozenset({"docx", "docm", "dotx", "dotm"})),
    "xl/": ("ooxml-excel", frozenset({"xlsx", "xlsm", "xltx", "xltm"})),
    "ppt/": ("ooxml-powerpoint", frozenset({"pptx", "pptm", "potx", "potm"})),
}

DANGEROUS_EXTENSIONS = frozenset(
    {
        "exe",
        "scr",
        "com",
        "pif",
        "cpl",
        "msi",
        "dll",
        "bat",
        "cmd",
        "ps1",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "hta",
        "lnk",
        "iso",
        "img",
        "vhd",
        "vhdx",
        "jar",
        "one",
        "html",
        "htm",
        "shtml",
        "svg",
        "docm",
        "xlsm",
        "pptm",
        "dotm",
        "xlam",
        "reg",
        "url",
    }
)
_DANGEROUS_TYPES = {
    "pe-executable",
    "elf-executable",
    "lnk-shortcut",
    "iso-image",
    "html",
    "script",
}
_DECOY_EXTENSIONS = r"pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|zip|rtf"
_DOUBLE_EXT_RE = re.compile(rf"\.(?:{_DECOY_EXTENSIONS})\s*\.([a-z0-9]{{1,5}})$", re.I)
_RTLO = "‮"


def _text_type(data: bytes) -> tuple[str, frozenset[str]] | None:
    head = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith((b"<!doctype html", b"<html")) or b"<script" in head:
        return "html", frozenset({"html", "htm", "shtml"})
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "svg", frozenset({"svg"})
    if head.startswith(b"#!"):
        return "script", frozenset({"sh", "py", "pl"})
    try:
        data[:4096].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return "text", frozenset()  # plain text: extension can't be verified


def _inspect_zip(data: bytes) -> dict:
    info: dict = {"members": [], "encrypted": False, "macros": False, "office": None}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError):
        return info
    names = [i.filename for i in infos]
    info["members"] = names[:50]
    info["encrypted"] = any(i.flag_bits & 0x1 for i in infos)
    info["macros"] = any(n.lower().endswith("vbaproject.bin") for n in names)
    if "[Content_Types].xml" in names:
        for prefix, (label, exts) in _OOXML.items():
            if any(n.startswith(prefix) for n in names):
                info["office"] = (label, exts)
                break
    return info


def detect_type(data: bytes) -> dict:
    """Identify content by magic bytes. Returns label, expected extensions and extras."""
    for offset, magic, label, exts in _SIGNATURES:
        if data[offset : offset + len(magic)] == magic:
            result = {"type": label, "expected_extensions": sorted(exts)}
            if label == "zip":
                z = _inspect_zip(data)
                if z["office"]:
                    result["type"], office_exts = z["office"]
                    result["expected_extensions"] = sorted(office_exts)
                result["archive"] = {k: v for k, v in z.items() if k != "office"}
            return result
    text = _text_type(data)
    if text:
        return {"type": text[0], "expected_extensions": sorted(text[1])}
    return {"type": "unknown", "expected_extensions": []}


def _extension(filename: str) -> str:
    return PurePosixPath(filename.replace(_RTLO, "")).suffix.lower().lstrip(".")


def analyze_attachments(msg: EmailMessage) -> list[dict]:
    results = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename and part.get_content_disposition() != "attachment":
            continue
        data = part.get_payload(decode=True) or b""
        detected = detect_type(data)
        filename = filename or "(unnamed)"
        results.append(
            {
                "filename": filename,
                "declared_content_type": part.get_content_type(),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "extension": _extension(filename),
                **detected,
            }
        )
    return results


def attachment_findings(attachments: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    deliver = ("T1566.001", "T1204.002")
    for a in attachments:
        name, ext, kind = a["filename"], a["extension"], a["type"]
        expected = a["expected_extensions"]
        if _RTLO in name:
            out.append(
                Finding(
                    "att.rtlo",
                    "high",
                    f"Filename uses right-to-left override: {name!r}",
                    ("T1036.002", *deliver),
                )
            )
        m = _DOUBLE_EXT_RE.search(name.replace(_RTLO, ""))
        if m and m.group(1).lower() in DANGEROUS_EXTENSIONS:
            out.append(
                Finding(
                    "att.double_extension",
                    "high",
                    f"Double extension: {name}",
                    ("T1036.007", *deliver),
                )
            )
        if expected and ext not in expected:
            sev = "high" if kind in _DANGEROUS_TYPES else "medium"
            out.append(
                Finding(
                    "att.type_mismatch",
                    sev,
                    f"{name}: extension .{ext or '?'} but content is {kind}",
                    ("T1036.008", *deliver),
                )
            )
        if kind in _DANGEROUS_TYPES or ext in DANGEROUS_EXTENSIONS:
            techniques = deliver
            if kind == "html" or ext in ("html", "htm", "shtml", "svg"):
                techniques = ("T1027.006", *deliver)
            elif kind == "iso-image" or ext in ("iso", "img", "vhd", "vhdx"):
                techniques = ("T1553.005", *deliver)
            out.append(
                Finding(
                    "att.dangerous_type",
                    "high",
                    f"{name}: high-risk file type ({kind}, .{ext})",
                    techniques,
                )
            )
        archive = a.get("archive") or {}
        if archive.get("macros"):
            out.append(Finding("att.macros", "high", f"{name}: contains VBA macros", deliver))
        if kind == "ole2":
            out.append(
                Finding(
                    "att.legacy_office",
                    "medium",
                    f"{name}: legacy OLE2 Office/MSI container (macros possible)",
                    deliver,
                )
            )
        if archive.get("encrypted"):
            out.append(
                Finding(
                    "att.encrypted_archive",
                    "medium",
                    f"{name}: password-protected archive (evades scanning)",
                    ("T1027.013", *deliver),
                )
            )
        risky = [
            n
            for n in archive.get("members", [])
            if _extension(n) in DANGEROUS_EXTENSIONS and not n.lower().endswith(".bin")
        ]
        if risky and kind == "zip":
            out.append(
                Finding(
                    "att.archive_payload",
                    "high",
                    f"{name}: archive contains high-risk file(s): {', '.join(risky[:5])}",
                    deliver,
                )
            )
    return out
