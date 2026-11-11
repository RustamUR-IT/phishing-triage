"""Command line interface: phishtriage message.eml [options]"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from phishtriage import __version__
from phishtriage.domains import load_allowlist
from phishtriage.report import to_json, to_markdown
from phishtriage.triage import analyze


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishtriage",
        description="Triage a suspicious .eml file and print a ticket-ready report.",
    )
    p.add_argument("eml", type=Path, help="path to the .eml file")
    p.add_argument(
        "-f", "--format", choices=("md", "json"), default="md", help="stdout format (default: md)"
    )
    p.add_argument(
        "-o", "--out-dir", type=Path, help="also write <name>.md and <name>.json into this folder"
    )
    p.add_argument("-a", "--allowlist", type=Path, help="file with trusted domains, one per line")
    p.add_argument(
        "--enrich",
        action="store_true",
        help="look up attachment hashes (VirusTotal) and public IPs (AbuseIPDB); "
        "keys from VT_API_KEY / ABUSEIPDB_API_KEY",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        raw = args.eml.read_bytes()
        allowlist = load_allowlist(args.allowlist)
    except OSError as exc:
        print(f"phishtriage: {exc}", file=sys.stderr)
        return 2

    report = analyze(raw, source=args.eml.name, allowlist=allowlist, do_enrich=args.enrich)
    rendered = {"md": to_markdown(report), "json": to_json(report)}

    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        for ext, text in rendered.items():
            (args.out_dir / f"{args.eml.stem}.{ext}").write_text(text + "\n", encoding="utf-8")
    sys.stdout.write(rendered[args.format] + "\n")
    return 0
