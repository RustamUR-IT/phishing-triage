# phishtriage

[![CI](https://github.com/RustamUR-IT/phishing-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/RustamUR-IT/phishing-triage/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
![Dependencies](https://img.shields.io/badge/runtime%20deps-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**Automates the first five minutes of phishing triage.** Give it a reported `.eml`, get back a
defanged, ticket-ready report in Markdown and JSON: sender and authentication results, the
Received chain, every URL checked against your allowlist, attachments hashed and typed by magic
bytes, and each finding tagged with MITRE ATT&CK.

```bash
phishtriage samples/credential_phish.eml --allowlist allowlist.example.txt
```

> ## Phishing triage: Ihr Postfach ist zu 98% voll – Aktion erforderlich
>
> **Verdict:** LIKELY MALICIOUS (score 29, 12 findings) · triage hint, not a final classification
>
> | Field | Value |
> |---|---|
> | From | "IT-Servicedesk example[.]com" <servicedesk@examp1e-it[.]test> |
> | Reply-To | helpdesk-reset@freemail[.]test |
> | Return-Path | bounce-7781@mailer-7781[.]test |
> | SPF / DKIM / DMARC | softfail / none / fail |
> | Originating IP | 198.51.100.23 |
>
> ### Findings
>
> | Sev | Finding | ATT&CK |
> |---|---|---|
> | HIGH | DMARC result: fail | T1672 |
> | HIGH | Display name references example[.]com but the address is at examp1e-it[.]test | T1656, T1566 |
> | HIGH | Link text shows outlook[.]example[.]com but points to examp1e-it[.]test | T1566.002, T1598.003, T1656 |
> | MED | Replies go to a different domain (freemail[.]test) than the sender (examp1e-it[.]test) | T1656 |
> | MED | URL uses a raw IP address: hxxp://203[.]0[.]113[.]45:8080/verify | T1566.002, T1204.001 |
> | MED | Punycode/IDN domain (possible homograph): hxxps://xn--exmple-cua[.]test/reset | T1566.002, T1204.001 |
> | LOW | URL shortener hides the real target: hxxps://bit[.]ly/3xQmpl3 | T1566.002, T1204.001 |
> | … | *(5 more)* | |
>
> ### Received chain (origin first)
>
> | # | From | IP | By | Time | Delay |
> |---|---|---|---|---|---|
> | 1 | [10[.]13[.]37[.]5] | 198.51.100.23 (documentation) | mail[.]examp1e-it[.]test | 2026-11-10T07:13:58+00:00 | - |
> | 2 | mail[.]examp1e-it[.]test | 203.0.113.45 (documentation) | mx01[.]example[.]com | 2026-11-10T08:14:05+01:00 | 7s |
> | 3 | mx01[.]example[.]com | 192.0.2.10 (documentation) | mailstore[.]example[.]com | 2026-11-10T08:14:07+01:00 | 2s |

The attachment sample (`samples/attachment_phish.eml`) passes SPF, DKIM and DMARC, and is still
flagged, which is the point of looking past authentication:

```text
| HIGH | Lieferschein_0117.pdf: archive contains high-risk file(s): Lieferschein_0117.js  | T1566.001, T1204.002            |
| HIGH | Rechnung_2026-0117.pdf.exe: high-risk file type (pe-executable, .exe)            | T1566.001, T1204.002            |
| HIGH | Rechnung_Details.docm: high-risk file type (ooxml-word, .docm)                   | T1566.001, T1204.002            |
| HIGH | Double extension: Rechnung_2026-0117.pdf.exe                                     | T1036.007, T1566.001, T1204.002 |
| HIGH | Rechnung_Details.docm: contains VBA macros                                       | T1566.001, T1204.002            |
| MED  | Lieferschein_0117.pdf: extension .pdf but content is zip                         | T1036.008, T1566.001, T1204.002 |
```

The same data as JSON (`-f json`), for SOAR playbooks or scripts:

```json
{
  "summary": { "verdict": "likely malicious", "score": 29, "findings": 12, "urls": 6,
               "attachments": 0, "originating_ip": "198.51.100.23" },
  "findings": [
    { "id": "auth.dmarc_fail", "severity": "high", "message": "DMARC result: fail",
      "attack": ["T1672"] }
  ]
}
```

## What it checks

| Area | Checks |
|---|---|
| **Sender** | From, Reply-To, Return-Path, Subject, Message-ID. Reply-To and Return-Path domains compared with From, display name naming a different domain |
| **Authentication** | SPF, DKIM and DMARC from the top `Authentication-Results` header (the one your MTA added), `Received-SPF` as a fallback |
| **Received chain** | Hops ordered origin → mailbox, client IP as recorded by the receiving MTA (not the spoofable HELO), per-hop delay, internal/public IP classification, originating IP |
| **URLs** | Extracted from text and HTML (`href`, `src`, `action`, visible text), deduplicated and defanged (`hxxps://evil[.]test`). Allowlist check that matches subdomains but not lookalikes. Flags link text ≠ target, raw IPs, punycode, shorteners, `user@host` URLs, unusual ports |
| **Attachments** | SHA-256 and size. File type from magic bytes (PE, ELF, OLE2, ZIP, OOXML, RAR, 7z, ISO, LNK, RTF, PDF, HTML, SVG, images). Extension mismatch, double extensions, right-to-left override, VBA macros, encrypted archives, risky files inside ZIPs |
| **Enrichment** *(opt-in)* | Attachment hashes against VirusTotal, public relay IPs against AbuseIPDB |

The score is a sum of severities (high 5, medium 3, low 1) and the verdict is a triage hint to sort
the queue. It does not replace an analyst.

## MITRE ATT&CK mapping

Every finding carries the techniques it is evidence for. The report ends with the deduplicated list.

| Technique | Triggered by |
|---|---|
| [T1566](https://attack.mitre.org/techniques/T1566/) Phishing | Display-name impersonation, AbuseIPDB-reported relay |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) Spearphishing Attachment | Every attachment finding, VirusTotal detections |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) Spearphishing Link | Suspicious URLs, link text ≠ target |
| [T1598.003](https://attack.mitre.org/techniques/T1598/003/) Phishing for Information: Spearphishing Link | Link text ≠ target (credential harvesting pattern) |
| [T1656](https://attack.mitre.org/techniques/T1656/) Impersonation | Display name naming a foreign domain, Reply-To redirect, disguised links |
| [T1672](https://attack.mitre.org/techniques/T1672/) Email Spoofing | SPF/DKIM/DMARC failures, Return-Path mismatch |
| [T1036.002](https://attack.mitre.org/techniques/T1036/002/) Right-to-Left Override | U+202E in attachment filename |
| [T1036.007](https://attack.mitre.org/techniques/T1036/007/) Double File Extension | `invoice.pdf.exe` |
| [T1036.008](https://attack.mitre.org/techniques/T1036/008/) Masquerade File Type | Extension does not match magic bytes |
| [T1027.006](https://attack.mitre.org/techniques/T1027/006/) HTML Smuggling | HTML/SVG attachments |
| [T1027.013](https://attack.mitre.org/techniques/T1027/013/) Encrypted/Encoded File | Password-protected archives |
| [T1553.005](https://attack.mitre.org/techniques/T1553/005/) Mark-of-the-Web Bypass | ISO/IMG/VHD attachments |
| [T1204.001](https://attack.mitre.org/techniques/T1204/001/) / [.002](https://attack.mitre.org/techniques/T1204/002/) User Execution | Malicious link / malicious file findings |

## Install and use

Requires Python 3.11+. No third-party runtime dependencies.

```bash
git clone https://github.com/RustamUR-IT/phishing-triage.git && cd phishing-triage
```

```bash
pip install .
```

```bash
# Markdown to stdout (paste into the ticket)
phishtriage suspicious.eml --allowlist allowlist.txt

# JSON to stdout
phishtriage suspicious.eml -f json

# Write suspicious.md and suspicious.json into reports/
phishtriage suspicious.eml -a allowlist.txt -o reports/
```

`python -m phishtriage` works as well. The allowlist is one domain per line, `#` starts a comment,
subdomains match automatically (see [`allowlist.example.txt`](allowlist.example.txt)).

### Enrichment

```bash
export VT_API_KEY=...          # VirusTotal v3
export ABUSEIPDB_API_KEY=...   # AbuseIPDB v2
phishtriage suspicious.eml --enrich
```

Keys are read from environment variables only and never written to the report. A missing key skips
that source. Only SHA-256 hashes and public relay IPs are sent; no message content, URLs or
addresses leave the machine. Internal and documentation-range IPs are never looked up.

## Endpoint hunt: after the attachment is opened

[`hunting/`](hunting/) picks up where the mail report ends. It has a Sigma hunting query (plus
Splunk and Defender XDR KQL versions) for `wscript`/`cscript`/`mshta` started on a file from an
archive, a download or a mail attachment, and for the shell or PowerShell that file starts. It
also has a harmless PowerShell simulation of that chain for your own lab VM, and an offline
runner that checks the exported Sysmon events:

```bash
python hunting/hunt.py hunting/testdata/simulated_attack.jsonl --expect-chain
```

Setup, run steps, tuning and limits are in [`hunting/README.md`](hunting/README.md).

## Design notes and limits

- **Static analysis only.** Nothing is opened, rendered, detonated or fetched (apart from the
  opt-in API lookups). URLs are never visited.
- **Trust boundary.** Only the top `Authentication-Results` header is used, because headers below
  it may have been forged by the sender. In production, pin this to your own `authserv-id`.
- **Base domains** use a small built-in suffix list instead of the full Public Suffix List, to stay
  dependency-free. Good enough for sender comparisons, not for every ccTLD.
- **Not a verdict engine.** The heuristics favour recall; a legitimate newsletter sent through a
  mailing service can show a Return-Path mismatch (rated *low* for that reason).

## Test data notice

This repository contains **only synthetic test data**. The samples in [`samples/`](samples/) were
written from scratch and are generated by [`scripts/make_samples.py`](scripts/make_samples.py),
using reserved domains (`.test`, `example.com`), RFC 5737 documentation IPs and inert attachment
stubs. No real mail, customer data, employer data, internal hostnames or IP addresses are included.
`.gitignore` blocks `*.eml` outside `samples/` so a real message is not committed by accident.

## Development

```bash
pip install -r requirements-dev.txt -e .
```

```bash
pytest
```

```bash
ruff check . && ruff format --check .
```

GitHub Actions runs lint and the test suite on Python 3.11 to 3.14 for every push and pull request.

## License

[MIT](LICENSE)
