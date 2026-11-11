# Rules and false positives

Every rule below is listed with what it checks, its severity and ATT&CK mapping, the false
positives that showed up, and what was done about them. Fixes are pinned by a regression test in
[`tests/test_false_positives.py`](../tests/test_false_positives.py). Each test pairs the benign
case with the malicious variant that must still be caught, so reducing noise cannot quietly
open a blind spot.

**Where the false positives come from.** This repository contains only synthetic data (see the
README). The false positives were found by writing benign messages that follow common
legitimate patterns (newsletters sent by a mailing service, forwarded mail, ticket systems,
click tracking, OpenDocument files, users reporting phishing as an attached `.msg`) and running
the rules against them. They are realistic patterns, not measured rates from a production
mailbox.

**General techniques used to reduce false positives**

| Technique | Used by |
|---|---|
| Compare *registrable* (base) domains, not full host names | Reply-To, Return-Path, display name, link disguise |
| Let a stronger signal decide: DMARC pass makes SPF/DKIM noise and Return-Path mismatch irrelevant | `auth.*`, `sender.return_path_mismatch` |
| Allowlist on whole labels, consulted by the noisiest rules | `url.*`, `sender.reply_to_mismatch` |
| Downgrade to `info` (0 points) instead of deleting the finding | `auth.*` with DMARC pass, `att.legacy_office` for `.msg`, `url.not_allowlisted` |
| Collect a weak signal as data but raise no finding | `plain-http` URL flag, HTTP links in general |
| Require a combination, not a single feature | `att.double_extension` (decoy + dangerous ext), `att.archive_payload` (ZIP + dangerous member) |
| Thresholds on external intel | `intel.vt_malicious`, `intel.abuseipdb_reported` |

---

## Authentication

### `auth.spf_*`, `auth.dkim_*`, `auth.dmarc_*`

| | |
|---|---|
| **Checks** | SPF, DKIM and DMARC results from the **top** `Authentication-Results` header (added by your MTA); `Received-SPF` as SPF fallback. `pass` raises nothing. |
| **Severity** | DMARC `fail` high · SPF/DKIM `fail` medium · `softfail`, `none`, `neutral`, `policy`, `permerror` low · `temperror` info |
| **ATT&CK** | T1672 Email Spoofing |
| **False positives** | 1. **Forwarded mail and mailing lists** break SPF (the forwarder's IP is not in the sender's SPF record) while DKIM still passes and DMARC passes. The rule scored this as `spf=fail` medium. 2. **Several DKIM signatures** (sender plus mailing service): one failing signature next to a valid one was read as `dkim=fail`. 3. **Temporary DNS errors** (`temperror`) say nothing about the sender. |
| **Reduction** | 1. If DMARC passed, SPF and DKIM findings are downgraded to `info` with the note "DMARC passed via the other mechanism". 2. Any valid DKIM signature counts as `dkim=pass`. 3. `temperror` is `info`. |
| **Still caught** | Spoofed mail fails DMARC, so SPF/DKIM failures keep their full weight. Lower `Authentication-Results` headers, which a sender can forge, are ignored. |
| **Test** | `test_forwarded_mail_with_dmarc_pass_does_not_score_spf_fail`, `test_top_authentication_results_header_wins` |

### `auth.*_missing`

| | |
|---|---|
| **Checks** | No SPF, DKIM or DMARC result at all. |
| **Severity** | low |
| **False positives** | Internal mail between two mailboxes on the same server often has no `Authentication-Results`. |
| **Reduction** | Kept at low on purpose: all three together score 3, which stays below *suspicious* (4). |

---

## Sender

### `sender.display_name_spoof`

| | |
|---|---|
| **Checks** | The display name contains a domain (`"IT-Servicedesk example.com"`) whose base domain differs from the actual From address. |
| **Severity** | high |
| **ATT&CK** | T1656 Impersonation, T1566 Phishing |
| **False positives** | Display names such as `max.mustermann` or `j.doe` were parsed as domains (`mustermann` and `doe` look like TLDs to a regex), so ordinary colleagues were reported as *high* impersonation. |
| **Reduction** | A word in the display name only counts as a domain if it ends in a known TLD (`domains.KNOWN_TLDS`). Comparison is on base domains, so `"Shop shop.example.com" <news@example.com>` is fine. |
| **Remaining** | Mailing-list rewriting such as `"Jane (jane@partner.test) via List" <list@example.com>` still fires. That is arguably correct, since the mail did not come from partner.test, but analysts should know the pattern. A rare TLD missing from the list leads to a missed spoof, not a false alarm. |
| **Test** | `test_display_name_with_dotted_person_name_is_not_a_domain` |

### `sender.reply_to_mismatch`

| | |
|---|---|
| **Checks** | `Reply-To` base domain differs from the `From` base domain. |
| **Severity** | medium |
| **ATT&CK** | T1656 Impersonation |
| **False positives** | 1. Support mail sent from `example.com` with replies going to `support.example.com`. 2. Companies that route replies to their own ticket system or CRM on another domain. |
| **Reduction** | 1. Compared on base domain. 2. A Reply-To domain on the allowlist is not flagged. Add your ticket system's domain there. |
| **Test** | `test_reply_to_subdomain_of_sender_is_not_flagged`, `test_reply_to_own_ticket_system_is_not_flagged_when_allowlisted` |

### `sender.return_path_mismatch`

| | |
|---|---|
| **Checks** | `Return-Path` (envelope sender) base domain differs from `From`. |
| **Severity** | low |
| **ATT&CK** | T1672 Email Spoofing |
| **False positives** | Almost every newsletter: the mailing service uses its own bounce domain. At medium (3 points), one more weak signal such as a shortener (1) would already make a normal newsletter *suspicious* (4). |
| **Reduction** | Severity low from the start. The rule is skipped entirely when DMARC passed, because then the message is authenticated for the From domain via aligned DKIM and the bounce domain does not matter. |
| **Test** | `test_return_path_of_mailing_service_is_ignored_when_dmarc_passes` |

---

## URLs

All URL rules skip `mailto:`, `cid:`, `tel:` and relative links, strip trailing punctuation from
URLs found in text (`https://a.test/p.` → `https://a.test/p`), and deduplicate.

### `url.anchor_mismatch`

| | |
|---|---|
| **Checks** | The visible text of an HTML link looks like a domain or URL and points to a different site than the `href`. |
| **Severity** | high |
| **ATT&CK** | T1566.002, T1598.003, T1656 |
| **False positives** | 1. Text `www.example.com`, target `https://example.com/…`: same site, but the first version compared full host names. 2. **Click tracking** and rewriters (newsletter tools, Microsoft Safe Links, your own gateway): every link in a legitimate newsletter points to `click.tracker.test`. 3. Link text without a domain ("Hier klicken") was never compared, by design. |
| **Reduction** | 1. Compare base domains. 2. A target on the allowlist is not a disguise; put your tracking/rewriting domains there. 3. Only text that looks like a domain is checked. |
| **Not loosened** | Shared-hosting platforms (`github.io`, `sharepoint.com`, `web.app`, …) are treated as public suffixes, so `victim.github.io` → `attacker.github.io` is still reported even though both end in `github.io`. |
| **Test** | `test_anchor_text_www_and_target_apex_are_the_same_site`, `test_allowlisted_click_tracker_is_not_a_mismatch`, `test_shared_hosting_subdomains_are_different_sites` |

### `url.ip_literal`, `url.punycode`, `url.shortener`, `url.userinfo`, `url.nonstandard_port`

| Rule | Checks | Severity |
|---|---|---|
| `url.ip_literal` | Host is a raw IP address | medium |
| `url.punycode` | `xn--` label or non-ASCII host (possible homograph) | medium |
| `url.shortener` | Host is a known shortener (`bit.ly`, `t.co`, …) | low |
| `url.userinfo` | `user@host` in the URL (`https://bank.example@evil.test/`) | high |
| `url.nonstandard_port` | Port other than 80/443 | low |

ATT&CK for all: T1566.002, T1204.001.

| | |
|---|---|
| **False positives** | Legitimate IDN domains (German umlaut domains such as `müller.example`), intranet links with a port (`:8443`), a company's own branded shortener. |
| **Reduction** | Per-URL flags are not turned into findings when the host is on the allowlist. The flags stay in the JSON so the analyst can still see them. Shorteners and ports were set to low from the start because they are common in marketing mail. |
| **Test** | `test_allowlisted_idn_domain_is_not_flagged_as_homograph` |

### `plain-http` (flag only)

Plain `http://` links are recorded as a flag on the URL but **never** raise a finding. During
tuning they fired on most newsletters and old intranet links and said nothing about phishing.
Test: `test_plain_http_alone_is_not_a_finding`.

### `url.not_allowlisted`

| | |
|---|---|
| **Checks** | Lists linked domains that are not on the allowlist. |
| **Severity** | info (0 points) |
| **Reasoning** | Without an allowlist every domain is "unknown", so this would fire on every message. It is a pivot list for the analyst, not a score contributor. |

---

## Attachments

Type detection always uses magic bytes, never the declared `Content-Type` or the extension alone.

### `att.type_mismatch`

| | |
|---|---|
| **Checks** | Extension does not match the content type found from the magic bytes. |
| **Severity** | high if the real content is executable/HTML/ISO/LNK, otherwise medium |
| **ATT&CK** | T1036.008 Masquerade File Type, T1566.001, T1204.002 |
| **False positives** | 1. Many formats are ZIP files on disk: `.odt`, `.ods`, `.epub`, `.jar`, `.xps`, `.vsdx`. They were reported as "extension .odt but content is zip". 2. OLE2 is also used by `.dot`, `.xlt`, `.pps`, `.pub`, `.vsd`. 3. Plain text (`.csv`, `.txt`, `.log`) has no magic bytes at all. |
| **Reduction** | 1./2. Added these container formats to the expected extensions of ZIP and OLE2. 3. Detected plain text has no expected extension, so it is never compared. |
| **Still caught** | A `.pdf` that is a ZIP, a `.jpg` that is a PE file. A `.jar` is no longer a *mismatch* but is still a high `att.dangerous_type`. |
| **Test** | `test_opendocument_and_epub_are_zip_but_not_a_mismatch`, `test_csv_and_txt_are_not_reported_as_type_mismatch`, `test_pdf_that_is_really_a_zip_with_script` |

### `att.double_extension`

| | |
|---|---|
| **Checks** | A decoy extension followed by a dangerous one: `Rechnung.pdf.exe`, `scan.jpg .js`. |
| **Severity** | high |
| **ATT&CK** | T1036.007 Double File Extension |
| **False positives** | Any filename with two dots (`Bericht v2.1.pdf`, `Q3.2026.xlsx`) would fire on a naive "two extensions" check. |
| **Reduction** | Fires only if the second-to-last extension is a typical decoy (`pdf`, `docx`, `jpg`, …) **and** the last one is on the dangerous list. |
| **Test** | `test_version_number_in_filename_is_not_a_double_extension`, `test_double_extension_and_rtlo` |

### `att.rtlo`

| | |
|---|---|
| **Checks** | U+202E right-to-left override in the filename (`invoice` + U+202E + `fdp.exe` displays as `invoiceexe.pdf`). |
| **Severity** | high |
| **ATT&CK** | T1036.002 Right-to-Left Override |
| **False positives** | None seen. RTL *text* in Arabic or Hebrew filenames does not use U+202E. |

### `att.dangerous_type`

| | |
|---|---|
| **Checks** | Content is PE/ELF/LNK/ISO/HTML/script, or the extension is on the dangerous list (`exe`, `js`, `hta`, `iso`, `one`, `html`, `svg`, `docm`, …). |
| **Severity** | high |
| **ATT&CK** | T1566.001, T1204.002; plus T1027.006 HTML Smuggling for HTML/SVG, T1553.005 MOTW bypass for ISO/IMG/VHD |
| **False positives** | Accepted: some invoicing and e-banking systems send `.html` attachments, some teams exchange `.docm` files internally. |
| **Reduction** | None on purpose. These formats are the main delivery vehicles, and an analyst looking at a legitimate `.html` invoice is cheap compared to missing HTML smuggling. |

### `att.macros`

| | |
|---|---|
| **Checks** | OOXML file contains `vbaProject.bin`. |
| **Severity** | high |
| **False positives** | Internal macro workbooks. Not reduced: macros from outside are blocked by default in current Office for good reason. |

### `att.legacy_office`

| | |
|---|---|
| **Checks** | OLE2 container (`.doc`, `.xls`, `.msi`, …) where macros cannot be ruled out without parsing the container. |
| **Severity** | medium; **info** for `.msg` |
| **False positives** | Users report phishing by forwarding it **as an attached Outlook item** (`.msg`, which is OLE2). The evidence itself was scored as a suspicious Office file. |
| **Reduction** | `.msg` is reported as `info` with the hint to analyse the attached message separately. A `.doc` still scores medium. |
| **Test** | `test_forwarded_outlook_item_is_info_not_medium` |

### `att.encrypted_archive`

| | |
|---|---|
| **Checks** | ZIP with the encryption flag set. |
| **Severity** | medium |
| **ATT&CK** | T1027.013 Encrypted/Encoded File |
| **False positives** | Encrypted ZIPs are a common (if weak) way to send confidential documents, for example payroll or medical data. |
| **Reduction** | Medium rather than high, so it needs a second signal (sender, link, payload) to reach *likely malicious*. |

### `att.archive_payload`

| | |
|---|---|
| **Checks** | A real ZIP (not OOXML) contains a member with a dangerous extension. |
| **Severity** | high |
| **False positives** | Office files are ZIPs full of internal parts. Inspecting them as archives would report their internals. |
| **Reduction** | Only applies when the detected type is plain `zip`, never to OOXML. |

---

## Enrichment (opt-in)

### `intel.vt_malicious`

| | |
|---|---|
| **Checks** | Attachment SHA-256 known to VirusTotal with detections. |
| **Severity** | high with ≥ 3 engines, low with 1–2 |
| **ATT&CK** | T1566.001, T1204.002 |
| **False positives** | One or two engines flagging a clean file (heuristic or "generic" detections, packed installers) is common. The first version raised *high* on a single engine. |
| **Reduction** | Threshold `VT_HIGH_THRESHOLD = 3`. One or two hits are reported as low so they remain visible. |
| **Test** | `test_single_virustotal_engine_is_low_not_high` |

### `intel.abuseipdb_reported`

| | |
|---|---|
| **Checks** | Public relay IP from the Received chain with AbuseIPDB confidence ≥ 50 %. |
| **Severity** | medium |
| **ATT&CK** | T1566 |
| **False positives** | Large shared senders (cloud mail providers) collect abuse reports simply because of volume. |
| **Reduction** | Confidence threshold of 50 %, medium severity only. Internal and documentation-range IPs are never looked up. |
| **Remaining** | Your own MX relays appear in the chain as public IPs and are looked up too. If they are ever reported, add a filter on your own networks. |

---

## Tuning checklist for a new environment

1. Put your own domains, your ticket system, your link rewriter (e.g. Safe Links) and your
   newsletter tracking domains on the allowlist.
2. Pin the trusted `Authentication-Results` header to your MTA's `authserv-id`.
3. Run the tool on a few days of *reported but benign* mail and look at which rule IDs fire most;
   each fix should come with a pair of tests like the ones in `tests/test_false_positives.py`.
