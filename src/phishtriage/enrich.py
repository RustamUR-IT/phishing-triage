"""Optional threat-intel enrichment (VirusTotal, AbuseIPDB).

API keys are read from the environment only:
    VT_API_KEY          VirusTotal v3 API key
    ABUSEIPDB_API_KEY   AbuseIPDB v2 API key
Missing keys simply skip that source. Only hashes and public IPs are sent;
no message content ever leaves the machine.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping

from phishtriage.findings import Finding

VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{}"
VT_GUI_URL = "https://www.virustotal.com/gui/file/{}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 15

# fetch(url, headers) -> (http_status, parsed_json_or_None)
Fetch = Callable[[str, dict], tuple[int, dict | None]]


def http_get_json(url: str, headers: dict) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers={**headers, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, None


def virustotal_file(sha256: str, api_key: str, fetch: Fetch = http_get_json) -> dict:
    try:
        status, data = fetch(VT_FILE_URL.format(sha256), {"x-apikey": api_key})
    except (OSError, ValueError) as exc:
        return {"sha256": sha256, "error": str(exc)}
    if status == 404:
        return {"sha256": sha256, "found": False}
    if status != 200 or not data:
        return {"sha256": sha256, "error": f"HTTP {status}"}
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "sha256": sha256,
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0),
        "link": VT_GUI_URL.format(sha256),
    }


def abuseipdb_ip(ip: str, api_key: str, fetch: Fetch = http_get_json) -> dict:
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    try:
        status, data = fetch(f"{ABUSEIPDB_URL}?{query}", {"Key": api_key})
    except (OSError, ValueError) as exc:
        return {"ip": ip, "error": str(exc)}
    if status != 200 or not data:
        return {"ip": ip, "error": f"HTTP {status}"}
    d = data.get("data", {})
    return {
        "ip": ip,
        "abuse_confidence": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "last_reported": d.get("lastReportedAt"),
    }


def enrich(
    hashes: list[str],
    ips: list[str],
    env: Mapping[str, str] = os.environ,
    fetch: Fetch = http_get_json,
) -> tuple[dict, list[Finding]]:
    result: dict = {"virustotal": None, "abuseipdb": None, "skipped": []}
    findings: list[Finding] = []

    vt_key = env.get("VT_API_KEY")
    if not vt_key:
        result["skipped"].append("virustotal (VT_API_KEY not set)")
    else:
        result["virustotal"] = [virustotal_file(h, vt_key, fetch) for h in dict.fromkeys(hashes)]
        for r in result["virustotal"]:
            if r.get("malicious", 0) > 0:
                findings.append(
                    Finding(
                        "intel.vt_malicious",
                        "high",
                        f"VirusTotal: {r['malicious']} engines flag {r['sha256'][:16]}...",
                        ("T1566.001", "T1204.002"),
                    )
                )

    abuse_key = env.get("ABUSEIPDB_API_KEY")
    if not abuse_key:
        result["skipped"].append("abuseipdb (ABUSEIPDB_API_KEY not set)")
    else:
        result["abuseipdb"] = [abuseipdb_ip(ip, abuse_key, fetch) for ip in dict.fromkeys(ips)]
        for r in result["abuseipdb"]:
            if (r.get("abuse_confidence") or 0) >= 50:
                findings.append(
                    Finding(
                        "intel.abuseipdb_reported",
                        "medium",
                        f"AbuseIPDB: {r['ip']} abuse confidence {r['abuse_confidence']}%",
                        ("T1566",),
                    )
                )
    return result, findings
