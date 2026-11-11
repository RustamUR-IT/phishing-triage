from phishtriage.enrich import enrich

SHA = "a" * 64


class FakeFetch:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        for prefix, response in self.responses.items():
            if url.startswith(prefix):
                return response
        raise AssertionError(f"unexpected URL {url}")


def test_without_keys_nothing_is_called():
    fetch = FakeFetch({})
    result, findings = enrich([SHA], ["8.8.8.8"], env={}, fetch=fetch)
    assert fetch.calls == []
    assert findings == []
    assert len(result["skipped"]) == 2


def test_virustotal_and_abuseipdb_with_keys():
    vt = {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1}}}}
    ab = {"data": {"abuseConfidenceScore": 87, "totalReports": 40, "countryCode": "ZZ"}}
    fetch = FakeFetch(
        {"https://www.virustotal.com/": (200, vt), "https://api.abuseipdb.com/": (200, ab)}
    )
    env = {"VT_API_KEY": "vt-secret", "ABUSEIPDB_API_KEY": "ab-secret"}
    result, findings = enrich([SHA, SHA], ["8.8.8.8"], env=env, fetch=fetch)

    assert len(fetch.calls) == 2  # duplicate hash looked up once
    assert fetch.calls[0][1] == {"x-apikey": "vt-secret"}
    assert "ipAddress=8.8.8.8" in fetch.calls[1][0]
    assert result["virustotal"][0]["malicious"] == 12
    assert result["abuseipdb"][0]["abuse_confidence"] == 87
    assert {f.id for f in findings} == {"intel.vt_malicious", "intel.abuseipdb_reported"}
    assert "secret" not in repr(result)


def test_unknown_hash_and_http_errors_do_not_raise():
    fetch = FakeFetch(
        {"https://www.virustotal.com/": (404, None), "https://api.abuseipdb.com/": (429, None)}
    )
    env = {"VT_API_KEY": "k", "ABUSEIPDB_API_KEY": "k"}
    result, findings = enrich([SHA], ["8.8.8.8"], env=env, fetch=fetch)
    assert result["virustotal"][0] == {"sha256": SHA, "found": False}
    assert result["abuseipdb"][0]["error"] == "HTTP 429"
    assert findings == []
