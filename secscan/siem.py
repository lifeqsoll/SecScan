from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
from urllib import error, request

from secscan.model import Finding


def _post_json(url: str, payload: object, headers: dict[str, str], timeout: int = 20) -> tuple[int, str]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(url=url, method="POST", headers=headers, data=body)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        return e.code, msg
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def export_splunk_hec(findings: list[Finding], host: dict, hec_url: str | None, hec_token: str | None, sourcetype: str = "secscan:json") -> str:
    if not hec_url or not hec_token:
        return "Splunk export skipped (missing URL/token)"
    sent = 0
    headers = {"Authorization": f"Splunk {hec_token}", "Content-Type": "application/json"}
    for f in findings:
        payload = {
            "sourcetype": sourcetype,
            "event": {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "details": f.details,
                "recommendation": f.recommendation,
                "host": host,
            },
        }
        status, _ = _post_json(hec_url, payload, headers)
        if status in (200, 201):
            sent += 1
    return f"Splunk export: sent {sent}/{len(findings)}"


def export_elk(findings: list[Finding], host: dict, elk_url: str | None, api_key: str | None, index: str = "secscan-findings") -> str:
    if not elk_url:
        return "ELK export skipped (missing URL)"
    date_suffix = dt.datetime.utcnow().strftime("%Y.%m.%d")
    index_name = f"{index}-{date_suffix}"
    bulk_lines: list[str] = []
    for f in findings:
        bulk_lines.append(json.dumps({"index": {"_index": index_name}}))
        bulk_lines.append(
            json.dumps(
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "details": f.details,
                    "recommendation": f.recommendation,
                    "host": host,
                    "@timestamp": dt.datetime.utcnow().isoformat() + "Z",
                },
                ensure_ascii=False,
            )
        )
    if not bulk_lines:
        return "ELK export: no findings to send"
    body = ("\n".join(bulk_lines) + "\n").encode("utf-8")
    headers = {"Content-Type": "application/x-ndjson"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    url = elk_url.rstrip("/") + "/_bulk"
    req = request.Request(url=url, method="POST", headers=headers, data=body)
    try:
        with request.urlopen(req, timeout=30) as resp:
            code = resp.status
            return f"ELK export: HTTP {code}, docs={len(findings)}"
    except error.HTTPError as e:
        return f"ELK export failed: HTTP {e.code}"
    except Exception as e:
        return f"ELK export failed: {type(e).__name__}: {e}"


def export_sentinel(findings: list[Finding], host: dict, workspace_id: str | None, shared_key: str | None, log_type: str = "SecScanFindings") -> str:
    if not workspace_id or not shared_key:
        return "Sentinel export skipped (missing workspace/key)"
    body_data = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "details": f.details,
            "recommendation": f.recommendation,
            "host": host,
        }
        for f in findings
    ]
    if not body_data:
        return "Sentinel export: no findings to send"
    body = json.dumps(body_data, ensure_ascii=False).encode("utf-8")
    rfc1123date = dt.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    string_to_hash = f"POST\n{len(body)}\napplication/json\nx-ms-date:{rfc1123date}\n/api/logs"
    decoded_key = base64.b64decode(shared_key)
    signature = base64.b64encode(hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()).decode("utf-8")
    auth = f"SharedKey {workspace_id}:{signature}"
    uri = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        "Content-Type": "application/json",
        "Authorization": auth,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date,
    }
    req = request.Request(url=uri, method="POST", headers=headers, data=body)
    try:
        with request.urlopen(req, timeout=30) as resp:
            return f"Sentinel export: HTTP {resp.status}, docs={len(findings)}"
    except error.HTTPError as e:
        return f"Sentinel export failed: HTTP {e.code}"
    except Exception as e:
        return f"Sentinel export failed: {type(e).__name__}: {e}"
