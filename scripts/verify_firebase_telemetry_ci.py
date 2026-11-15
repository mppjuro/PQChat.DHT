"""End-to-end verification script for PQChat.DHT Firebase research telemetry.

This script performs three layers of verification without introducing external
Python dependencies:
1. Credential resolution from environment variables, ``app/google-services.json``,
   or base64-encoded ``GOOGLE_SERVICES_JSON_BASE64``.
2. Synthetic research bundle construction (CSV files, SHA-256 checksums,
   ``session_manifest.json``, and compressed ``.zip`` archive) plus local schema
   validation mirroring ``firestore.rules`` (both positive and negative cases).
3. Live Firebase Anonymous Auth + Cloud Firestore REST API verification when
   credentials are available and ``--offline-only`` is not set, asserting that:
   - valid ``schemaVersion == 2`` research sessions succeed with HTTP 200/201,
   - malformed payloads (``schemaVersion == 999`` or missing ``metrics``) fail
     with HTTP 403 ``PERMISSION_DENIED``, and
   - client ``GET`` reads of ``research_sessions`` fail with HTTP 403
     ``PERMISSION_DENIED``.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

#: Minimum valid Unix epoch timestamp in milliseconds enforced by ``firestore.rules``.
MIN_VALID_TIMESTAMP_MS = 1_700_000_000_000

#: Expected research telemetry schema version enforced by ``firestore.rules``.
EXPECTED_SCHEMA_VERSION = 2

#: Maximum compressed ZIP bundle size in bytes allowed by ``firestore.rules``.
MAX_BUNDLE_ZIP_BYTES = 700_000

#: Maximum Base64 string length for ``bundleZipBase64`` allowed by ``firestore.rules``.
MAX_BUNDLE_BASE64_CHARS = 950_000

#: Minimum allowed ``sessionId`` length enforced by ``firestore.rules``.
MIN_SESSION_ID_LEN = 8

#: Maximum allowed ``sessionId`` length enforced by ``firestore.rules``.
MAX_SESSION_ID_LEN = 64

#: Default Android application package name inside ``google-services.json``.
ANDROID_PACKAGE_NAME = "org.pqchat.dht"

#: Master telemetry CSV header matching ``ResearchCsvSchema.MASTER_CSV_HEADER``.
MASTER_CSV_HEADER = (
    "record_id,session_id,timestamp_epoch_ms,iso_timestamp,record_type,"
    "packet_role,target_prefix,seq_num,payload_bytes,rtt_ms,nodes_queried,"
    "nodes_responded,lookup_hops,success,republish_attempt,message_age_ms,"
    "network_type,polling_state,replication_k,poisson_lambda,"
    "battery_current_ua,battery_level_pct,republish_active,is_alive,"
    "elapsed_hours,e2e_latency_ms,error_or_status"
)

#: Packet events CSV header matching ``PacketTelemetryEvent.CSV_HEADER``.
PACKET_EVENTS_CSV_HEADER = (
    "event_id,session_id,timestamp_epoch_ms,iso_timestamp,role,"
    "role_display_name,target_prefix,seq_num,payload_bytes,rtt_ms,"
    "nodes_queried,nodes_responded,lookup_hops,success,republish_attempt,"
    "message_age_ms,network_type,polling_state,replication_k,poisson_lambda,"
    "battery_current_ua,battery_level_pct,error_code"
)

#: TTL sample CSV header matching ``TtlSampleEvent.CSV_HEADER``.
TTL_SAMPLES_CSV_HEADER = (
    "sample_id,session_id,timestamp_epoch_ms,iso_timestamp,target_prefix,"
    "initial_put_epoch_ms,elapsed_minutes,elapsed_hours,republish_active,"
    "is_alive,nodes_queried,nodes_responded,lookup_hops,probe_rtt_ms,"
    "confirmed_lifespan_minutes,network_type,polling_state,replication_k,"
    "poisson_lambda,battery_current_ua,battery_level_pct"
)

#: Republish summary CSV header matching ``RepublishAnalysisSummary.CSV_HEADER``.
REPUBLISH_SUMMARY_CSV_HEADER = (
    "message_prefix,session_id,initial_sent_epoch_ms,delivered_epoch_ms,"
    "is_delivered,total_republishes,time_to_first_republish_ms,"
    "e2e_delivery_latency_ms,crowd_relayed,final_status"
)

#: Group events CSV header matching ``GroupTelemetryEvent.CSV_HEADER``.
GROUP_EVENTS_CSV_HEADER = (
    "event_id,session_id,timestamp_epoch_ms,iso_timestamp,event_type,"
    "group_id_prefix,group_size_m,latency_ms,fan_out_skew_ms,"
    "key_rotation_convergence_ms,epoch"
)

#: Exact top-level document keys allowed by ``firestore.rules``.
REQUIRED_TOP_LEVEL_KEYS = frozenset(
    {"sessionId", "timestamp", "deviceInfo", "metrics", "schemaVersion"}
)

#: Required ``deviceInfo`` keys enforced by ``firestore.rules``.
REQUIRED_DEVICE_INFO_KEYS = (
    "sessionId",
    "deviceModel",
    "androidVersion",
    "appVersion",
    "versionCode",
)

#: Required non-negative integer ``metrics`` keys enforced by ``firestore.rules``.
REQUIRED_METRIC_COUNTER_KEYS = (
    "totalEvents",
    "firstSendCount",
    "ownRepublishCount",
    "crowdRepublishCount",
    "packetsReceivedCount",
    "ttlSamplesCount",
)


@dataclass(frozen=True)
class FirebaseCredentials:
    """Resolved Firebase Web/Android project configuration."""

    #: Firebase project identifier (e.g. ``pqchat-dht-research``).
    project_id: str

    #: Android/Firebase API key used for Identity Toolkit anonymous sign-up.
    api_key: str

    #: Mobile SDK application ID from ``google-services.json``.
    app_id: str

    #: Human-readable label indicating where credentials were loaded from.
    source: str


def _parse_google_services_dict(data: dict[str, Any], source: str) -> FirebaseCredentials | None:
    """Extract Firebase credentials from parsed ``google-services.json`` data."""
    project_info = data.get("project_info")
    if not isinstance(project_info, dict):
        return None
    project_id = str(project_info.get("project_id") or "").strip()

    clients = data.get("client")
    if not isinstance(clients, list) or not clients:
        return None

    selected_client: dict[str, Any] | None = None
    for entry in clients:
        if not isinstance(entry, dict):
            continue
        client_info = entry.get("client_info") or {}
        android_info = client_info.get("android_client_info") or {}
        if android_info.get("package_name") == ANDROID_PACKAGE_NAME:
            selected_client = entry
            break
    if selected_client is None and isinstance(clients[0], dict):
        selected_client = clients[0]
    if selected_client is None:
        return None

    client_info = selected_client.get("client_info") or {}
    app_id = str(client_info.get("mobilesdk_app_id") or "").strip()

    api_key = ""
    api_keys = selected_client.get("api_key")
    if isinstance(api_keys, list) and api_keys and isinstance(api_keys[0], dict):
        api_key = str(api_keys[0].get("current_key") or "").strip()

    if not project_id or not api_key:
        return None

    return FirebaseCredentials(
        project_id=project_id,
        api_key=api_key,
        app_id=app_id,
        source=source,
    )


def resolve_firebase_credentials(repo_root: Path) -> FirebaseCredentials | None:
    """Resolve Firebase credentials from env vars, file, or base64 secret."""
    env_project = os.environ.get("FIREBASE_PROJECT_ID", "").strip()
    env_api_key = os.environ.get("FIREBASE_API_KEY", "").strip()
    env_app_id = os.environ.get("FIREBASE_APP_ID", "").strip()

    if env_project and env_api_key:
        return FirebaseCredentials(
            project_id=env_project,
            api_key=env_api_key,
            app_id=env_app_id,
            source="environment variables",
        )

    google_services_path = repo_root / "app" / "google-services.json"
    if google_services_path.is_file():
        try:
            raw = json.loads(google_services_path.read_text(encoding="utf-8"))
            creds = _parse_google_services_dict(raw, str(google_services_path))
            if creds is not None:
                return creds
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Failed to parse {google_services_path}: {exc}", file=sys.stderr)

    b64_secret = os.environ.get("GOOGLE_SERVICES_JSON_BASE64", "").strip()
    if b64_secret:
        try:
            decoded_bytes = base64.b64decode(b64_secret, validate=True)
            raw = json.loads(decoded_bytes.decode("utf-8"))
            creds = _parse_google_services_dict(raw, "GOOGLE_SERVICES_JSON_BASE64")
            if creds is not None:
                return creds
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(
                f"[WARN] Failed to decode GOOGLE_SERVICES_JSON_BASE64: {exc}",
                file=sys.stderr,
            )

    return None


def _sha256_bytes(content: bytes) -> str:
    """Compute lowercase hexadecimal SHA-256 digest for byte content."""
    return hashlib.sha256(content).hexdigest()


def _format_iso_utc(epoch_ms: int) -> str:
    """Format millisecond epoch timestamp as UTC ISO-8601 string."""
    seconds = epoch_ms / 1000.0
    millis = epoch_ms % 1000
    utc_struct = time.gmtime(seconds)
    return time.strftime("%Y-%m-%dT%H:%M:%S", utc_struct) + f".{millis:03d}Z"


def build_synthetic_research_payload(
    session_id: str | None = None,
    timestamp_ms: int | None = None,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    """Build a synthetic ``schemaVersion == 2`` research payload and ZIP archive.

    Returns a tuple of (firestore_document_dict, zip_bytes, file_checksums).
    """
    now_ms = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)
    iso_now = _format_iso_utc(now_ms)
    resolved_session_id = session_id or f"ci_verify_{uuid.uuid4().hex[:12]}"
    if len(resolved_session_id) > MAX_SESSION_ID_LEN:
        resolved_session_id = resolved_session_id[:MAX_SESSION_ID_LEN]

    event_1 = str(uuid.uuid4())
    event_2 = str(uuid.uuid4())
    event_3 = str(uuid.uuid4())
    sample_1 = str(uuid.uuid4())

    master_rows = [
        MASTER_CSV_HEADER,
        (
            f"{event_1},{resolved_session_id},{now_ms},{iso_now},PACKET_EVENT,"
            f"FIRST_SEND,a1b2c3d4,1,900,48,24,8,3,true,0,0,WIFI,FOREGROUND_CHAT,"
            f"8,0.002083,-180000,92,\"\",true,\"\",\"\",\"\""
        ),
        (
            f"{event_2},{resolved_session_id},{now_ms + 1200},{iso_now},PACKET_EVENT,"
            f"OWN_REPUBLISH,a1b2c3d4,1,900,51,24,8,3,true,1,600000,WIFI,"
            f"BACKGROUND_IDLE,8,0.002083,-140000,91,\"\",true,\"\",\"\",\"\""
        ),
        (
            f"{event_3},{resolved_session_id},{now_ms + 2400},{iso_now},PACKET_EVENT,"
            f"PACKET_RECEIVED,e5f6a7b8,1,900,39,16,8,2,true,0,1500,WIFI,"
            f"FOREGROUND_CHAT,8,0.002083,-150000,91,\"\",true,\"\",\"\",\"\""
        ),
        (
            f"{sample_1},{resolved_session_id},{now_ms + 3600},{iso_now},TTL_PROBE,"
            f"TTL_PROBE,a1b2c3d4,1,900,44,20,8,3,true,0,0,WIFI,FOREGROUND_CHAT,"
            f"8,0.002083,-155000,91,true,true,0.2500,\"\",\"\""
        ),
    ]

    packet_rows = [
        PACKET_EVENTS_CSV_HEADER,
        (
            f"{event_1},{resolved_session_id},{now_ms},{iso_now},FIRST_SEND,"
            f"\"Original Message\",a1b2c3d4,1,900,48,24,8,3,true,0,0,WIFI,"
            f"FOREGROUND_CHAT,8,0.002083,-180000,92,\"\""
        ),
        (
            f"{event_2},{resolved_session_id},{now_ms + 1200},{iso_now},OWN_REPUBLISH,"
            f"\"Own Republish\",a1b2c3d4,1,900,51,24,8,3,true,1,600000,WIFI,"
            f"BACKGROUND_IDLE,8,0.002083,-140000,91,\"\""
        ),
        (
            f"{event_3},{resolved_session_id},{now_ms + 2400},{iso_now},PACKET_RECEIVED,"
            f"\"Packet Received\",e5f6a7b8,1,900,39,16,8,2,true,0,1500,WIFI,"
            f"FOREGROUND_CHAT,8,0.002083,-150000,91,\"\""
        ),
    ]

    ttl_rows = [
        TTL_SAMPLES_CSV_HEADER,
        (
            f"{sample_1},{resolved_session_id},{now_ms + 3600},{iso_now},a1b2c3d4,"
            f"{now_ms},15.00,0.2500,true,true,20,8,3,44,15.00,WIFI,"
            f"FOREGROUND_CHAT,8,0.002083,-155000,91"
        ),
    ]

    republish_rows = [
        REPUBLISH_SUMMARY_CSV_HEADER,
        f"a1b2c3d4,{resolved_session_id},{now_ms},{now_ms + 1500},true,1,600000,1500,false,DELIVERED",
    ]

    group_rows = [
        GROUP_EVENTS_CSV_HEADER,
        f"{uuid.uuid4()},{resolved_session_id},{now_ms + 500},{iso_now},BROADCAST,9f8e7d6c,3,180,45,0,1",
    ]

    csv_files: dict[str, bytes] = {
        "research_telemetry_master.csv": ("\n".join(master_rows) + "\n").encode("utf-8"),
        "research_packet_events.csv": ("\n".join(packet_rows) + "\n").encode("utf-8"),
        "research_ttl_samples.csv": ("\n".join(ttl_rows) + "\n").encode("utf-8"),
        "research_republish_analysis.csv": ("\n".join(republish_rows) + "\n").encode("utf-8"),
        "research_group_events.csv": ("\n".join(group_rows) + "\n").encode("utf-8"),
    }

    file_checksums = {name: _sha256_bytes(blob) for name, blob in csv_files.items()}

    manifest_dict: dict[str, Any] = {
        "sessionId": resolved_session_id,
        "appVersion": "ci-verify",
        "versionCode": 1,
        "deviceModel": "CI-Synthetic-Runner",
        "androidVersion": 34,
        "createdEpochMs": now_ms,
        "isoCreatedAt": iso_now,
        "totalEvents": 3,
        "firstSendCount": 1,
        "ownRepublishCount": 1,
        "crowdRepublishCount": 0,
        "packetsReceivedCount": 1,
        "ttlSamplesCount": 1,
        "fileChecksums": file_checksums,
        "manifestSha256": "",
    }
    manifest_pre_hash = json.dumps(manifest_dict, indent=2).encode("utf-8")
    manifest_dict["manifestSha256"] = _sha256_bytes(manifest_pre_hash)
    manifest_bytes = json.dumps(manifest_dict, indent=2).encode("utf-8")

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for filename, content in csv_files.items():
            zf.writestr(filename, content)
        zf.writestr("session_manifest.json", manifest_bytes)
    zip_bytes = zip_buf.getvalue()

    zip_b64 = base64.b64encode(zip_bytes).decode("ascii")
    document_data: dict[str, Any] = {
        "sessionId": resolved_session_id,
        "timestamp": now_ms,
        "schemaVersion": EXPECTED_SCHEMA_VERSION,
        "deviceInfo": {
            "sessionId": resolved_session_id,
            "deviceModel": "CI-Synthetic-Runner",
            "androidVersion": 34,
            "appVersion": "ci-verify",
            "versionCode": 1,
        },
        "metrics": {
            "totalEvents": 3,
            "firstSendCount": 1,
            "ownRepublishCount": 1,
            "crowdRepublishCount": 0,
            "packetsReceivedCount": 1,
            "ttlSamplesCount": 1,
            "rttStats": {"sampleCount": 3, "meanMs": 46.0, "p50Ms": 48, "p95Ms": 51},
            "ttlStats": {"aliveCount": 1, "expiredCount": 0, "survivalRatePct": 100.0},
            "republishStats": {"ownRepublishCount": 1, "crowdRepublishCount": 0},
            "fileChecksums": file_checksums,
            "manifestSha256": manifest_dict["manifestSha256"],
            "bundleZipSizeBytes": len(zip_bytes),
            "bundleZipStatus": "EMBEDDED_ZIP_BASE64",
            "bundleZipBase64": zip_b64,
        },
    }
    return document_data, zip_bytes, file_checksums


def _is_strict_int(value: Any) -> bool:
    """Return True if value is an integer and not a Python bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def validate_payload_against_rules(document_data: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate a Firestore ``research_sessions`` payload against ``firestore.rules``."""
    keys = set(document_data.keys())
    if keys != REQUIRED_TOP_LEVEL_KEYS:
        return (
            False,
            f"Top-level keys mismatch: expected {sorted(REQUIRED_TOP_LEVEL_KEYS)}, got {sorted(keys)}",
        )

    session_id = document_data.get("sessionId")
    if not isinstance(session_id, str) or not (
        MIN_SESSION_ID_LEN <= len(session_id) <= MAX_SESSION_ID_LEN
    ):
        return False, "sessionId must be a string with length between 8 and 64"

    timestamp = document_data.get("timestamp")
    if not _is_strict_int(timestamp) or timestamp <= MIN_VALID_TIMESTAMP_MS:
        return False, f"timestamp must be an integer > {MIN_VALID_TIMESTAMP_MS}"

    schema_version = document_data.get("schemaVersion")
    if not _is_strict_int(schema_version) or schema_version != EXPECTED_SCHEMA_VERSION:
        return False, f"schemaVersion must equal {EXPECTED_SCHEMA_VERSION}"

    device_info = document_data.get("deviceInfo")
    if not isinstance(device_info, dict):
        return False, "deviceInfo must be a map"
    for key in REQUIRED_DEVICE_INFO_KEYS:
        if key not in device_info:
            return False, f"deviceInfo missing required key '{key}'"
    if device_info.get("sessionId") != session_id:
        return False, "deviceInfo.sessionId must match top-level sessionId"
    if not isinstance(device_info.get("deviceModel"), str) or not isinstance(
        device_info.get("appVersion"), str
    ):
        return False, "deviceInfo.deviceModel and deviceInfo.appVersion must be strings"
    if not _is_strict_int(device_info.get("androidVersion")) or not _is_strict_int(
        device_info.get("versionCode")
    ):
        return False, "deviceInfo.androidVersion and deviceInfo.versionCode must be integers"

    metrics = document_data.get("metrics")
    if not isinstance(metrics, dict):
        return False, "metrics must be a map"
    for key in REQUIRED_METRIC_COUNTER_KEYS:
        if key not in metrics:
            return False, f"metrics missing required key '{key}'"
        val = metrics.get(key)
        if not _is_strict_int(val) or val < 0:
            return False, f"metrics.{key} must be a non-negative integer"

    zip_size = metrics.get("bundleZipSizeBytes")
    if zip_size is not None:
        if not _is_strict_int(zip_size) or zip_size < 0 or zip_size > MAX_BUNDLE_ZIP_BYTES:
            return False, f"metrics.bundleZipSizeBytes must be in 0..{MAX_BUNDLE_ZIP_BYTES}"

    zip_b64 = metrics.get("bundleZipBase64")
    if zip_b64 is not None:
        if not isinstance(zip_b64, str) or len(zip_b64) > MAX_BUNDLE_BASE64_CHARS:
            return False, f"metrics.bundleZipBase64 must be a string <= {MAX_BUNDLE_BASE64_CHARS} chars"

    return True, None


def run_local_schema_and_bundle_checks(payload: dict[str, Any], zip_bytes: bytes) -> None:
    """Verify ZIP integrity, SHA-256 manifest, and positive/negative schema checks."""
    valid, reason = validate_payload_against_rules(payload)
    if not valid:
        raise AssertionError(f"Synthetic payload failed rules validation: {reason}")

    with zipfile.ZipFile(io.BytesIO(zip_bytes), mode="r") as zf:
        names = set(zf.namelist())
        if "session_manifest.json" not in names:
            raise AssertionError("Synthetic bundle missing session_manifest.json")
        manifest = json.loads(zf.read("session_manifest.json").decode("utf-8"))
        for csv_name, expected_sha in manifest["fileChecksums"].items():
            if csv_name not in names:
                raise AssertionError(f"Bundle missing checksummed file {csv_name}")
            actual_sha = _sha256_bytes(zf.read(csv_name))
            if actual_sha != expected_sha:
                raise AssertionError(f"SHA-256 mismatch for {csv_name}")

    # Negative validation checks mirroring firestore.rules rejections
    bad_schema = json.loads(json.dumps(payload))
    bad_schema["schemaVersion"] = 999
    if validate_payload_against_rules(bad_schema)[0]:
        raise AssertionError("Negative check failed: schemaVersion=999 must be rejected")

    missing_metrics = json.loads(json.dumps(payload))
    del missing_metrics["metrics"]
    if validate_payload_against_rules(missing_metrics)[0]:
        raise AssertionError("Negative check failed: missing metrics must be rejected")

    oversized_zip = json.loads(json.dumps(payload))
    oversized_zip["metrics"]["bundleZipSizeBytes"] = MAX_BUNDLE_ZIP_BYTES + 1
    if validate_payload_against_rules(oversized_zip)[0]:
        raise AssertionError("Negative check failed: oversized bundleZipSizeBytes must be rejected")


def _to_firestore_value(value: Any) -> dict[str, Any]:
    """Convert a Python value into a Cloud Firestore REST API ``Value`` object."""
    if value is None:
        return {"nullValue": None}
    if isinstance(value, bool):
        return {"booleanValue": value}
    if isinstance(value, int):
        return {"integerValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, list):
        return {"arrayValue": {"values": [_to_firestore_value(item) for item in value]}}
    if isinstance(value, dict):
        return {
            "mapValue": {
                "fields": {str(k): _to_firestore_value(v) for k, v in value.items()}
            }
        }
    return {"stringValue": str(value)}


def to_firestore_document(payload: dict[str, Any]) -> dict[str, Any]:
    """Convert a flat/nested dictionary to a Firestore REST ``Document`` body."""
    return {"fields": {str(k): _to_firestore_value(v) for k, v in payload.items()}}


def _http_json_request(
    url: str,
    method: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout_s: float = 20.0,
) -> tuple[int, str]:
    """Execute an HTTP JSON request and return ``(status_code, response_body)``."""
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    data_bytes: bytes | None = None
    if body is not None:
        req_headers["Content-Type"] = "application/json; charset=utf-8"
        data_bytes = json.dumps(body).encode("utf-8")

    request = urllib.request.Request(url, data=data_bytes, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", errors="replace")


def sign_in_anonymously(api_key: str) -> str:
    """Authenticate anonymously via Firebase Identity Toolkit REST API."""
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={urllib.parse.quote(api_key)}"
    status, resp_text = _http_json_request(url, "POST", body={"returnSecureToken": True})
    if status != 200:
        raise RuntimeError(
            f"Firebase Anonymous Auth signUp failed with HTTP {status}: {resp_text[:300]}"
        )
    parsed = json.loads(resp_text)
    id_token = str(parsed.get("idToken") or "")
    if not id_token:
        raise RuntimeError("Firebase Anonymous Auth response did not contain an idToken")
    return id_token


def verify_live_firestore_ingestion(
    creds: FirebaseCredentials,
    payload: dict[str, Any],
) -> None:
    """Verify live Firestore write success and negative ``firestore.rules`` rejections."""
    id_token = sign_in_anonymously(creds.api_key)
    auth_header = {"Authorization": f"Bearer {id_token}"}
    base_docs_url = (
        f"https://firestore.googleapis.com/v1/projects/"
        f"{urllib.parse.quote(creds.project_id)}/databases/(default)/documents/research_sessions"
    )
    session_id = payload["sessionId"]

    # 1. Valid schemaVersion == 2 creation must return HTTP 200 (or 201)
    create_url = f"{base_docs_url}?documentId={urllib.parse.quote(session_id)}"
    status, body = _http_json_request(
        create_url,
        "POST",
        body=to_firestore_document(payload),
        headers=auth_header,
    )
    if status not in (200, 201):
        raise AssertionError(
            f"Expected HTTP 200/201 creating valid research_sessions/{session_id}, "
            f"got HTTP {status}: {body[:400]}"
        )
    print(f"[PASS] Live Firestore CREATE succeeded for research_sessions/{session_id} (HTTP {status})")

    # 2. Invalid schemaVersion == 999 must be rejected with HTTP 403 PERMISSION_DENIED
    bad_schema_payload = json.loads(json.dumps(payload))
    bad_schema_payload["schemaVersion"] = 999
    bad_schema_doc_id = f"{session_id}_bad_schema"[:MAX_SESSION_ID_LEN]
    bad_schema_payload["sessionId"] = bad_schema_doc_id
    bad_schema_payload["deviceInfo"]["sessionId"] = bad_schema_doc_id
    status_bad, body_bad = _http_json_request(
        f"{base_docs_url}?documentId={urllib.parse.quote(bad_schema_doc_id)}",
        "POST",
        body=to_firestore_document(bad_schema_payload),
        headers=auth_header,
    )
    if status_bad != 403:
        raise AssertionError(
            f"Expected HTTP 403 PERMISSION_DENIED for schemaVersion=999, got {status_bad}: {body_bad[:300]}"
        )
    print("[PASS] Live Firestore rejected invalid schemaVersion=999 with HTTP 403 PERMISSION_DENIED")

    # 3. Missing metrics map must be rejected with HTTP 403 PERMISSION_DENIED
    no_metrics_payload = json.loads(json.dumps(payload))
    no_metrics_doc_id = f"{session_id}_no_metrics"[:MAX_SESSION_ID_LEN]
    no_metrics_payload["sessionId"] = no_metrics_doc_id
    no_metrics_payload["deviceInfo"]["sessionId"] = no_metrics_doc_id
    del no_metrics_payload["metrics"]
    status_no_metrics, body_no_metrics = _http_json_request(
        f"{base_docs_url}?documentId={urllib.parse.quote(no_metrics_doc_id)}",
        "POST",
        body=to_firestore_document(no_metrics_payload),
        headers=auth_header,
    )
    if status_no_metrics != 403:
        raise AssertionError(
            f"Expected HTTP 403 PERMISSION_DENIED when metrics is missing, got {status_no_metrics}: {body_no_metrics[:300]}"
        )
    print("[PASS] Live Firestore rejected payload missing 'metrics' with HTTP 403 PERMISSION_DENIED")

    # 4. Client GET on research_sessions must be blocked with HTTP 403 (allow read: if false)
    status_get, body_get = _http_json_request(
        f"{base_docs_url}/{urllib.parse.quote(session_id)}",
        "GET",
        headers=auth_header,
    )
    if status_get != 403:
        raise AssertionError(
            f"Expected HTTP 403 PERMISSION_DENIED for client GET on research_sessions/{session_id}, "
            f"got {status_get}: {body_get[:300]}"
        )
    print("[PASS] Live Firestore blocked client GET read with HTTP 403 PERMISSION_DENIED")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options for the Firebase telemetry verifier."""
    parser = argparse.ArgumentParser(
        description="Verify PQChat.DHT Firebase research telemetry schema and live ingestion."
    )
    parser.add_argument(
        "--require-credentials",
        action="store_true",
        help="Fail with non-zero exit code if Firebase credentials are not configured.",
    )
    parser.add_argument(
        "--offline-only",
        action="store_true",
        help="Run bundle and schema verification locally without contacting Firebase REST APIs.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point running local schema verification and optional live Firestore checks."""
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parent.parent

    run_id = os.environ.get("GITHUB_RUN_ID", "").strip()
    suffix = uuid.uuid4().hex[:8]
    session_id = f"ci_verify_{run_id}_{suffix}" if run_id else f"ci_verify_{suffix}"
    session_id = session_id[:MAX_SESSION_ID_LEN]

    payload, zip_bytes, checksums = build_synthetic_research_payload(session_id=session_id)
    run_local_schema_and_bundle_checks(payload, zip_bytes)
    print(
        f"[PASS] Synthetic research bundle verified locally "
        f"({len(zip_bytes)} bytes ZIP, {len(checksums)} CSV files, schemaVersion={payload['schemaVersion']})."
    )

    if args.offline_only:
        print("[SKIP] --offline-only requested; skipping live Firebase REST verification.")
        return 0

    creds = resolve_firebase_credentials(repo_root)
    if creds is None:
        if args.require_credentials:
            print(
                "[FAIL] Firebase credentials not found and --require-credentials was set.",
                file=sys.stderr,
            )
            return 1
        print(
            "[SKIP] Firebase credentials unavailable; live Firestore REST checks skipped."
        )
        return 0

    print(
        f"[INFO] Loaded Firebase configuration for project '{creds.project_id}' from {creds.source}."
    )
    verify_live_firestore_ingestion(creds, payload)
    print("[PASS] All Firebase research telemetry E2E checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
