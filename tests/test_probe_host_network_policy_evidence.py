"""Tests for target host network policy evidence probing."""

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE_SCRIPT = ROOT / "scripts" / "probe_host_network_policy_evidence.py"

PROBE_SPEC = importlib.util.spec_from_file_location(
    "probe_host_network_policy_evidence", PROBE_SCRIPT
)
probe = importlib.util.module_from_spec(PROBE_SPEC)
assert PROBE_SPEC.loader is not None
sys.modules[PROBE_SPEC.name] = probe
PROBE_SPEC.loader.exec_module(probe)


def _command_runner(args, timeout):
    if args[:2] == ["ss", "-ltnp"]:
        return probe.CommandResult(
            args,
            0,
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(nginx)\n",
            "",
        )
    if args[:2] == ["netstat", "-ltnp"]:
        return probe.CommandResult(args, 1, "", "not installed")
    if args[:2] == ["nft", "list"]:
        return probe.CommandResult(
            args,
            0,
            "table inet filter { chain input { tcp dport 443 accept } }\n",
            "",
        )
    return probe.CommandResult(args, 1, "", "not configured")


def _preflight_client(base_url, origin, timeout):
    return 204, {"Access-Control-Allow-Origin": origin}, ""


def _tls_client(host, port, timeout):
    return {
        "version": "TLSv1.3",
        "cipher": ["TLS_AES_256_GCM_SHA384", "TLSv1.3", 256],
        "subject": [[["commonName", host]]],
        "issuer": [[["commonName", "Test CA"]]],
        "notBefore": "Jul 13 00:00:00 2026 GMT",
        "notAfter": "Jul 13 00:00:00 2027 GMT",
        "subjectAltName": [["DNS", host]],
    }


def test_host_network_policy_probe_writes_passing_artifact(tmp_path):
    output = tmp_path / "host-network-policy.json"
    artifact = probe.run_probe(
        base_url="https://prod.example",
        expected_origin="https://app.example",
        expected_ports=[443],
        allow_http=False,
        timeout=1,
        captured_at_utc="2026-07-13T04:00:00Z",
        system_name="Linux",
        command_runner=_command_runner,
        preflight_client=_preflight_client,
        tls_client=_tls_client,
    )
    probe.write_artifact(output, artifact)
    saved = json.loads(output.read_text(encoding="utf-8"))

    assert artifact["summary"]["passed"] is True
    assert saved["evidence_type"] == "host_network_policy"
    assert saved["host"]["evidence_system"] == "Linux"
    assert saved["captured_output_hashes"]["listening_ports_sha256"]
    assert saved["captured_output_hashes"]["firewall_policy_sha256"]
    assert {check["name"] for check in saved["checks"]} >= {
        "listening_ports_captured",
        "expected_ports_visible",
        "firewall_policy_captured",
        "tls_certificate_captured",
        "cors_origin_enforced",
    }


def test_host_network_policy_probe_fails_for_wildcard_cors():
    def preflight_client(base_url, origin, timeout):
        return 204, {"Access-Control-Allow-Origin": "*"}, ""

    artifact = probe.run_probe(
        base_url="https://prod.example",
        expected_origin="https://app.example",
        expected_ports=[443],
        allow_http=False,
        timeout=1,
        captured_at_utc="2026-07-13T04:00:00Z",
        system_name="Linux",
        command_runner=_command_runner,
        preflight_client=preflight_client,
        tls_client=_tls_client,
    )
    cors_check = next(
        check
        for check in artifact["checks"]
        if check["name"] == "cors_origin_enforced"
    )

    assert artifact["summary"]["passed"] is False
    assert cors_check["passed"] is False
