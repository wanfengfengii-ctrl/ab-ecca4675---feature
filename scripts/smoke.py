"""Signature-admission smoke test run inside the one-shot ``verify`` service.

It generates a fresh keypair, declares the public key, starts the real HTTP
server on an ephemeral port, exercises accept/retry/reject paths plus the
emergency-restore flow (valid restore, wrong-source rejections), then restarts
a second server against the same database to prove head persistence.

Exit code is non-zero (count of failures) if any check fails.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import ed25519
from app.server import build_server

FAILURES = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    print(f"[smoke:{mark}] {name}{(' - ' + detail) if detail and not condition else ''}")
    global FAILURES
    if not condition:
        FAILURES += 1


def request(port: int, method: str, path: str, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, body=json.dumps(body) if body is not None else None,
                 headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, (json.loads(raw) if raw else {})


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="smoke-")
    db_path = os.path.join(tmp, "att.db")
    keys_path = os.path.join(tmp, "keys.json")

    seed = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1" "66d38535076f094b85ce3a2e0b4458f7")
    public = ed25519.publickey(seed)
    key_id = "smoke-vendor"
    device = "smoke-sat-1"
    with open(keys_path, "w", encoding="utf-8") as fh:
        json.dump({"keys": {key_id: {
            "algorithm": "Ed25519",
            "publicKeyBase64": base64.b64encode(public).decode(),
            "deviceId": device,
        }}}, fh)

    server = build_server("127.0.0.1", 0, db_path, keys_path)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    try:
        status, body = request(port, "GET", "/healthz")
        check("healthz", status == 200 and body.get("status") == "ok", f"{status} {body}")

        config1 = b"smoke-config-v1"
        doc1 = {
            "deviceId": device,
            "generation": 1,
            "previousGeneration": 0,
            "configSha256": hashlib.sha256(config1).hexdigest(),
        }
        payload1 = json.dumps(doc1, separators=(",", ":")).encode()
        envelope = {
            "attestationId": "smoke-att-1",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload1).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(payload1, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", envelope)
        check("first attestation accepted (201)", status == 201, f"{status} {body}")

        # exact retry -> original result, no state change
        status, body = request(port, "POST", "/api/attestations", envelope)
        check("identical retry is duplicate (200)",
              status == 200 and body.get("status") == "duplicate", f"{status} {body}")

        # wrong signature rejected, state untouched
        bad = dict(envelope)
        bad["signatureBase64"] = base64.b64encode(b"\x00" * 64).decode()
        status, body = request(port, "POST", "/api/attestations", bad)
        check("bad signature rejected",
              status == 401 and body["error"]["code"] == "INVALID_SIGNATURE", f"{status} {body}")

        # unknown key rejected
        bad_key = dict(envelope)
        bad_key["attestationId"] = "smoke-att-x"
        bad_key["keyId"] = "does-not-exist"
        status, body = request(port, "POST", "/api/attestations", bad_key)
        check("unknown key rejected",
              status == 401 and body["error"]["code"] == "UNKNOWN_KEY_ID", f"{status} {body}")

        # successor chaining
        config2 = b"smoke-config-v2"
        doc2 = {"deviceId": device, "generation": 2, "previousGeneration": 1,
                "configSha256": hashlib.sha256(config2).hexdigest()}
        payload2 = json.dumps(doc2, separators=(",", ":")).encode()
        env2 = {
            "attestationId": "smoke-att-2",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload2).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(payload2, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", env2)
        check("successor accepted (201)", status == 201, f"{status} {body}")

        # stale predecessor conflict (claims 0 while head is 2)
        doc_stale = {"deviceId": device, "generation": 9, "previousGeneration": 0,
                     "configSha256": hashlib.sha256(b"x").hexdigest()}
        p_stale = json.dumps(doc_stale, separators=(",", ":")).encode()
        env_stale = {
            "attestationId": "smoke-att-stale",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(p_stale).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(p_stale, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", env_stale)
        check("stale predecessor conflict",
              status == 409 and body["error"]["code"] == "STALE_PREDECESSOR",
              f"{status} {body}")

        status, body = request(port, "GET", f"/api/devices/{device}/head")
        check("head is generation 2 with v2 digest",
              status == 200 and body.get("generation") == 2
              and body.get("configSha256") == hashlib.sha256(config2).hexdigest(),
              f"{status} {body}")

        # jump to generation 5, leaving 3 and 4 never accepted
        config3 = b"smoke-config-v3"
        doc5 = {"deviceId": device, "generation": 5, "previousGeneration": 2,
                "configSha256": hashlib.sha256(config3).hexdigest()}
        payload5 = json.dumps(doc5, separators=(",", ":")).encode()
        env5 = {
            "attestationId": "smoke-att-5",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload5).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(payload5, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", env5)
        check("gapped successor accepted (201)", status == 201, f"{status} {body}")

        # ---- restore flow ------------------------------------------------
        # emergency restore of the generation-1 config, chained as gen 6
        doc6 = {"deviceId": device, "generation": 6, "previousGeneration": 5,
                "configSha256": hashlib.sha256(config1).hexdigest(),
                "restoresGeneration": 1}
        payload6 = json.dumps(doc6, separators=(",", ":")).encode()
        env6 = {
            "attestationId": "smoke-att-6",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload6).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(payload6, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", env6)
        check("restore accepted (201) with source",
              status == 201 and body.get("restoresGeneration") == 1, f"{status} {body}")

        # identical retry of the restore -> duplicate, same source, no new state
        status, body = request(port, "POST", "/api/attestations", env6)
        check("restore retry is duplicate with source",
              status == 200 and body.get("status") == "duplicate"
              and body.get("restoresGeneration") == 1, f"{status} {body}")

        status, body = request(port, "GET", f"/api/devices/{device}/head")
        check("head reports restore source",
              status == 200 and body.get("generation") == 6
              and body.get("restoresGeneration") == 1
              and body.get("configSha256") == hashlib.sha256(config1).hexdigest(),
              f"{status} {body}")

        # wrong restore sources are rejected with stable codes, state untouched
        def restore_env(att_id, restores, config, gen=7, prev=6):
            doc = {"deviceId": device, "generation": gen, "previousGeneration": prev,
                   "configSha256": hashlib.sha256(config).hexdigest(),
                   "restoresGeneration": restores}
            p = json.dumps(doc, separators=(",", ":")).encode()
            return {
                "attestationId": att_id,
                "keyId": key_id,
                "payloadBase64": base64.b64encode(p).decode(),
                "signatureBase64": base64.b64encode(ed25519.sign(p, seed)).decode(),
            }

        # generation 4 is behind the head but was never accepted
        status, body = request(port, "POST", "/api/attestations",
                               restore_env("smoke-att-bad1", 4, config1))
        check("restore of unknown generation rejected",
              status == 409 and body["error"]["code"] == "RESTORE_TARGET_NOT_FOUND",
              f"{status} {body}")

        # the current head itself is not an earlier generation
        status, body = request(port, "POST", "/api/attestations",
                               restore_env("smoke-att-bad2", 6, config1))
        check("restore of non-earlier generation rejected",
              status == 409 and body["error"]["code"] == "RESTORE_TARGET_NOT_EARLIER",
              f"{status} {body}")

        # gen 2 recorded config2's digest, not config1's
        status, body = request(port, "POST", "/api/attestations",
                               restore_env("smoke-att-bad3", 2, config1))
        check("restore with mismatched digest rejected",
              status == 409 and body["error"]["code"] == "RESTORE_CONFIG_MISMATCH",
              f"{status} {body}")

        status, body = request(port, "GET", f"/api/devices/{device}/head")
        check("rejections left head at generation 6",
              status == 200 and body.get("generation") == 6
              and body.get("restoresGeneration") == 1, f"{status} {body}")
    finally:
        server.shutdown()
        server.server_close()

    # ---- restart: brand new server process against the same database -------
    server2 = build_server("127.0.0.1", 0, db_path, keys_path)
    port2 = server2.server_address[1]
    t2 = threading.Thread(target=server2.serve_forever, daemon=True)
    t2.start()
    time.sleep(0.1)
    try:
        status, body = request(port2, "GET", f"/api/devices/{device}/head")
        check("head (with restore source) survives restart",
              status == 200 and body.get("generation") == 6
              and body.get("restoresGeneration") == 1
              and body.get("configSha256") == hashlib.sha256(config1).hexdigest()
              and body.get("attestationId") == "smoke-att-6",
              f"{status} {body}")

        # retrying the restore after the restart replays the same outcome
        status, body = request(port2, "POST", "/api/attestations", env6)
        check("restore retry after restart is duplicate",
              status == 200 and body.get("status") == "duplicate"
              and body.get("restoresGeneration") == 1, f"{status} {body}")

        # unknown device
        status, body = request(port2, "GET", "/api/devices/unknown/head")
        check("unknown device 404", status == 404
              and body["error"]["code"] == "DEVICE_NOT_FOUND", f"{status} {body}")
    finally:
        server2.shutdown()
        server2.server_close()

    print(f"[smoke] {FAILURES} failure(s)")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
