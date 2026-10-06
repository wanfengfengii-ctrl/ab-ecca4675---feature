"""End-to-end HTTP tests against a live server instance."""

import base64
import hashlib
import http.client
import json
import os
import tempfile
import threading
import time
import unittest

from app import ed25519
from app.server import build_server

SEED = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1" "66d38535076f094b85ce3a2e0b4458f7")
PUB = ed25519.publickey(SEED)
KEY_ID = "http-vendor"


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class HttpCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.keys_path = os.path.join(cls.tmp.name, "keys.json")
        cls.db_path = os.path.join(cls.tmp.name, "att.db")
        with open(cls.keys_path, "w") as fh:
            json.dump({"keys": {KEY_ID: {
                "algorithm": "Ed25519",
                "publicKeyBase64": base64.b64encode(PUB).decode(),
            }}}, fh)
        cls.server = build_server("127.0.0.1", 0, cls.db_path, cls.keys_path)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def req(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json"} if body is not None else {}
        conn.request(method, path, body=json.dumps(body) if body is not None else None,
                     headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw) if raw else {}

    def attestation_body(self, att_id, device, gen, prev, config, *, bad_sig=False,
                         key_id=KEY_ID, restores=None):
        doc = {"deviceId": device, "generation": gen, "previousGeneration": prev,
               "configSha256": h(config)}
        if restores is not None:
            doc["restoresGeneration"] = restores
        payload = json.dumps(doc, separators=(",", ":")).encode()
        sig = b"\x00" * 64 if bad_sig else ed25519.sign(payload, SEED)
        return {
            "attestationId": att_id,
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload).decode(),
            "signatureBase64": base64.b64encode(sig).decode(),
        }

    def test_health(self):
        status, body = self.req("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_full_flow_and_head(self):
        body = self.attestation_body("att-1", "sat-1", 1, 0, b"config-v1")
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 201, resp)
        self.assertEqual(resp["status"], "accepted")

        status, resp = self.req("GET", "/api/devices/sat-1/head")
        self.assertEqual(status, 200)
        self.assertEqual(resp["generation"], 1)
        self.assertEqual(resp["configSha256"], h(b"config-v1"))

        # chain successor
        b2 = self.attestation_body("att-2", "sat-1", 2, 1, b"config-v2")
        status, resp = self.req("POST", "/api/attestations", b2)
        self.assertEqual(status, 201)

        status, resp = self.req("GET", "/api/devices/sat-1/head")
        self.assertEqual(resp["generation"], 2)

    def test_retry_is_idempotent(self):
        body = self.attestation_body("att-r", "sat-r", 1, 0, b"c")
        s1, r1 = self.req("POST", "/api/attestations", body)
        s2, r2 = self.req("POST", "/api/attestations", body)
        self.assertEqual((s1, r1["status"]), (201, "accepted"))
        self.assertEqual((s2, r2["status"]), (200, "duplicate"))

    def test_unknown_device_head(self):
        status, resp = self.req("GET", "/api/devices/ghost/head")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "DEVICE_NOT_FOUND")

    def test_unknown_key_error_code(self):
        body = self.attestation_body("x", "sat-x", 1, 0, b"c", key_id="missing")
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 401)
        self.assertEqual(resp["error"]["code"], "UNKNOWN_KEY_ID")

    def test_bad_signature_error_code(self):
        body = self.attestation_body("x", "sat-x", 1, 0, b"c", bad_sig=True)
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 401)
        self.assertEqual(resp["error"]["code"], "INVALID_SIGNATURE")

    def test_conflict_error_codes(self):
        self.req("POST", "/api/attestations",
                 self.attestation_body("c1", "sat-c", 1, 0, b"v1"))
        # stale predecessor: head is 1 but request claims predecessor 0
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("c2", "sat-c", 3, 0, b"v3"))
        self.assertEqual(s, 409)
        self.assertEqual(r["error"]["code"], "STALE_PREDECESSOR")
        # same id, different content
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("c1", "sat-c", 2, 1, b"v2"))
        self.assertEqual(r["error"]["code"], "ATTESTATION_ID_CONTENT_MISMATCH")
        # head not advanced
        s, head = self.req("GET", "/api/devices/sat-c/head")
        self.assertEqual(head["generation"], 1)
        self.assertEqual(head["configSha256"], h(b"v1"))

    def test_malformed_request(self):
        s, r = self.req("POST", "/api/attestations", {"attestationId": "z"})
        self.assertEqual(s, 400)
        self.assertEqual(r["error"]["code"], "MALFORMED_REQUEST")

    def test_restore_flow(self):
        self.req("POST", "/api/attestations",
                 self.attestation_body("rs-1", "sat-rs", 1, 0, b"v1"))
        self.req("POST", "/api/attestations",
                 self.attestation_body("rs-2", "sat-rs", 2, 1, b"v2"))

        # emergency restore: new generation 3 replicating generation 1's config
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("rs-3", "sat-rs", 3, 2, b"v1", restores=1))
        self.assertEqual(s, 201, r)
        self.assertEqual(r["status"], "accepted")
        self.assertEqual(r["restoresGeneration"], 1)
        self.assertEqual(r["configSha256"], h(b"v1"))

        s, head = self.req("GET", "/api/devices/sat-rs/head")
        self.assertEqual(s, 200)
        self.assertEqual(head["generation"], 3)
        self.assertEqual(head["restoresGeneration"], 1)
        self.assertEqual(head["configSha256"], h(b"v1"))

        # byte-identical retry of the restore replays the original outcome
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("rs-3", "sat-rs", 3, 2, b"v1", restores=1))
        self.assertEqual((s, r["status"]), (200, "duplicate"))
        self.assertEqual(r["restoresGeneration"], 1)

    def test_restore_conflict_codes(self):
        self.req("POST", "/api/attestations",
                 self.attestation_body("rc-1", "sat-rc", 1, 0, b"v1"))
        self.req("POST", "/api/attestations",
                 self.attestation_body("rc-2", "sat-rc", 2, 1, b"v2"))

        # source generation was never accepted
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("rc-3", "sat-rc", 3, 2, b"v1", restores=9))
        self.assertEqual(s, 409)
        self.assertEqual(r["error"]["code"], "RESTORE_SOURCE_NOT_FOUND")

        # source is the current head, not an earlier generation
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("rc-4", "sat-rc", 3, 2, b"v2", restores=2))
        self.assertEqual(s, 409)
        self.assertEqual(r["error"]["code"], "RESTORE_SOURCE_NOT_EARLIER")

        # digest does not match the historical record for generation 1
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("rc-5", "sat-rc", 3, 2, b"v2", restores=1))
        self.assertEqual(s, 409)
        self.assertEqual(r["error"]["code"], "RESTORE_CONFIG_MISMATCH")

        # none of the conflicts advanced the head
        s, head = self.req("GET", "/api/devices/sat-rc/head")
        self.assertEqual(head["generation"], 2)
        self.assertEqual(head["configSha256"], h(b"v2"))
        self.assertNotIn("restoresGeneration", head)

    def test_unknown_route(self):
        s, _ = self.req("GET", "/nope")
        self.assertEqual(s, 404)


if __name__ == "__main__":
    unittest.main()
