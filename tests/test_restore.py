"""Emergency-restore rules: signed payloads carrying ``restoresGeneration``.

A restore rolls the chain *forward* to a new generation whose config digest
replicates a previously accepted one. The historical source must exist for the
same device, lie strictly before the current head, and match the digest.
"""

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest

from app import ed25519
from app.admit import Admitter
from app.store import Store

SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PUB = ed25519.publickey(SEED)
KEY_ID = "vendor-1"


def digest(config: bytes) -> str:
    return hashlib.sha256(config).hexdigest()


class RestoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "att.db")
        self.store = Store(self.db)
        self.admitter = Admitter(self.store, {KEY_ID: PUB}, {KEY_ID: None})

    def tearDown(self):
        self.tmp.cleanup()

    def submit(self, att_id, device, gen, prev, config, *, restores=None):
        doc = {
            "deviceId": device,
            "generation": gen,
            "previousGeneration": prev,
            "configSha256": digest(config),
        }
        if restores is not None:
            doc["restoresGeneration"] = restores
        return self.submit_doc(att_id, doc)

    def submit_doc(self, att_id, doc):
        payload = json.dumps(doc, separators=(",", ":")).encode("utf-8")
        sig = ed25519.sign(payload, SEED)
        decision = self.admitter.admit(
            attestation_id=att_id,
            key_id=KEY_ID,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        )
        return decision, payload, sig

    def chain(self, n, device="dev"):
        """Accept generations 1..n with config b"cfg-<i>"."""
        for i in range(1, n + 1):
            d, _, _ = self.submit(f"root-{i}", device, i, i - 1, f"cfg-{i}".encode())
            self.assertTrue(d.accepted)

    # ------------------------------------------------------------- happy path
    def test_valid_restore_rolls_forward(self):
        self.chain(3)
        d, _, _ = self.submit("r1", "dev", 4, 3, b"cfg-1", restores=1)
        self.assertTrue(d.accepted, d)
        self.assertEqual(d.status, 201)
        self.assertEqual(d.record["restoresGeneration"], 1)

        head = self.admitter.head("dev")
        self.assertEqual(head["generation"], 4)
        self.assertEqual(head["previousGeneration"], 3)
        self.assertEqual(head["configSha256"], digest(b"cfg-1"))
        self.assertEqual(head["restoresGeneration"], 1)

    def test_chain_continues_after_restore(self):
        self.chain(3)
        self.assertTrue(self.submit("r1", "dev", 4, 3, b"cfg-1", restores=1)[0].accepted)
        # plain successor on top of the restore carries no restore marker
        d, _, _ = self.submit("n5", "dev", 5, 4, b"cfg-9")
        self.assertTrue(d.accepted)
        head = self.admitter.head("dev")
        self.assertEqual(head["generation"], 5)
        self.assertNotIn("restoresGeneration", head)
        # a second restore to a different historical generation still works
        d2, _, _ = self.submit("r2", "dev", 6, 5, b"cfg-2", restores=2)
        self.assertTrue(d2.accepted)
        self.assertEqual(self.admitter.head("dev")["restoresGeneration"], 2)

    def test_plain_attestation_has_no_restore_field(self):
        d, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertTrue(d.accepted)
        self.assertNotIn("restoresGeneration", d.record)
        self.assertNotIn("restoresGeneration", self.admitter.head("dev"))

    # -------------------------------------------------------------- conflicts
    def test_restore_unknown_source_conflict(self):
        self.chain(3)
        d, _, _ = self.submit("r1", "dev", 4, 3, b"cfg-1", restores=7)
        self.assertFalse(d.accepted)
        self.assertEqual(d.status, 409)
        self.assertEqual(d.code, "RESTORE_SOURCE_NOT_FOUND")
        # beyond the head it cannot exist either
        d2, _, _ = self.submit("r2", "dev", 4, 3, b"cfg-1", restores=99)
        self.assertEqual(d2.code, "RESTORE_SOURCE_NOT_FOUND")
        # state untouched
        self.assertEqual(self.admitter.head("dev")["generation"], 3)
        self.assertEqual(self.store.accepted_generations("dev"), [1, 2, 3])

    def test_restore_source_must_precede_head(self):
        self.chain(3)
        # restoring the current head itself is not an emergency restore
        d, _, _ = self.submit("r1", "dev", 4, 3, b"cfg-3", restores=3)
        self.assertFalse(d.accepted)
        self.assertEqual(d.status, 409)
        self.assertEqual(d.code, "RESTORE_SOURCE_NOT_EARLIER")
        self.assertEqual(self.admitter.head("dev")["generation"], 3)

    def test_restore_digest_mismatch_conflict(self):
        self.chain(3)
        # claims to restore generation 1 but carries generation 2's digest
        d, _, _ = self.submit("r1", "dev", 4, 3, b"cfg-2", restores=1)
        self.assertFalse(d.accepted)
        self.assertEqual(d.status, 409)
        self.assertEqual(d.code, "RESTORE_CONFIG_MISMATCH")
        self.assertEqual(self.admitter.head("dev")["generation"], 3)
        self.assertEqual(self.admitter.head("dev")["configSha256"], digest(b"cfg-3"))

    def test_restore_without_history_conflict(self):
        # no accepted generation exists at all -> nothing to restore
        d, _, _ = self.submit("r0", "dev", 1, 0, b"cfg-1", restores=1)
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "RESTORE_SOURCE_NOT_FOUND")
        self.assertIsNone(self.admitter.head("dev"))

    def test_restore_source_is_per_device(self):
        self.chain(2, device="dev-A")
        # dev-B has no history; generation 1 of dev-A must not leak over
        d, _, _ = self.submit("rb", "dev-B", 1, 0, b"cfg-1", restores=1)
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "RESTORE_SOURCE_NOT_FOUND")
        self.assertIsNone(self.admitter.head("dev-B"))

    def test_restore_must_chain_current_head(self):
        self.chain(3)
        # predecessor 2 while head is 3: stale, even with a valid source
        d, _, _ = self.submit("r1", "dev", 4, 2, b"cfg-1", restores=1)
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "STALE_PREDECESSOR")
        self.assertEqual(self.admitter.head("dev")["generation"], 3)

    def test_restore_generation_must_increase(self):
        self.submit("g1", "dev", 10, 0, b"cfg-1")
        self.submit("g2", "dev", 25, 10, b"cfg-2")
        # 20 was never accepted and does not advance the head
        d, _, _ = self.submit("r1", "dev", 20, 25, b"cfg-1", restores=10)
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "GENERATION_NOT_GREATER")
        # reusing an accepted generation conflicts on content
        d2, _, _ = self.submit("r2", "dev", 25, 25, b"cfg-1", restores=10)
        self.assertEqual(d2.code, "GENERATION_CONTENT_CONFLICT")
        self.assertEqual(self.admitter.head("dev")["generation"], 25)

    def test_restore_field_type_validation(self):
        self.chain(2)
        base = {
            "deviceId": "dev",
            "generation": 3,
            "previousGeneration": 2,
            "configSha256": digest(b"cfg-1"),
        }
        for bad in ("1", 1.5, True, -1, None):
            doc = {**base, "restoresGeneration": bad}
            d, _, _ = self.submit_doc(f"bad-{bad!r}", doc)
            self.assertFalse(d.accepted, bad)
            self.assertEqual(d.status, 400, bad)
            self.assertEqual(d.code, "INVALID_JSON_PAYLOAD", bad)
        self.assertEqual(self.admitter.head("dev")["generation"], 2)

    # -------------------------------------------------- retry and persistence
    def test_restore_retry_replays_original(self):
        self.chain(2)
        d1, payload, sig = self.submit("r1", "dev", 3, 2, b"cfg-1", restores=1)
        self.assertEqual(d1.status, 201)
        self.assertEqual(d1.record["restoresGeneration"], 1)
        before = self.store.accepted_generations("dev")

        retry = self.admitter.admit(
            attestation_id="r1",
            key_id=KEY_ID,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        )
        self.assertTrue(retry.accepted)
        self.assertEqual(retry.status, 200)
        self.assertTrue(retry.duplicate)
        self.assertEqual(retry.record["restoresGeneration"], 1)
        self.assertEqual(self.store.accepted_generations("dev"), before)

    def test_restore_survives_reopen(self):
        self.chain(2)
        self.submit("r1", "dev", 3, 2, b"cfg-1", restores=1)
        store2 = Store(self.db)
        adm2 = Admitter(store2, {KEY_ID: PUB}, {KEY_ID: None})
        head = adm2.head("dev")
        self.assertEqual(head["generation"], 3)
        self.assertEqual(head["restoresGeneration"], 1)
        self.assertEqual(head["configSha256"], digest(b"cfg-1"))

    def test_legacy_database_is_migrated(self):
        # a database created before restoresGeneration existed
        legacy = os.path.join(self.tmp.name, "legacy.db")
        conn = sqlite3.connect(legacy)
        conn.execute(
            "CREATE TABLE attestations ("
            " device_id TEXT NOT NULL, generation INTEGER NOT NULL,"
            " previous_generation INTEGER NOT NULL, config_sha256 TEXT NOT NULL,"
            " attestation_id TEXT NOT NULL, payload_sha256 TEXT NOT NULL,"
            " accepted_at TEXT NOT NULL,"
            " PRIMARY KEY (device_id, generation), UNIQUE (attestation_id))"
        )
        for gen, cfg in ((1, b"cfg-1"), (2, b"cfg-2")):
            conn.execute(
                "INSERT INTO attestations VALUES (?,?,?,?,?,?,?)",
                ("dev", gen, gen - 1, digest(cfg), f"old-{gen}", "x" * 64,
                 "2026-01-01T00:00:00Z"),
            )
        conn.commit()
        conn.close()

        store = Store(legacy)  # migrates in place
        adm = Admitter(store, {KEY_ID: PUB}, {KEY_ID: None})
        head = adm.head("dev")
        self.assertEqual(head["generation"], 2)
        self.assertNotIn("restoresGeneration", head)

        self.store, self.admitter, self.db = store, adm, legacy
        d, _, _ = self.submit("r1", "dev", 3, 2, b"cfg-1", restores=1)
        self.assertTrue(d.accepted, d)
        self.assertEqual(adm.head("dev")["restoresGeneration"], 1)

    # -------------------------------------------------------------- concurrency
    def test_concurrent_restore_and_successor_single_winner(self):
        self.chain(2)  # head = 2
        results = []
        lock = threading.Lock()

        def worker(att_id, gen, config, restores):
            d, _, _ = self.submit(att_id, "dev", gen, 2, config, restores=restores)
            with lock:
                results.append((att_id, d.accepted, d.code))

        threads = [
            threading.Thread(target=worker, args=("plain-3", 3, b"cfg-3", None)),
            threading.Thread(target=worker, args=("restore-4", 4, b"cfg-1", 1)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        winners = [r for r in results if r[1]]
        self.assertEqual(len(winners), 1, results)
        losers = [r for r in results if not r[1]]
        self.assertEqual(len(losers), 1, results)
        self.assertIn(losers[0][2], {"STALE_PREDECESSOR", "CONCURRENT_UPDATE"})

        # exactly one new generation chains off generation 2
        head = self.admitter.head("dev")
        if winners[0][0] == "restore-4":
            self.assertEqual(head["generation"], 4)
            self.assertEqual(head["restoresGeneration"], 1)
            self.assertEqual(head["configSha256"], digest(b"cfg-1"))
        else:
            self.assertEqual(head["generation"], 3)
            self.assertEqual(head["configSha256"], digest(b"cfg-3"))
            self.assertNotIn("restoresGeneration", head)
        self.assertEqual(sorted(self.store.accepted_generations("dev")),
                         [1, 2, head["generation"]])


if __name__ == "__main__":
    unittest.main()
