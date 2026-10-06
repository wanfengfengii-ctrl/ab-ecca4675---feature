"""Admission-rule, persistence, retry and concurrency tests."""

import base64
import hashlib
import json
import os
import tempfile
import threading
import unittest

from app import ed25519
from app.admit import Admitter
from app.config import load_key_bindings, load_keys
from app.store import Store

SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PUB = ed25519.publickey(SEED)
KEY_ID = "vendor-1"

SEED2 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4" "4449c5697b326919703bac031cae7f60")
PUB2 = ed25519.publickey(SEED2)
KEY_ID2 = "vendor-2"


def digest(config: bytes) -> str:
    return hashlib.sha256(config).hexdigest()


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "att.db")
        self.store = Store(self.db)
        self.admitter = Admitter(
            self.store,
            {KEY_ID: PUB, KEY_ID2: PUB2},
            {KEY_ID: None, KEY_ID2: None},
        )

    def tearDown(self):
        self.tmp.cleanup()

    def submit(self, att_id, device, gen, prev, config, *, key_id=KEY_ID, seed=SEED, extra=None):
        doc = {
            "deviceId": device,
            "generation": gen,
            "previousGeneration": prev,
            "configSha256": digest(config),
        }
        if extra:
            doc.update(extra)
        payload = json.dumps(doc, separators=(",", ":")).encode("utf-8")
        sig = ed25519.sign(payload, seed)
        return self.admitter.admit(
            attestation_id=att_id,
            key_id=key_id,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        ), payload, sig

    def test_first_must_have_zero_predecessor(self):
        d, _, _ = self.submit("a1", "dev", 1, 1, b"cfg-1")
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "FIRST_PREDECESSOR_NOT_ZERO")
        self.assertIsNone(self.admitter.head("dev"))

    def test_generation_zero_rejected(self):
        d, _, _ = self.submit("a0", "dev", 0, 0, b"cfg-0")
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "GENERATION_ZERO")

    def test_happy_path_chain(self):
        d1, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertTrue(d1.accepted)
        self.assertEqual(d1.status, 201)
        self.assertEqual(d1.record["generation"], 1)

        d2, _, _ = self.submit("a2", "dev", 2, 1, b"cfg-2")
        self.assertTrue(d2.accepted)
        self.assertEqual(d2.status, 201)

        head = self.admitter.head("dev")
        self.assertEqual(head["generation"], 2)
        self.assertEqual(head["configSha256"], digest(b"cfg-2"))

    def test_exact_retry_returns_original(self):
        d1, payload, sig = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertEqual(d1.status, 201)
        before = self.store.accepted_generations("dev")
        # identical request bytes -> replay, no new row
        r = self.admitter.admit(
            attestation_id="a1",
            key_id=KEY_ID,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        )
        self.assertTrue(r.accepted)
        self.assertEqual(r.status, 200)
        self.assertTrue(r.duplicate)
        self.assertEqual(self.store.accepted_generations("dev"), before)

    def test_same_id_different_content_conflicts(self):
        d1, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertTrue(d1.accepted)
        d2, _, _ = self.submit("a1", "dev", 2, 1, b"cfg-2")
        self.assertFalse(d2.accepted)
        self.assertEqual(d2.code, "ATTESTATION_ID_CONTENT_MISMATCH")
        # state unchanged
        self.assertEqual(self.admitter.head("dev")["generation"], 1)

    def test_same_generation_different_content_conflicts(self):
        d1, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertTrue(d1.accepted)
        # new id but same generation, different config
        d2, _, _ = self.submit("a2", "dev", 1, 0, b"cfg-OTHER")
        self.assertFalse(d2.accepted)
        self.assertEqual(d2.code, "GENERATION_CONTENT_CONFLICT")
        self.assertEqual(self.admitter.head("dev")["configSha256"], digest(b"cfg-1"))

    def test_stale_predecessor_is_conflict(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        # replay an old attestation against head 2
        d3, _, _ = self.submit("a3", "dev", 3, 1, b"cfg-3")
        self.assertFalse(d3.accepted)
        self.assertEqual(d3.code, "STALE_PREDECESSOR")
        self.assertEqual(self.admitter.head("dev")["generation"], 2)

    def test_generation_must_increase(self):
        self.submit("a1", "dev", 5, 0, b"cfg-1")
        d, _, _ = self.submit("a2", "dev", 5, 5, b"cfg-2")
        self.assertEqual(d.code, "GENERATION_CONTENT_CONFLICT")  # gen exists
        d2, _, _ = self.submit("a3", "dev", 4, 5, b"cfg-x")
        self.assertEqual(d2.code, "GENERATION_NOT_GREATER")
        self.assertEqual(self.admitter.head("dev")["generation"], 5)

    def test_non_increasing_gaps_allowed(self):
        # generations need not be consecutive
        d, _, _ = self.submit("a1", "dev", 10, 0, b"cfg-1")
        self.assertTrue(d.accepted)
        d2, _, _ = self.submit("a2", "dev", 25, 10, b"cfg-2")
        self.assertTrue(d2.accepted)

    # ---------------------------------------------------------------- restore
    def test_plain_attestation_reports_null_restore(self):
        d, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertTrue(d.accepted)
        self.assertIsNone(d.record["restoresGeneration"])
        self.assertIsNone(self.admitter.head("dev")["restoresGeneration"])

    def test_restore_accepted_and_reported(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        # emergency restore of the generation-1 config, still moving forward
        d, _, _ = self.submit("a3", "dev", 3, 2, b"cfg-1",
                              extra={"restoresGeneration": 1})
        self.assertTrue(d.accepted)
        self.assertEqual(d.status, 201)
        self.assertEqual(d.record["restoresGeneration"], 1)
        self.assertEqual(d.record["generation"], 3)
        head = self.admitter.head("dev")
        self.assertEqual(head["generation"], 3)
        self.assertEqual(head["configSha256"], digest(b"cfg-1"))
        self.assertEqual(head["restoresGeneration"], 1)

    def test_restore_can_target_a_restore(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        self.submit("a3", "dev", 3, 2, b"cfg-1", extra={"restoresGeneration": 1})
        self.submit("a4", "dev", 4, 3, b"cfg-4")
        # generation 3 is itself a restore; restoring it again is fine
        d, _, _ = self.submit("a5", "dev", 5, 4, b"cfg-1",
                              extra={"restoresGeneration": 3})
        self.assertTrue(d.accepted)
        self.assertEqual(d.record["restoresGeneration"], 3)

    def test_restore_target_must_exist(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 5, 1, b"cfg-5")  # gap: 2..4 never accepted
        # generation 3 is behind the head but was never accepted
        d, _, _ = self.submit("a3", "dev", 6, 5, b"cfg-1",
                              extra={"restoresGeneration": 3})
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "RESTORE_TARGET_NOT_FOUND")
        self.assertEqual(d.status, 409)
        self.assertEqual(self.admitter.head("dev")["generation"], 5)

    def test_restore_without_any_history_rejected(self):
        d, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1",
                              extra={"restoresGeneration": 0})
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "RESTORE_TARGET_NOT_FOUND")
        self.assertIsNone(self.admitter.head("dev"))

    def test_restore_target_must_be_earlier_than_head(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        # equal to the current head is not "an earlier generation"
        d, _, _ = self.submit("a3", "dev", 3, 2, b"cfg-2",
                              extra={"restoresGeneration": 2})
        self.assertEqual(d.code, "RESTORE_TARGET_NOT_EARLIER")
        # ahead of the head (also not accepted anywhere)
        d2, _, _ = self.submit("a4", "dev", 3, 2, b"cfg-2",
                               extra={"restoresGeneration": 9})
        self.assertEqual(d2.code, "RESTORE_TARGET_NOT_EARLIER")
        self.assertEqual(self.admitter.head("dev")["generation"], 2)

    def test_restore_digest_must_match_history(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        # generation 1 accepted cfg-1, not cfg-OTHER
        d, _, _ = self.submit("a3", "dev", 3, 2, b"cfg-OTHER",
                              extra={"restoresGeneration": 1})
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "RESTORE_CONFIG_MISMATCH")
        self.assertEqual(d.status, 409)
        head = self.admitter.head("dev")
        self.assertEqual(head["generation"], 2)
        self.assertIsNone(head["restoresGeneration"])

    def test_restore_still_chains_head(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        # a restore does not exempt the attestation from the chain rules
        d, _, _ = self.submit("a3", "dev", 3, 1, b"cfg-1",
                              extra={"restoresGeneration": 1})
        self.assertEqual(d.code, "STALE_PREDECESSOR")
        self.assertEqual(self.admitter.head("dev")["generation"], 2)

    def test_restore_still_requires_forward_generation(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 5, 1, b"cfg-5")  # gap: head is 5
        d, _, _ = self.submit("a3", "dev", 3, 5, b"cfg-1",
                              extra={"restoresGeneration": 1})
        self.assertEqual(d.code, "GENERATION_NOT_GREATER")

    def test_restore_retry_is_duplicate_with_source(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        d1, payload, sig = self.submit("a3", "dev", 3, 2, b"cfg-1",
                                       extra={"restoresGeneration": 1})
        self.assertEqual(d1.status, 201)
        # byte-identical retry replays the original outcome, source included
        r = self.admitter.admit(
            attestation_id="a3",
            key_id=KEY_ID,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        )
        self.assertTrue(r.accepted)
        self.assertEqual(r.status, 200)
        self.assertTrue(r.duplicate)
        self.assertEqual(r.record["restoresGeneration"], 1)
        self.assertEqual(self.store.accepted_generations("dev"), [1, 2, 3])

    def test_restore_survives_reopen(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        self.submit("a3", "dev", 3, 2, b"cfg-1", extra={"restoresGeneration": 1})
        store2 = Store(self.db)
        adm2 = Admitter(store2, {KEY_ID: PUB}, {KEY_ID: None})
        head = adm2.head("dev")
        self.assertEqual(head["generation"], 3)
        self.assertEqual(head["restoresGeneration"], 1)
        self.assertEqual(head["configSha256"], digest(b"cfg-1"))

    def test_restore_payload_field_validation(self):
        # bool must not be accepted as an integer
        d, _, _ = self.submit("a1", "dev", 1, 0, b"c",
                              extra={"restoresGeneration": True})
        self.assertEqual(d.code, "INVALID_JSON_PAYLOAD")
        d2, _, _ = self.submit("a2", "dev", 1, 0, b"c",
                               extra={"restoresGeneration": "1"})
        self.assertEqual(d2.code, "INVALID_JSON_PAYLOAD")
        d3, _, _ = self.submit("a3", "dev", 1, 0, b"c",
                               extra={"restoresGeneration": -1})
        self.assertEqual(d3.code, "INVALID_JSON_PAYLOAD")
        self.assertIsNone(self.admitter.head("dev"))

    def test_legacy_database_is_migrated(self):
        import sqlite3

        legacy_db = os.path.join(self.tmp.name, "legacy.db")
        conn = sqlite3.connect(legacy_db)
        conn.execute(
            "CREATE TABLE attestations ("
            " device_id TEXT NOT NULL, generation INTEGER NOT NULL,"
            " previous_generation INTEGER NOT NULL, config_sha256 TEXT NOT NULL,"
            " attestation_id TEXT NOT NULL, payload_sha256 TEXT NOT NULL,"
            " accepted_at TEXT NOT NULL,"
            " PRIMARY KEY (device_id, generation), UNIQUE (attestation_id))"
        )
        conn.execute(
            "INSERT INTO attestations VALUES ('dev', 1, 0, ?, 'a1', ?, ?)",
            (digest(b"cfg-1"), digest(b"payload-1"), "2026-01-01T00:00:00Z"),
        )
        conn.execute(
            "INSERT INTO attestations VALUES ('dev', 2, 1, ?, 'a2', ?, ?)",
            (digest(b"cfg-2"), digest(b"payload-2"), "2026-01-02T00:00:00Z"),
        )
        conn.commit()
        conn.close()

        store = Store(legacy_db)  # migrates the old schema in place
        adm = Admitter(store, {KEY_ID: PUB}, {KEY_ID: None})
        head = adm.head("dev")
        self.assertEqual(head["generation"], 2)
        self.assertIsNone(head["restoresGeneration"])
        # a restore may target a generation accepted before the migration
        d, _, _ = self._submit_to(adm, "a3", "dev", 3, 2, b"cfg-1",
                                  extra={"restoresGeneration": 1})
        self.assertTrue(d.accepted)
        self.assertEqual(d.record["restoresGeneration"], 1)

    def _submit_to(self, admitter, att_id, device, gen, prev, config, *, extra=None):
        doc = {
            "deviceId": device,
            "generation": gen,
            "previousGeneration": prev,
            "configSha256": digest(config),
        }
        if extra:
            doc.update(extra)
        payload = json.dumps(doc, separators=(",", ":")).encode("utf-8")
        sig = ed25519.sign(payload, SEED)
        return admitter.admit(
            attestation_id=att_id,
            key_id=KEY_ID,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        ), payload, sig

    def test_unknown_key(self):
        d, _, _ = self.submit("a1", "dev", 1, 0, b"cfg-1", key_id="nope", seed=SEED)
        self.assertFalse(d.accepted)
        self.assertEqual(d.code, "UNKNOWN_KEY_ID")
        self.assertEqual(d.status, 401)
        self.assertIsNone(self.admitter.head("dev"))

    def test_bad_signature(self):
        doc = {"deviceId": "dev", "generation": 1, "previousGeneration": 0,
               "configSha256": digest(b"cfg-1")}
        payload = json.dumps(doc).encode()
        d = self.admitter.admit("a1", KEY_ID,
                                base64.b64encode(payload).decode(),
                                base64.b64encode(b"\x00" * 64).decode())
        self.assertEqual(d.code, "INVALID_SIGNATURE")
        # flip one payload byte but reuse signature -> invalid signature
        tampered = payload.replace(b"cfg-1", b"cfg-2", 1) if b"cfg-1" in payload else payload
        sig = ed25519.sign(payload, SEED)
        # build a distinct payload signed for a different message
        other = json.dumps({**doc, "generation": 2}).encode()
        d2 = self.admitter.admit("a1", KEY_ID,
                                 base64.b64encode(other).decode(),
                                 base64.b64encode(sig).decode())
        self.assertEqual(d2.code, "INVALID_SIGNATURE")

    def test_wrong_device_key_binding(self):
        adm = Admitter(self.store, {KEY_ID: PUB}, {KEY_ID: "bound-dev"})
        doc = {"deviceId": "other-dev", "generation": 1, "previousGeneration": 0,
               "configSha256": digest(b"c")}
        payload = json.dumps(doc).encode()
        sig = ed25519.sign(payload, SEED)
        d = adm.admit("a1", KEY_ID, base64.b64encode(payload).decode(),
                      base64.b64encode(sig).decode())
        self.assertEqual(d.code, "KEY_NOT_BOUND_TO_DEVICE")

    def test_malformed_payload_encoding(self):
        sig = ed25519.sign(b"\xff\xfe not utf8", SEED)
        d = self.admitter.admit(
            "a1", KEY_ID,
            base64.b64encode(b"\xff\xfe not utf8").decode(),
            base64.b64encode(sig).decode(),
        )
        self.assertEqual(d.code, "INVALID_JSON_PAYLOAD")

        good = {"deviceId": "dev", "generation": 1, "previousGeneration": 0,
                "configSha256": digest(b"c")}
        payload = json.dumps(good).encode()
        sig2 = ed25519.sign(payload, SEED)
        # uppercase hash must be rejected
        bad = json.dumps({**good, "configSha256": digest(b"c").upper()}).encode()
        d3 = self.admitter.admit("a1", KEY_ID, base64.b64encode(bad).decode(),
                                 base64.b64encode(ed25519.sign(bad, SEED)).decode())
        self.assertEqual(d3.code, "INVALID_JSON_PAYLOAD")

    def test_devices_are_independent_chains(self):
        self.assertTrue(self.submit("a1", "dev-A", 1, 0, b"c1")[0].accepted)
        self.assertTrue(self.submit("b1", "dev-B", 1, 0, b"d1")[0].accepted)
        self.assertTrue(self.submit("a2", "dev-A", 2, 1, b"c2")[0].accepted)
        self.assertEqual(self.admitter.head("dev-A")["generation"], 2)
        self.assertEqual(self.admitter.head("dev-B")["generation"], 1)

    def test_persistence_survives_reopen(self):
        self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.submit("a2", "dev", 2, 1, b"cfg-2")
        store2 = Store(self.db)
        adm2 = Admitter(store2, {KEY_ID: PUB}, {KEY_ID: None})
        head = adm2.head("dev")
        self.assertEqual(head["generation"], 2)
        self.assertEqual(head["configSha256"], digest(b"cfg-2"))
        # after "restart" a stale predecessor still fails
        d, _, _ = self.submit("a3", "dev", 3, 1, b"cfg-3")
        self.assertEqual(d.code, "STALE_PREDECESSOR")
        # and the true successor succeeds
        d2, _, _ = self.submit("a4", "dev", 3, 2, b"cfg-3")
        self.assertTrue(d2.accepted)

    def test_concurrent_competing_successors_only_one_wins(self):
        self.submit("root", "dev", 1, 0, b"cfg-1")
        results = []

        def worker(att_id, config):
            d, _, _ = self.submit(att_id, "dev", 2, 1, config)
            results.append((att_id, d.accepted, d.code))

        # three different-config competitors for the same successor generation
        threads = [threading.Thread(target=worker, args=(f"g2-{i}", f"cfg-{i}".encode()))
                   for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wins = [r for r in results if r[1]]
        self.assertEqual(len(wins), 1, results)
        self.assertEqual(len(self.store.accepted_generations("dev")), 2)
        self.assertEqual(self.admitter.head("dev")["generation"], 2)

    def test_concurrent_identical_retry_single_acceptance(self):
        results = []

        def worker():
            d, _, _ = self.submit("same-id", "dev", 1, 0, b"cfg-1")
            results.append((d.accepted, d.status, d.code, d.duplicate))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        accepted_201 = [r for r in results if r[1] and not r[3]]
        self.assertEqual(len(accepted_201), 1, results)
        self.assertTrue(all(r[1] for r in results), results)
        self.assertEqual(len(self.store.accepted_generations("dev")), 1)

    def test_concurrent_successor_vs_restore_single_winner(self):
        self.submit("root", "dev", 1, 0, b"cfg-1")
        self.submit("g2", "dev", 2, 1, b"cfg-2")
        results = []

        def plain_successor():
            d, _, _ = self.submit("plain-3", "dev", 3, 2, b"cfg-3")
            results.append(("plain", d.accepted, d.code))

        def restore():
            d, _, _ = self.submit("restore-3", "dev", 3, 2, b"cfg-1",
                                  extra={"restoresGeneration": 1})
            results.append(("restore", d.accepted, d.code))

        threads = [threading.Thread(target=plain_successor),
                   threading.Thread(target=restore)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # exactly one attestation chains onto the old head
        wins = [r for r in results if r[1]]
        self.assertEqual(len(wins), 1, results)
        self.assertEqual(self.store.accepted_generations("dev"), [1, 2, 3])
        head = self.admitter.head("dev")
        self.assertEqual(head["generation"], 3)
        if wins[0][0] == "restore":
            # the unique new generation exposes its restore source
            self.assertEqual(head["restoresGeneration"], 1)
            self.assertEqual(head["configSha256"], digest(b"cfg-1"))
        else:
            self.assertIsNone(head["restoresGeneration"])
            self.assertEqual(head["configSha256"], digest(b"cfg-3"))


def _multiprocess_worker(db_path, att_id, config_byte):
    """Independent Store/Admitter instance, as in a separate process."""
    import base64 as _b64
    import json as _json

    store = Store(db_path)
    adm = Admitter(store, {KEY_ID: PUB}, {KEY_ID: None})
    doc = {
        "deviceId": "mp-dev",
        "generation": 2,
        "previousGeneration": 1,
        "configSha256": digest(bytes([config_byte]) * 8),
    }
    payload = _json.dumps(doc, separators=(",", ":")).encode()
    sig = ed25519.sign(payload, SEED)
    d = adm.admit(
        attestation_id=att_id,
        key_id=KEY_ID,
        payload_b64=_b64.b64encode(payload).decode(),
        signature_b64=_b64.b64encode(sig).decode(),
    )
    return d.accepted, d.code


class MultiprocessConcurrencyTests(unittest.TestCase):
    """Separate processes hammering the same SQLite file must not fork."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "att.db")
        store = Store(self.db)
        adm = Admitter(store, {KEY_ID: PUB}, {KEY_ID: None})
        doc = {"deviceId": "mp-dev", "generation": 1, "previousGeneration": 0,
               "configSha256": digest(b"root")}
        payload = __import__("json").dumps(doc, separators=(",", ":")).encode()
        import base64 as _b64
        d = adm.admit(
            "mp-root", KEY_ID,
            _b64.b64encode(payload).decode(),
            _b64.b64encode(ed25519.sign(payload, SEED)).decode(),
        )
        self.assertTrue(d.accepted)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cross_process_competitors(self):
        import multiprocessing as mp

        ctx = mp.get_context("spawn")
        with ctx.Pool(processes=4) as pool:
            futures = [
                pool.apply_async(_multiprocess_worker, (self.db, f"mp-g2-{i}", 0x40 + i))
                for i in range(4)
            ]
            outcomes = [f.get(timeout=30) for f in futures]
        wins = [o for o in outcomes if o[0]]
        self.assertEqual(len(wins), 1, outcomes)
        # every loser must carry a stable conflict/race code
        for accepted, code in outcomes:
            if not accepted:
                self.assertIn(code, {"GENERATION_CONTENT_CONFLICT", "CONCURRENT_UPDATE"})
        store = Store(self.db)
        gens = store.accepted_generations("mp-dev")
        self.assertEqual(gens, [1, 2], gens)
        self.assertEqual(store.head("mp-dev").generation, 2)


if __name__ == "__main__":
    unittest.main()
