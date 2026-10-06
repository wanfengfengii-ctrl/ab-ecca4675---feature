"""Attestation admission: payload validation, signature verification, chain rules.

Chain rule
----------
For each device the accepted attestations form a strictly increasing chain of
generations:

* the first attestation ever accepted for a device MUST carry
  ``previousGeneration == 0``;
* every later attestation MUST carry ``previousGeneration`` equal to the
  currently accepted generation and a ``generation`` strictly greater than it.

Restore attestations
--------------------
A payload MAY carry ``restoresGeneration`` to perform an emergency restore of a
previously accepted configuration (e.g. a satellite payload team rolling back
to a known-good config after an anomaly). A restore is NOT a plain rollback:
it still chains onto the current head with a strictly greater ``generation``,
so the proof lineage keeps moving monotonically forward. Additionally:

* ``restoresGeneration`` MUST name a generation that was accepted for the same
  device strictly before the current head;
* ``configSha256`` MUST equal the digest recorded at that historical
  generation.

Violations are stable 409 conflicts and leave state untouched.

Retries (same attestation id byte-for-byte) replay the original outcome and
never mutate state. A reused id with different content, a stale predecessor,
or a generation that does not advance is a conflict and leaves state untouched.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from . import ed25519
from .store import Store

# Stable error codes (part of the API contract).
ERR_MALFORMED = "MALFORMED_REQUEST"
ERR_INVALID_JSON = "INVALID_JSON_PAYLOAD"
ERR_INVALID_BASE64 = "INVALID_BASE64"
ERR_UNKNOWN_KEY = "UNKNOWN_KEY_ID"
ERR_KEY_DEVICE_MISMATCH = "KEY_NOT_BOUND_TO_DEVICE"
ERR_BAD_SIGNATURE = "INVALID_SIGNATURE"
ERR_UNSUPPORTED_ALG = "UNSUPPORTED_KEY"
ERR_GEN_ZERO = "GENERATION_ZERO"
ERR_GEN_NOT_GREATER = "GENERATION_NOT_GREATER"
ERR_BAD_PREDECESSOR_FIRST = "FIRST_PREDECESSOR_NOT_ZERO"
ERR_STALE_PREDECESSOR = "STALE_PREDECESSOR"
ERR_ID_CONTENT_MISMATCH = "ATTESTATION_ID_CONTENT_MISMATCH"
ERR_GENERATION_CONTENT_MISMATCH = "GENERATION_CONTENT_CONFLICT"
ERR_RESTORE_TARGET_NOT_FOUND = "RESTORE_TARGET_NOT_FOUND"
ERR_RESTORE_TARGET_NOT_EARLIER = "RESTORE_TARGET_NOT_EARLIER"
ERR_RESTORE_CONFIG_MISMATCH = "RESTORE_CONFIG_MISMATCH"
ERR_RACE_LOST = "CONCURRENT_UPDATE"
ERR_INTERNAL = "INTERNAL_ERROR"


@dataclass(frozen=True)
class AdmissionDecision:
    accepted: bool
    status: int
    code: str
    message: str
    record: Optional[dict] = None
    duplicate: bool = False


def _b64decode(data: str) -> bytes:
    # urlsafe or standard alphabet both accepted; padding optional.
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        pass
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(str(exc)) from exc


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_payload(raw: bytes) -> dict:
    """Decode payload bytes as UTF-8 JSON and enforce required fields."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"payload is not valid UTF-8: {exc}") from exc
    if text and text[0] == "﻿":
        raise ValueError("payload must not contain a UTF-8 BOM")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"payload is not valid JSON: {exc.msg}") from exc
    if not isinstance(doc, dict):
        raise ValueError("payload JSON must be an object")

    required = ("deviceId", "generation", "previousGeneration", "configSha256")
    for field in required:
        if field not in doc:
            raise ValueError(f"payload missing required field: {field}")

    if not isinstance(doc["deviceId"], str) or not doc["deviceId"]:
        raise ValueError("payload field deviceId must be a non-empty string")
    # bool is a subclass of int: reject it explicitly for both generations.
    for field in ("generation", "previousGeneration"):
        value = doc[field]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"payload field {field} must be an integer")
    if doc["generation"] < 0 or doc["previousGeneration"] < 0:
        raise ValueError("generation values must be non-negative")
    if not isinstance(doc["configSha256"], str) or not doc["configSha256"]:
        raise ValueError("payload field configSha256 must be a non-empty string")
    if not _HEX64.fullmatch(doc["configSha256"]):
        raise ValueError("payload field configSha256 must be 64 lowercase hex characters")
    # Optional restore marker: a non-negative integer generation number.
    if "restoresGeneration" in doc:
        value = doc["restoresGeneration"]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("payload field restoresGeneration must be an integer")
        if value < 0:
            raise ValueError("payload field restoresGeneration must be non-negative")
    return doc


_HEX64 = re.compile(r"[0-9a-f]{64}")


class Admitter:
    def __init__(self, store: Store, keys: dict[str, bytes], bindings: dict[str, Optional[str]] | None = None):
        self.store = store
        # keyId -> raw 32-byte Ed25519 public key
        self.keys = keys
        # keyId -> bound deviceId (None or missing means unbound)
        self.bindings = bindings or {}

    def head(self, device_id: str) -> Optional[dict]:
        rec = self.store.head(device_id)
        return rec.to_dict() if rec is not None else None

    def admit(
        self,
        attestation_id: object,
        key_id: object,
        payload_b64: object,
        signature_b64: object,
    ) -> AdmissionDecision:
        # ---- request shape -------------------------------------------------
        if not all(isinstance(v, str) for v in (attestation_id, key_id, payload_b64, signature_b64)):
            return AdmissionDecision(
                False, 400, ERR_MALFORMED,
                "attestationId, keyId, payloadBase64 and signatureBase64 "
                "must all be strings",
            )
        if not attestation_id:
            return AdmissionDecision(False, 400, ERR_MALFORMED, "attestationId must be non-empty")

        try:
            payload = _b64decode(payload_b64)
        except ValueError:
            return AdmissionDecision(False, 400, ERR_INVALID_BASE64, "payloadBase64 is not valid base64")
        try:
            signature = _b64decode(signature_b64)
        except ValueError:
            return AdmissionDecision(False, 400, ERR_INVALID_BASE64, "signatureBase64 is not valid base64")

        # ---- signature / key ----------------------------------------------
        public_key = self.keys.get(key_id)
        if public_key is None:
            return AdmissionDecision(
                False, 401, ERR_UNKNOWN_KEY,
                f"no public key is registered for keyId {key_id!r}",
            )
        try:
            ed25519.verify(signature, payload, public_key)
        except ValueError:
            return AdmissionDecision(False, 401, ERR_BAD_SIGNATURE, "Ed25519 signature verification failed")

        # ---- payload -------------------------------------------------------
        try:
            doc = validate_payload(payload)
        except ValueError as exc:
            return AdmissionDecision(False, 400, ERR_INVALID_JSON, str(exc))

        bound_device = self.bindings.get(key_id)
        if bound_device is not None and bound_device != doc["deviceId"]:
            return AdmissionDecision(
                False, 403, ERR_KEY_DEVICE_MISMATCH,
                f"keyId {key_id!r} is not bound to device {doc['deviceId']!r}",
            )

        # The signature is valid, so attestation id reuse can be checked
        # against the exact signed bytes rather than trusting the client.
        payload_sha = hashlib.sha256(payload).hexdigest()
        return self._persist(
            attestation_id=attestation_id,
            payload_sha=payload_sha,
            device_id=doc["deviceId"],
            generation=doc["generation"],
            previous_generation=doc["previousGeneration"],
            config_sha256=doc["configSha256"],
            restores_generation=doc.get("restoresGeneration"),
        )

    def _persist(
        self,
        *,
        attestation_id: str,
        payload_sha: str,
        device_id: str,
        generation: int,
        previous_generation: int,
        config_sha256: str,
        restores_generation: Optional[int],
    ) -> AdmissionDecision:
        from .store import ConcurrentUpdateError

        try:
            with self.store.transaction() as conn:
                existing_id = self.store.find_by_id(conn, attestation_id)
                prior = self.store.find(conn, device_id, generation)

                # 1) Exact retry: same id AND byte-identical signed payload.
                if existing_id is not None and existing_id.payload_sha256 == payload_sha:
                    if existing_id.device_id != device_id:
                        return AdmissionDecision(
                            False, 409, ERR_ID_CONTENT_MISMATCH,
                            "attestationId already used for different content",
                        )
                    return AdmissionDecision(
                        True, 200, "",
                        "attestation already accepted",
                        record=existing_id.to_dict(), duplicate=True,
                    )

                # 2) Reused attestation id with different signed content.
                if existing_id is not None:
                    return AdmissionDecision(
                        False, 409, ERR_ID_CONTENT_MISMATCH,
                        "attestationId was already used with different content",
                    )

                # 3) Same generation number already accepted -> content must match.
                if prior is not None:
                    return AdmissionDecision(
                        False, 409, ERR_GENERATION_CONTENT_MISMATCH,
                        f"generation {generation} for device {device_id!r} is "
                        "already accepted with different content",
                    )

                # 4) Chain / predecessor rules evaluated against the locked head.
                head = self.store.head_unlocked(conn, device_id)
                if head is None:
                    if previous_generation != 0:
                        return AdmissionDecision(
                            False, 409, ERR_BAD_PREDECESSOR_FIRST,
                            f"first attestation for device {device_id!r} must "
                            f"have previousGeneration 0 (got {previous_generation})",
                        )
                    if generation == 0:
                        return AdmissionDecision(
                            False, 409, ERR_GEN_ZERO,
                            "generation must be greater than 0",
                        )
                else:
                    if previous_generation != head.generation:
                        return AdmissionDecision(
                            False, 409, ERR_STALE_PREDECESSOR,
                            f"previousGeneration {previous_generation} does not "
                            f"match current head generation {head.generation}",
                        )
                    if generation <= head.generation:
                        return AdmissionDecision(
                            False, 409, ERR_GEN_NOT_GREATER,
                            f"generation {generation} must be greater than "
                            f"current head {head.generation}",
                        )

                # 5) Restore semantics, checked against the locked head and
                #    history. A restore still chains onto the head (enforced
                #    above); here the restore SOURCE must be an accepted
                #    generation strictly behind the head with a matching
                #    config digest.
                if restores_generation is not None:
                    if head is None:
                        return AdmissionDecision(
                            False, 409, ERR_RESTORE_TARGET_NOT_FOUND,
                            f"device {device_id!r} has no accepted generation "
                            f"{restores_generation} to restore",
                        )
                    if restores_generation >= head.generation:
                        return AdmissionDecision(
                            False, 409, ERR_RESTORE_TARGET_NOT_EARLIER,
                            f"restoresGeneration {restores_generation} is not "
                            f"earlier than the current head generation "
                            f"{head.generation}",
                        )
                    target = self.store.find(conn, device_id, restores_generation)
                    if target is None:
                        return AdmissionDecision(
                            False, 409, ERR_RESTORE_TARGET_NOT_FOUND,
                            f"device {device_id!r} has no accepted generation "
                            f"{restores_generation} to restore",
                        )
                    if target.config_sha256 != config_sha256:
                        return AdmissionDecision(
                            False, 409, ERR_RESTORE_CONFIG_MISMATCH,
                            f"configSha256 does not match the digest accepted "
                            f"at generation {restores_generation}",
                        )

                self.store.insert(
                    conn,
                    device_id=device_id,
                    generation=generation,
                    previous_generation=previous_generation,
                    config_sha256=config_sha256,
                    attestation_id=attestation_id,
                    payload_sha256=payload_sha,
                    accepted_at=_now(),
                    restores_generation=restores_generation,
                )
                rec = self.store.find(conn, device_id, generation)
                return AdmissionDecision(
                    True, 201, "", "attestation accepted", record=rec.to_dict()
                )
        except ConcurrentUpdateError:
            return AdmissionDecision(
                False, 409, ERR_RACE_LOST,
                "lost the concurrency race; reload the current head and retry",
            )
