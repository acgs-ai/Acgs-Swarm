"""Tests for constitution sync (Phase 1 — Protocol Bridge)."""

from __future__ import annotations

import hashlib
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from constitutional_swarm.bittensor.constitution_sync import (
    ConstitutionDistributor,
    ConstitutionReceiver,
    ConstitutionSyncMessage,
    ConstitutionVersionRecord,
)

YAML_V1 = """\
name: test-constitution-v1
rules:
  - id: safety-01
    text: Do not cause harm
    severity: critical
    hardcoded: true
    keywords:
      - harm
      - danger
"""

YAML_V2 = """\
name: test-constitution-v2
rules:
  - id: safety-01
    text: Do not cause harm
    severity: critical
    hardcoded: true
    keywords:
      - harm
      - danger
  - id: privacy-01
    text: Protect personal data
    severity: high
    hardcoded: false
    keywords:
      - PII
      - personal
"""

_SIGNING_KEY = Ed25519PrivateKey.generate()
_TRUSTED_KEYS = {
    "subnet-owner": _SIGNING_KEY.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
}


def _distributor(yaml_content: str) -> ConstitutionDistributor:
    return ConstitutionDistributor(yaml_content, _SIGNING_KEY)


def _receiver(node_id: str) -> ConstitutionReceiver:
    return ConstitutionReceiver(node_id, trusted_issuer_keys=_TRUSTED_KEYS)


# ---------------------------------------------------------------------------
# ConstitutionVersionRecord
# ---------------------------------------------------------------------------


class TestConstitutionVersionRecord:
    def test_create_produces_stable_hash(self):
        r1 = ConstitutionVersionRecord.create(YAML_V1)
        r2 = ConstitutionVersionRecord.create(YAML_V1)
        assert r1.constitution_hash == r2.constitution_hash

    def test_different_yaml_different_hash(self):
        r1 = ConstitutionVersionRecord.create(YAML_V1)
        r2 = ConstitutionVersionRecord.create(YAML_V2)
        assert r1.constitution_hash != r2.constitution_hash

    def test_hash_length(self):
        r = ConstitutionVersionRecord.create(YAML_V1)
        assert len(r.constitution_hash) == 16

    def test_version_id_unique(self):
        r1 = ConstitutionVersionRecord.create(YAML_V1)
        r2 = ConstitutionVersionRecord.create(YAML_V1)
        assert r1.version_id != r2.version_id

    def test_age_seconds(self):
        r = ConstitutionVersionRecord.create(YAML_V1)
        assert r.age_seconds >= 0.0
        assert r.age_seconds < 5.0

    def test_immutable(self):
        r = ConstitutionVersionRecord.create(YAML_V1)
        with pytest.raises(AttributeError):
            r.constitution_hash = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ConstitutionSyncMessage
# ---------------------------------------------------------------------------


class TestConstitutionSyncMessage:
    def _make_msg(self, yaml: str = YAML_V1) -> ConstitutionSyncMessage:
        digest = hashlib.sha256(yaml.encode()).digest()
        return ConstitutionSyncMessage(
            version_id="v001",
            version=1,
            expected_hash=digest.hex()[:16],
            content_digest=digest,
            yaml_content=yaml,
            issued_at=time.time_ns(),
        )

    def test_verify_valid(self):
        msg = self._make_msg()
        assert msg.verify() is True

    def test_verify_tampered_content(self):
        msg = self._make_msg()
        tampered = ConstitutionSyncMessage(
            version_id=msg.version_id,
            version=msg.version,
            expected_hash=msg.expected_hash,
            content_digest=msg.content_digest,
            yaml_content=msg.yaml_content + "\n# tampered",
            issued_at=msg.issued_at,
        )
        assert tampered.verify() is False

    def test_reject_wrong_hash_shape(self):
        msg = self._make_msg()
        with pytest.raises(ValueError, match="expected_hash"):
            ConstitutionSyncMessage(
                version_id=msg.version_id,
                version=msg.version,
                expected_hash="wronghash1234567",
                content_digest=msg.content_digest,
                yaml_content=msg.yaml_content,
                issued_at=msg.issued_at,
            )

    def test_to_dict_from_dict_roundtrip(self):
        msg = self._make_msg()
        restored = ConstitutionSyncMessage.from_dict(msg.to_dict())
        assert restored.version_id == msg.version_id
        assert restored.version == msg.version
        assert restored.expected_hash == msg.expected_hash
        assert restored.content_digest == msg.content_digest
        assert restored.yaml_content == msg.yaml_content
        assert restored.wire_version == 2


# ---------------------------------------------------------------------------
# ConstitutionDistributor
# ---------------------------------------------------------------------------


class TestConstitutionDistributor:
    def test_initial_version(self):
        dist = _distributor(YAML_V1)
        assert dist.active_hash
        assert len(dist.version_history) == 1

    def test_broadcast_message_passes_verify(self):
        dist = _distributor(YAML_V1)
        msg = dist.broadcast_message()
        assert msg.verify() is True
        assert msg.signature is not None
        assert len(msg.signature) == 64
        assert msg.verify_signature(_TRUSTED_KEYS)

    def test_update_creates_new_version(self):
        dist = _distributor(YAML_V1)
        v1_hash = dist.active_hash
        dist.update(YAML_V2, description="Added privacy rule")
        assert dist.active_hash != v1_hash
        assert len(dist.version_history) == 2

    def test_update_same_content_raises(self):
        dist = _distributor(YAML_V1)
        with pytest.raises(ValueError, match="unchanged"):
            dist.update(YAML_V1)

    def test_version_history_ordered(self):
        dist = _distributor(YAML_V1)
        dist.update(YAML_V2)
        history = dist.version_history
        assert history[0].yaml_content == YAML_V1
        assert history[1].yaml_content == YAML_V2
        assert [record.version for record in history] == [1, 2]

    def test_multiple_updates(self):
        dist = _distributor(YAML_V1)
        for i in range(3):
            extra_yaml = YAML_V1 + f"\n  # update {i}"
            dist.update(extra_yaml)
        assert len(dist.version_history) == 4


# ---------------------------------------------------------------------------
# ConstitutionReceiver
# ---------------------------------------------------------------------------


class TestConstitutionReceiver:
    def test_uninitialised(self):
        r = _receiver("miner-01")
        assert not r.is_initialised
        assert r.active_hash == ""
        assert r.active_yaml == ""

    def test_apply_valid_message(self):
        dist = _distributor(YAML_V1)
        msg = dist.broadcast_message()

        receiver = _receiver("miner-01")
        result = receiver.apply(msg)

        assert result.success is True
        assert receiver.is_initialised
        assert receiver.active_hash == dist.active_hash

    def test_apply_tampered_message(self):
        dist = _distributor(YAML_V1)
        msg = dist.broadcast_message()
        tampered = ConstitutionSyncMessage(
            version_id=msg.version_id,
            version=msg.version,
            expected_hash=msg.expected_hash,
            content_digest=msg.content_digest,
            yaml_content=msg.yaml_content + "\n# tampered",
            issued_at=msg.issued_at,
        )
        receiver = _receiver("miner-01")
        result = receiver.apply(tampered)

        assert result.success is False
        assert not receiver.is_initialised

    def test_apply_version_update(self):
        dist = _distributor(YAML_V1)
        receiver = _receiver("miner-01")
        receiver.apply(dist.broadcast_message())

        dist.update(YAML_V2)
        result = receiver.apply(dist.broadcast_message())

        assert result.success is True
        assert receiver.active_hash == dist.active_hash
        assert len(receiver.version_history) == 2

    def test_verify_task_hash_matches(self):
        dist = _distributor(YAML_V1)
        receiver = _receiver("miner-01")
        receiver.apply(dist.broadcast_message())

        full_digest = hashlib.sha256(YAML_V1.encode()).hexdigest()
        assert receiver.verify_task_hash(full_digest) is True
        assert receiver.verify_task_hash("wrong_hash") is False

    def test_summary(self):
        receiver = _receiver("miner-42")
        s = receiver.summary()
        assert s["node_id"] == "miner-42"
        assert s["is_initialised"] is False

    def test_multiple_receivers_stay_in_sync(self):
        dist = _distributor(YAML_V1)
        miners = [_receiver(f"miner-{i:02d}") for i in range(5)]

        msg = dist.broadcast_message()
        for m in miners:
            result = m.apply(msg)
            assert result.success

        hashes = {m.active_hash for m in miners}
        assert len(hashes) == 1  # all nodes converge to same hash

        # Now update
        dist.update(YAML_V2)
        msg2 = dist.broadcast_message()
        for m in miners:
            result = m.apply(msg2)
            assert result.success

        hashes2 = {m.active_hash for m in miners}
        assert len(hashes2) == 1
        assert hashes2 != hashes  # moved to new version
