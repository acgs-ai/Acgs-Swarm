"""Durable epoch fencing and independent signed-journal rejection tests."""

import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.codec import encode_payload
from constitutional_swarm.apcc.crypto import b64u_encode, sha256_digest
from constitutional_swarm.apcc_empirical import w2_renewal_journal as j
from constitutional_swarm.apcc_empirical.w2_renewal_protocol import SignerBinding


@pytest.fixture
def owned(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "owned" / "journal.jsonl"
    context = dict(
        authority_store_id="store", authority_session_id="session", repetition_id="rep"
    )
    journal = j.RenewalJournal.create(
        path,
        key,
        key_id="renewal",
        context=context,
        plan_digest=sha256_digest(b"plan"),
        not_before_ms=100,
        expires_at_ms=1000,
        maximum_total_lifetime_ms=5000,
        maximum_renewals=3,
    )
    yield journal, path, key, context
    journal.close()


def replay(owned, **kwargs):
    _, path, key, context = owned
    return j.verify_journal(
        path.read_bytes(),
        SignerBinding("renewal", key.public_key().public_bytes_raw()),
        expected_context=context,
        expected_plan_digest=sha256_digest(b"plan"),
        **kwargs,
    )


def advance(journal):
    for i, state in enumerate(("DRAINED", "PREPARED", "RETIRED")):
        journal.transition(state, 0, state, {"proof": "bound"}, now_ms=200 + i)
    return journal.transition(
        "ACTIVE", 1, "successor", {"proof": "bound"}, now_ms=203, expires_at_ms=2000
    )


def test_full_handover_and_independent_replay(owned):
    journal, path, _, _ = owned
    journal.gate(0, 100)
    row = advance(journal)
    journal.gate(1, 204)
    with pytest.raises(ValueError):
        journal.gate(0, 204)
    assert (
        len(
            replay(
                owned,
                require_active=True,
                expected_final_digest=sha256_digest(encode_payload(row)),
            )
        )
        == 5
    )
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_idempotency_and_fork_rejection(owned):
    journal = owned[0]
    row = journal.transition("DRAINED", 0, "drain", {}, now_ms=200)
    assert journal.transition("DRAINED", 0, "drain", {}, now_ms=200) == row
    with pytest.raises(ValueError):
        journal.transition("DRAINED", 0, "drain", {"changed": "body"}, now_ms=200)
    with pytest.raises(ValueError):
        journal.transition("DRAINED", 0, "fork", {}, now_ms=200)
    assert len(journal.records()) == 2


def test_split_brain_drain_has_one_winner(owned):
    journal = owned[0]

    def drain(nonce):
        try:
            journal.transition("DRAINED", 0, nonce, {}, now_ms=200)
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(drain, ["one", "two"])) == [False, True]


def test_active_retry_requires_same_explicit_expiration(owned):
    journal = owned[0]
    original = advance(journal)
    assert (
        journal.transition(
            "ACTIVE",
            1,
            "successor",
            {"proof": "bound"},
            now_ms=203,
            expires_at_ms=2000,
        )
        == original
    )
    for expiration in (None, True, 2001):
        with pytest.raises(ValueError):
            journal.transition(
                "ACTIVE",
                1,
                "successor",
                {"proof": "bound"},
                now_ms=203,
                expires_at_ms=expiration,
            )
    assert len(journal.records()) == 5


@pytest.mark.parametrize("state", ["DRAINED", "PREPARED", "RETIRED"])
def test_each_handover_prefix_fences_and_failure_is_terminal(owned, state):
    journal = owned[0]
    for i, current in enumerate(("DRAINED", "PREPARED", "RETIRED")):
        journal.transition(current, 0, current, {}, now_ms=200 + i)
        if current == state:
            break
    with pytest.raises(ValueError):
        journal.gate(0, 210)
    with pytest.raises(ValueError):
        replay(owned, require_active=True)
    journal.transition("FAILED", 0, "cancel", {"reason": "cancelled"}, now_ms=1200)
    with pytest.raises(ValueError):
        journal.transition("ACTIVE", 1, "resume", {}, now_ms=1201, expires_at_ms=2000)
    with pytest.raises(ValueError):
        replay(owned, require_active=True)


@pytest.mark.parametrize("kind", ["truncate", "replace", "edit", "append", "symlink"])
def test_storage_mutation_permanently_fences(owned, kind):
    journal, path, _, _ = owned
    original = path.read_bytes()
    if kind == "truncate":
        path.write_bytes(original[:-1])
    elif kind == "replace":
        path.unlink()
        path.write_bytes(original)
    elif kind == "edit":
        path.write_bytes(original.replace(b"ACTIVE", b"BROKEN"))
    elif kind == "append":
        with path.open("ab") as stream:
            stream.write(b"unsigned\n")
    else:
        backup = path.with_suffix(".backup")
        path.rename(backup)
        path.symlink_to(backup)
    with pytest.raises((ValueError, OSError)):
        journal.gate(0, 200)
    path.write_bytes(original)
    with pytest.raises(ValueError):
        journal.gate(0, 200)


@pytest.mark.parametrize("fault", ["write", "file_sync", "parent_sync"])
def test_io_failure_never_publishes_and_poison_survives_repair(
    owned, monkeypatch, fault
):
    journal = owned[0]
    rows = journal.records()
    real_sync = os.fsync
    count = 0

    def sync(fd):
        nonlocal count
        count += 1
        if count == (1 if fault == "file_sync" else 2):
            raise OSError("injected fsync failure")
        return real_sync(fd)

    with monkeypatch.context() as patch:
        if fault == "write":
            patch.setattr(j.os, "write", lambda *_: 0)
        else:
            patch.setattr(j.os, "fsync", sync)
        with pytest.raises(OSError):
            journal.transition("DRAINED", 0, "drain", {}, now_ms=200)
    assert len(journal._rows) == len(rows)
    with pytest.raises(ValueError):
        journal.gate(0, 201)


def test_expiration_and_launch_cap(owned):
    journal = owned[0]
    for i, state in enumerate(("DRAINED", "PREPARED", "RETIRED")):
        journal.transition(state, 0, state, {}, now_ms=200 + i)
    for end in (203, 5101, 1_200_204):
        with pytest.raises(ValueError):
            journal.transition(
                "ACTIVE", 1, "successor", {}, now_ms=203, expires_at_ms=end
            )


def test_expiration_cannot_be_reversed_by_wall_clock_regression(owned):
    journal = owned[0]
    with pytest.raises(ValueError):
        journal.gate(0, 1000)
    with pytest.raises(ValueError):
        journal.gate(0, 200)
    with pytest.raises(ValueError):
        journal.transition("DRAINED", 0, "late", {}, now_ms=200)
    journal.transition("FAILED", 0, "expired", {"reason": "expired"}, now_ms=1000)


@pytest.mark.parametrize(
    "mutation",
    [
        "signature",
        "key",
        "extra",
        "sequence",
        "epoch",
        "plan",
        "nonce",
        "truncate",
        "duplicate",
    ],
)
def test_independent_replay_mutations(owned, mutation):
    journal, path, key, _ = owned
    advance(journal)
    rows = list(journal.records())
    if mutation == "truncate":
        path.write_bytes(path.read_bytes()[:-10])
    elif mutation == "duplicate":
        path.write_bytes(path.read_bytes() + encode_payload(rows[-1]) + b"\n")
    else:
        row = rows[-1]
        if mutation == "signature":
            row["signature"] = b64u_encode(bytes(64))
        elif mutation == "key":
            row["key_id"] = "other"
        else:
            field, value = {
                "extra": ("extra", "x"),
                "sequence": ("sequence", "09"),
                "epoch": ("epoch", "2"),
                "plan": ("plan_digest", sha256_digest(b"other")),
                "nonce": ("nonce", "initial"),
            }[mutation]
            row["body"][field] = value
            row["signature"] = b64u_encode(
                key.sign(j.DOMAIN + b"\0" + encode_payload(row["body"]))
            )
        path.write_bytes(b"".join(encode_payload(row) + b"\n" for row in rows))
    with pytest.raises(ValueError):
        replay(owned, require_active=True)


def test_complete_line_truncation_requires_external_tip(owned):
    journal, path, _, _ = owned
    final = advance(journal)
    tip = sha256_digest(encode_payload(final))
    path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])
    with pytest.raises(ValueError):
        replay(owned, require_active=True, expected_final_digest=tip)


def test_records_are_detached_and_close_is_idempotent(owned):
    journal = owned[0]
    rows = journal.records()
    rows[0]["body"]["state"] = "FAILED"
    journal.gate(0, 200)
    journal.close()
    journal.close()
    with pytest.raises(ValueError):
        journal.gate(0, 200)


def test_partial_write_and_initial_fsync_failure_close_descriptor(
    tmp_path, monkeypatch
):
    key = Ed25519PrivateKey.generate()
    real_open = os.open
    opened = []

    def track_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def fail_sync(_fd):
        raise OSError("initial durability failure")

    with monkeypatch.context() as patch:
        patch.setattr(j.os, "open", track_open)
        patch.setattr(j.os, "fsync", fail_sync)
        with pytest.raises(OSError):
            j.RenewalJournal.create(
                tmp_path / "failed" / "journal",
                key,
                key_id="renewal",
                context=dict(
                    authority_store_id="store",
                    authority_session_id="session",
                    repetition_id="rep",
                ),
                plan_digest=sha256_digest(b"plan"),
                not_before_ms=100,
                expires_at_ms=1000,
                maximum_total_lifetime_ms=5000,
                maximum_renewals=3,
            )
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_short_writes_are_fully_synced(owned, monkeypatch):
    journal = owned[0]
    write = os.write
    with monkeypatch.context() as patch:
        patch.setattr(j.os, "write", lambda fd, data: write(fd, data[:13]))
        journal.transition("DRAINED", 0, "short-write", {}, now_ms=200)
    assert len(replay(owned)) == 2


def test_renewal_count_exhaustion(owned):
    journal = owned[0]
    for epoch in range(4):
        for offset, state in enumerate(("DRAINED", "PREPARED", "RETIRED")):
            journal.transition(
                state, epoch, f"{epoch}-{state}", {}, now_ms=200 + epoch * 10 + offset
            )
        if epoch == 3:
            with pytest.raises(ValueError, match="count exhausted"):
                journal.transition(
                    "ACTIVE", 4, "exhausted", {}, now_ms=233, expires_at_ms=2000
                )
        else:
            journal.transition(
                "ACTIVE",
                epoch + 1,
                f"active-{epoch}",
                {},
                now_ms=203 + epoch * 10,
                expires_at_ms=2000,
            )
