"""Independent replay of externally pinned W2 observer-epoch evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from constitutional_swarm.apcc.codec import encode_payload
from constitutional_swarm.apcc.crypto import b64u_decode, sha256_digest
from constitutional_swarm.apcc.observation import (
    AuthorityObservationVerificationStream,
    decode_signed_authority_observation,
)
from constitutional_swarm.apcc.sqlite_store import (
    _SEMANTIC_CHECKPOINT_DOMAIN,
    _config_from_object,
    _semantic_checkpoint_body,
)
from constitutional_swarm.apcc_empirical import w2_campaign as c
from constitutional_swarm.apcc_empirical import w2_driver as d
from constitutional_swarm.apcc_empirical import w2_renewal_codec as codec
from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan
from constitutional_swarm.apcc_empirical.w2_renewal_journal import verify_journal
from constitutional_swarm.apcc_empirical.w2_renewal_protocol import SignerBinding

_PLAN_FIELDS = {
    "revision",
    "repetition_id",
    "authority_store_id",
    "authority_session_id",
    "renewal_key_id",
    "renewal_public_key",
    "controller_public_key",
    "config_digest",
    "profile",
    "limits",
    "windows",
    "campaign_eligible",
}
_RENEWAL_FIELDS = {
    "plan_sha256",
    "epoch",
    "authority_session_id",
    "delegation",
    "records",
    "continuity",
    "checkpoint",
    "initial_checkpoint_proof",
}


def _read(path: Path, expected: str) -> bytes:
    if path.is_symlink():
        raise ValueError("renewal evidence symlink rejected")
    raw = path.read_bytes()
    codec.external_plan_digest(raw, expected)
    return raw


def _load_plan(
    directory: Path, expected: str, *, _numeric_opt_in: bool = False
) -> dict[str, Any]:
    raw = _read(directory / "renewal-plan.json", expected)
    plan = json.loads(raw)
    if not _numeric_opt_in and plan.get("revision") != "w2-renewal-functional-v1":
        raise ValueError("functional verifier rejects numeric protocol")
    if (
        type(plan) is not dict
        or set(plan)
        != (
            _PLAN_FIELDS | {"numeric"}
            if plan.get("revision") == "w2-numeric-cold-v1"
            else _PLAN_FIELDS
        )
        or d._json(plan) + b"\n" != raw
        or plan["revision"] not in ("w2-renewal-functional-v1", "w2-numeric-cold-v1")
        or plan["profile"] != "W2_LINEAR_100"
        or plan["campaign_eligible"] is not False
        or type(plan["windows"]) is not list
        or not 1 <= len(plan["windows"]) <= 5
    ):
        raise ValueError("renewal plan schema or profile mismatch")
    if plan["revision"] == "w2-numeric-cold-v1" and len(plan["windows"]) != 1:
        raise ValueError("numeric cold plan must have one window")
    limits = codec.validate_plan_limits(plan["limits"])
    plans = [WindowPlan(**item) for item in plan["windows"]]
    if (
        any(item.qualification for item in plans)
        or len(plans) - 1 > limits["maximum_renewals"]
    ):
        raise ValueError("renewal functional window count or qualification mismatch")
    budget = sum(
        (item.duration_ns + item.drain_ns + 999_999) // 1_000_000 for item in plans
    )
    budget += (len(plans) - 1) * limits["handover_timeout_ms"]
    if budget > limits["maximum_total_lifetime_ms"]:
        raise ValueError("renewal declared windows exceed total lifetime")
    if any(
        (item.duration_ns + item.drain_ns + 999_999) // 1_000_000
        > limits["maximum_single_launch_ms"]
        for item in plans
    ):
        raise ValueError("renewal window exceeds single launch budget")
    for field in ("renewal_public_key", "controller_public_key", "config_digest"):
        b64u_decode(plan[field], expected_length=32)
    return plan


def _checkpoint(proof: Any, config: Any, schema: str) -> str:
    if type(proof) is not dict or set(proof) != {
        "body",
        "checkpoint_digest",
        "key_id",
        "signature",
    }:
        raise ValueError("renewal checkpoint proof fields")
    raw = b64u_decode(proof["body"])
    body = json.loads(raw)
    if type(body) is not dict or set(body) != {
        "profile",
        "kind",
        "authority_store_id",
        "schema_fingerprint",
        "change_sequence",
        "prior_digest",
        "authority_config_digest",
    }:
        raise ValueError("renewal checkpoint body fields")
    sequence = codec._canonical_decimal(
        body["change_sequence"], name="checkpoint sequence"
    )
    b64u_decode(body["prior_digest"], expected_length=32)
    if (
        raw != _semantic_checkpoint_body(config, schema, sequence, body["prior_digest"])
        or proof["checkpoint_digest"] != sha256_digest(raw)
        or proof["key_id"] != config.commit_trust.key_id
    ):
        raise ValueError("renewal checkpoint configuration or signer mismatch")
    Ed25519PublicKey.from_public_bytes(config.commit_trust.public_key).verify(
        b64u_decode(proof["signature"], expected_length=64),
        _SEMANTIC_CHECKPOINT_DOMAIN + b"\0" + raw,
    )
    return proof["checkpoint_digest"]


def _prepared_successor(
    prepared: dict[str, Any],
    retired: dict[str, Any],
    active: dict[str, Any],
    *,
    epoch: int,
    continuity_digest: str,
    launch_digest: str,
    prior_pid: str,
    issued_at_ms: str,
    prior_expires_at_ms: str,
    successor_expires_at_ms: str,
    delegation_expires_at_ms: str,
) -> None:
    """Bind durable preparation to precisely the subsequently activated successor."""
    bindings = {"continuity_digest": continuity_digest, "launch_digest": launch_digest}
    if (
        prepared["evidence"] != {"next_epoch": str(epoch), **bindings}
        or retired["evidence"]
        != {
            "observer_pid": prior_pid,
            "successor_launch_digest": launch_digest,
            "continuity_digest": continuity_digest,
        }
        or active["evidence"] != bindings
        or prepared["now_ms"] != issued_at_ms
        or not int(issued_at_ms)
        <= int(active["now_ms"])
        < min(
            int(prior_expires_at_ms),
            int(successor_expires_at_ms),
            int(delegation_expires_at_ms),
        )
    ):
        raise ValueError("renewal durable prepared successor mismatch or expiry")


class _Policy:
    def __init__(
        self,
        directory: Path,
        expected_plan_sha256: str,
        *,
        _numeric_opt_in: bool = False,
    ):
        self.directory = directory
        self.plan_sha = expected_plan_sha256
        self.plan = _load_plan(
            directory, expected_plan_sha256, _numeric_opt_in=_numeric_opt_in
        )
        self.digest = codec.external_plan_digest(
            (directory / "renewal-plan.json").read_bytes(), expected_plan_sha256
        )
        if self.plan["revision"] == "w2-numeric-cold-v1" and type(self) is _Policy:
            raise ValueError("numeric plan requires numeric verifier and external pins")
        self.limits = codec.validate_plan_limits(self.plan["limits"])
        self.completed: dict[int, dict[str, Any]] = {}
        self.checking: set[int] = set()

    def check_header(self, header: dict[str, Any]) -> Any:
        renewal = header.get("renewal")
        if type(renewal) is not dict or set(renewal) != _RENEWAL_FIELDS:
            raise ValueError("renewal header fields")
        epoch = renewal["epoch"]
        if (
            type(epoch) is not int
            or not 0 <= epoch < len(self.plan["windows"])
            or type(header["window_index"]) is not int
            or header["window_index"] != epoch
            or header["phase"] != ("cold" if epoch == 0 else "warm")
            or header["warm_mode"] != "renewed-observer-epochs-v1"
            or header["window_plans"] != self.plan["windows"]
            or header["plan"] != self.plan["windows"][epoch]
            or header["repetition_id"] != self.plan["repetition_id"]
            or header["run_id"] != self.plan["repetition_id"]
            or header["controller_public_key"] != self.plan["controller_public_key"]
            or renewal["authority_session_id"] != self.plan["authority_session_id"]
            or renewal["plan_sha256"] != self.plan_sha
        ):
            raise ValueError("renewal header external plan mismatch")
        # Reuse every existing authority/config/launch check, normalizing only the
        # old same-handle lifecycle restriction to the single current epoch.
        shadow = dict(
            header,
            window_index=0,
            phase="cold",
            warm_mode="same-handles-continuation",
            window_plans=[header["plan"]],
        )
        launch = c._header_check(shadow)
        config = _config_from_object(header["expected_public_config"])
        if (
            config.authority_store_id != self.plan["authority_store_id"]
            or codec.w2_config_digest(config) != self.plan["config_digest"]
        ):
            raise ValueError("renewal pinned configuration mismatch")
        if (
            int(launch.not_after_ms) - int(launch.not_before_ms)
            > self.limits["maximum_single_launch_ms"]
        ):
            raise ValueError("renewal launch exceeds external cap")
        initial_checkpoint = _checkpoint(
            renewal["initial_checkpoint_proof"], config, launch.schema_fingerprint
        )
        _checkpoint(renewal["checkpoint"], config, launch.schema_fingerprint)
        delegation_raw = b64u_decode(renewal["delegation"])
        delegation = cast(
            dict[str, str], codec.decode_delegation(delegation_raw)["body"]
        )
        expected = {
            k: self.plan[k]
            for k in (
                "authority_store_id",
                "authority_session_id",
                "repetition_id",
                "renewal_key_id",
                "renewal_public_key",
                "config_digest",
            )
        }
        expected.update(
            plan_digest=self.digest,
            checkpoint_digest=initial_checkpoint,
            initial_launch_digest=delegation["initial_launch_digest"],
        )
        codec.verify_delegation(
            delegation_raw,
            commit_key_id=config.commit_trust.key_id,
            commit_public_key=config.commit_trust.public_key,
            expected=expected,
            forbidden_public_keys=[
                b64u_decode(header["controller_public_key"]),
                b64u_decode(launch.observer_public_key),
            ]
            + [item.public_key for item in config.trust_bindings],
            now_ms=header["started_wall_ms"],
        )
        records = renewal["records"]
        if type(records) is not list:
            raise ValueError("renewal journal prefix must be a list")
        checked = verify_journal(
            b"".join(encode_payload(item) + b"\n" for item in records),
            SignerBinding(
                self.plan["renewal_key_id"],
                b64u_decode(self.plan["renewal_public_key"]),
            ),
            expected_context={
                k: self.plan[k]
                for k in ("authority_store_id", "authority_session_id", "repetition_id")
            },
            expected_plan_digest=self.digest,
            require_active=True,
        )
        tip = checked[-1]["body"]
        if (
            len(checked) != 1 + 4 * epoch
            or int(tip["epoch"]) != epoch
            or tip["expires_at_ms"] != launch.not_after_ms
            or int(tip["now_ms"]) > header["started_wall_ms"]
            or tip["maximum_total_lifetime_ms"]
            != self.plan["limits"]["maximum_total_lifetime_ms"]
            or tip["maximum_renewals"] != self.plan["limits"]["maximum_renewals"]
            or checked[0]["body"]["not_before_ms"] != delegation["not_before_ms"]
        ):
            raise ValueError("renewal journal epoch or budget mismatch")
        if (
            int(delegation["not_after_ms"])
            != int(checked[0]["body"]["not_before_ms"])
            + self.limits["maximum_total_lifetime_ms"]
        ):
            raise ValueError("renewal delegation total bound mismatch")
        return launch

    def check_transition(
        self, path: Path, header: dict[str, Any], launch: Any
    ) -> AuthorityObservationVerificationStream:
        epoch = header["window_index"]
        renewal = header["renewal"]
        if epoch == 0:
            if (
                header["previous_ledger"] is not None
                or header["chain_offset"] != 0
                or renewal["continuity"] is not None
            ):
                raise ValueError("renewal cold predecessor mismatch")
            delegation = cast(
                dict[str, str],
                codec.decode_delegation(b64u_decode(renewal["delegation"]))["body"],
            )
            if (
                delegation["initial_launch_digest"] != launch.canonical_digest
                or delegation["not_before_ms"] != launch.not_before_ms
            ):
                raise ValueError("renewal original launch mismatch")
        else:
            link = header["previous_ledger"]
            if (
                type(link) is not dict
                or set(link) != {"filename", "sha256"}
                or link["filename"] != f"window-{epoch - 1:03d}.jsonl"
            ):
                raise ValueError("renewal predecessor link mismatch")
            prior_path = path.parent / link["filename"]
            self.verify(prior_path, link["sha256"])
            if epoch - 1 not in self.completed:
                raise ValueError("renewal predecessor epoch gap")
            prior = self.completed[epoch - 1]
            ph, pf, pl = prior["header"], prior["footer"], prior["launch"]
            for field in (
                "expected_public_config",
                "controller_public_key",
                "worker_ids",
                "authority_pid",
                "executor_pid",
                "controller_pid",
                "provenance",
            ):
                if header[field] != ph[field]:
                    raise ValueError("renewal continuing authority/worker substitution")
            if (
                renewal["delegation"] != ph["renewal"]["delegation"]
                or renewal["initial_checkpoint_proof"]
                != ph["renewal"]["initial_checkpoint_proof"]
                or renewal["records"][:-4] != ph["renewal"]["records"]
                or prior["result"]["accounting"]["committed"]
                != ph["plan"]["scheduled_operations"]
                or prior["result"]["accounting"]["late_completions"] != 0
                or header["chain_offset"]
                != ph["chain_offset"] + ph["plan"]["scheduled_operations"] // 100
                or header["started_wall_ms"]
                < ph["started_wall_ms"] + pf["elapsed_ns"] // 1_000_000
            ):
                raise ValueError("renewal incomplete or overlapping predecessor")
            raw = b64u_decode(renewal["continuity"])
            terminal = decode_signed_authority_observation(
                b64u_decode(pf["terminal_proof"]["observation"])
            )
            delegation = cast(
                dict[str, str],
                codec.decode_delegation(b64u_decode(renewal["delegation"]))["body"],
            )
            expected = {
                k: self.plan[k]
                for k in (
                    "authority_store_id",
                    "authority_session_id",
                    "repetition_id",
                    "config_digest",
                )
            }
            expected.update(
                experiment_id=launch.experiment_id,
                run_id=launch.run_id,
                plan_digest=self.digest,
                checkpoint_digest=renewal["checkpoint"]["checkpoint_digest"],
                delegation_digest=sha256_digest(b64u_decode(renewal["delegation"])),
                renewal_index=str(epoch),
                prior_launch_digest=pl.canonical_digest,
                successor_launch_digest=launch.canonical_digest,
                prior_observer_session_id=pl.session_id,
                successor_observer_session_id=launch.session_id,
                prior_final_observation_sequence=terminal.sequence,
                prior_final_observation_digest=sha256_digest(
                    b64u_decode(pf["terminal_proof"]["observation"])
                ),
                trust_change_sequence=prior["stream"].highest_trust_log_sequence,
                trust_log_head=prior["stream"].highest_trust_log_head,
            )
            old_elapsed = (
                0
                if epoch == 1
                else int(
                    cast(
                        dict[str, str],
                        codec.decode_continuity(
                            b64u_decode(ph["renewal"]["continuity"])
                        )["body"],
                    )["cumulative_elapsed_ms"]
                )
            )
            body = codec.verify_continuity(
                raw,
                renewal_key_id=self.plan["renewal_key_id"],
                renewal_public_key=b64u_decode(self.plan["renewal_public_key"]),
                expected=expected,
                original_not_before_ms=int(delegation["not_before_ms"]),
                prior_not_after_ms=int(pl.not_after_ms),
                successor_not_before_ms=int(launch.not_before_ms),
                delegation_not_after_ms=int(delegation["not_after_ms"]),
                maximum_total_lifetime_ms=self.limits["maximum_total_lifetime_ms"],
                maximum_single_launch_ms=self.limits["maximum_single_launch_ms"],
                previous_elapsed_ms=old_elapsed,
                maximum_renewals=self.limits["maximum_renewals"],
            )
            if (
                body["successor_not_after_ms"] != launch.not_after_ms
                or int(body["issued_at_ms"]) > header["started_wall_ms"]
                or launch.initial_trust_sequence != expected["trust_change_sequence"]
                or launch.initial_trust_head != expected["trust_log_head"]
                or launch.observer_key_id == pl.observer_key_id
                or launch.launch_nonce == pl.launch_nonce
                or launch.observer_pid == pl.observer_pid
            ):
                raise ValueError("renewal successor launch or trust substitution")
            for previous_epoch, verified in self.completed.items():
                if previous_epoch >= epoch:
                    continue
                previous_launch = verified["launch"]
                if any(
                    getattr(previous_launch, field) == getattr(launch, field)
                    for field in ("observer_key_id", "session_id", "launch_nonce")
                ):
                    raise ValueError("renewal reused historical observer identity")
            drained, prepared, retired, active = [
                row["body"] for row in renewal["records"][-4:]
            ]
            from constitutional_swarm.apcc_empirical.w2_renewal_runtime import (
                verify_observer_tail,
            )

            tail = drained["evidence"].get("observer_tail")
            if type(tail) is not str:
                raise ValueError("renewal missing observer-signed terminal tail")
            verify_observer_tail(
                b64u_decode(tail),
                launch=pl,
                observation=terminal,
                epoch=epoch - 1,
                plan_digest=self.digest,
            )
            if (
                drained["evidence"]
                != {
                    "final_observation_digest": expected[
                        "prior_final_observation_digest"
                    ],
                    "checkpoint_digest": expected["checkpoint_digest"],
                    "controller_ledger_digest": codec.external_plan_digest(
                        prior_path.read_bytes(), link["sha256"]
                    ),
                    "controller_ledger_seal_digest": sha256_digest(d._json(pf)),
                    "observer_tail": tail,
                }
                or int(active["now_ms"]) - int(drained["now_ms"])
                > self.limits["handover_timeout_ms"]
            ):
                raise ValueError("renewal journal transition proof mismatch")
            _prepared_successor(
                prepared,
                retired,
                active,
                epoch=epoch,
                continuity_digest=sha256_digest(raw),
                launch_digest=launch.canonical_digest,
                prior_pid=pl.observer_pid,
                issued_at_ms=body["issued_at_ms"],
                prior_expires_at_ms=pl.not_after_ms,
                successor_expires_at_ms=launch.not_after_ms,
                delegation_expires_at_ms=delegation["not_after_ms"],
            )
        return AuthorityObservationVerificationStream(launch.session_id)

    def check_footer(
        self,
        header: dict[str, Any],
        footer: dict[str, Any],
        stream: Any,
        trust: Any,
        certificates: dict[str, bytes],
    ) -> None:
        row = footer.get("terminal_proof")
        if type(row) is not dict or row.get("node_index") != 99:
            raise ValueError("missing terminal complete-chain observation")
        d._verify_operation(row, header, stream, trust, certificates)
        if (
            type(row["verification_time_ms"]) is not int
            or row["verification_time_ms"]
            < header["started_wall_ms"] + header["plan"]["duration_ns"] // 1_000_000
            or row["verification_time_ms"]
            > header["started_wall_ms"] + footer["elapsed_ns"] // 1_000_000 + 1000
        ):
            raise ValueError("terminal observation window time mismatch")
        self.completed[header["window_index"]] = {
            "header": header,
            "footer": footer,
            "stream": stream,
            "launch": c.decode_observer_launch_attestation(
                b64u_decode(header["launch"])
            ),
        }

    def verify(self, path: Path, expected: str) -> dict[str, Any]:
        raw = _read(path, expected)
        header = json.loads(raw.splitlines()[0])
        epoch = header["window_index"]
        if type(epoch) is not int or not 0 <= epoch < 5 or epoch in self.checking:
            raise ValueError("renewal recursive predecessor cycle")
        self.checking.add(epoch)
        try:
            result = c.verify_ledger(
                path, expected_sha256=expected, _renewal_policy=self
            )
            self.completed[epoch]["result"] = result
            return result
        finally:
            self.checking.remove(epoch)


def verify_ledger(
    path: Path, *, expected_sha256: str, expected_plan_sha256: str
) -> dict[str, Any]:
    """Replay one epoch and every predecessor; never qualify a campaign."""
    return _Policy(path.parent, expected_plan_sha256).verify(path, expected_sha256)


def verify_repetition(
    path: Path, *, expected_sha256: str, expected_plan_sha256: str
) -> dict[str, Any]:
    """Require every planned epoch and the externally sealed final ACTIVE journal."""
    raw = _read(path, expected_sha256)
    manifest = json.loads(raw)
    if (
        type(manifest) is not dict
        or set(manifest)
        != {
            "revision",
            "repetition_id",
            "plan",
            "windows",
            "journal",
            "campaign_eligible",
        }
        or d._json(manifest) + b"\n" != raw
        or manifest["revision"] != "w2-renewal-repetition-v1"
        or manifest["campaign_eligible"] is not False
        or manifest["plan"]
        != {"filename": "renewal-plan.json", "sha256": expected_plan_sha256}
    ):
        raise ValueError("renewal repetition manifest mismatch")
    policy = _Policy(path.parent, expected_plan_sha256)
    if (
        manifest["repetition_id"] != policy.plan["repetition_id"]
        or type(manifest["windows"]) is not list
        or len(manifest["windows"]) != len(policy.plan["windows"])
    ):
        raise ValueError("renewal repetition truncated or substituted")
    results = []
    for index, link in enumerate(manifest["windows"]):
        if (
            type(link) is not dict
            or set(link) != {"filename", "sha256"}
            or link["filename"] != f"window-{index:03d}.jsonl"
        ):
            raise ValueError("renewal repetition window link")
        results.append(policy.verify(path.parent / link["filename"], link["sha256"]))
    journal = manifest["journal"]
    if (
        type(journal) is not dict
        or set(journal) != {"filename", "sha256", "tip_digest"}
        or journal["filename"] != "renewal-journal.jsonl"
    ):
        raise ValueError("renewal repetition journal link")
    journal_raw = _read(path.parent / journal["filename"], journal["sha256"])
    final_records = policy.completed[len(results) - 1]["header"]["renewal"]["records"]
    if (
        journal_raw != b"".join(encode_payload(row) + b"\n" for row in final_records)
        or sha256_digest(encode_payload(final_records[-1])) != journal["tip_digest"]
    ):
        raise ValueError("renewal final journal tip or prefix mismatch")
    return {
        "manifest_path": str(path),
        "manifest_sha256": expected_sha256,
        "windows": results,
        "campaign_eligible": False,
    }
