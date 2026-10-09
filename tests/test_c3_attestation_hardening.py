from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization as c3_receipt_serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from constitutional_swarm.governed_handoff import PolicyEngine, run_task, verify_bundle
from constitutional_swarm.governance_fixtures import (
    collusion_bundle,
    fixture_trusted_signers,
    slow_burn_bundle,
    valid_provenance_bundle,
)
import constitutional_swarm.governed_handoff as governed_handoff_module
from constitutional_swarm.governance_receipts import (
    GovernanceReceipt,
    GovernanceReceiptBundle,
    ReceiptPayload,
    RoleIdentity,
    SignatureRecord,
    ValidatorVote,
    build_receipt,
    bundle_from_json,
    bundle_to_json,
    payload_canonical_bytes,
    payload_digest,
    verify_bundle as verify_receipt_bundle,
)
from constitutional_swarm.governance_receipts_cli import main as receipts_cli_main


def c3_handoff_write_configs(root: Path, protected_paths: list[str] | None = None) -> None:
    acgs = root / ".acgs"
    acgs.mkdir(exist_ok=True)
    paths = protected_paths if protected_paths is not None else ["protected/**"]
    protected_yaml = "\n".join(f'    - "{path}"' for path in paths)
    (acgs / "constitution.yaml").write_text(
        "schema_version: 1\n"
        "policy:\n"
        "  unknown_decisions: fail_closed\n"
        "  protected_paths:\n"
        f"{protected_yaml}\n"
        "  command_allowlist:\n"
        '    - "true"\n',
        encoding="utf-8",
    )
    (acgs / "swarm.yaml").write_text(
        "schema_version: 1\n"
        "roles:\n"
        "  proposer: {adapter: mock}\n"
        "  executor: {adapter: mock}\n"
        "  validator: {adapter: mock}\n"
        "  observer: {adapter: mock}\n"
        "adapters:\n"
        "  mock: {}\n",
        encoding="utf-8",
    )


def c3_handoff_signed_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, task_id: str
) -> tuple[Path, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    c3_handoff_write_configs(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("ACGS_SIGNING_KEY", private_key.private_bytes_raw().hex())
    task = tmp_path / f"{task_id}.md"
    task.write_text(
        f"task_id: {task_id}\nACGS_WRITE output.txt :: ok\nACGS_TEST true\n",
        encoding="utf-8",
    )
    result = run_task(task, repo_root=tmp_path)
    return result.bundle_path, private_key.public_key().public_bytes_raw().hex()


class TestC3Handoff:
    @pytest.mark.parametrize(
        "field,replacement",
        [
            ("task_metadata", {"task_id": "forged", "task_hash": "0" * 64}),
            ("role_assignments", {"attacker": {"adapter": "mock"}}),
            ("policy_decisions", [{"gate": "handoff", "outcome": "allow"}]),
            ("tool_events", [{"command": "fake", "passed": True}]),
            ("file_changes", [{"path": ".git/config", "action": "write"}]),
            ("tests_run", [{"command": "fake", "passed": True}]),
            ("final_state", {"state": "handoff_ready", "forged": True}),
            ("audit_path", "/tmp/attacker.audit.jsonl"),
        ],
    )
    def test_signed_v2_rejects_any_payload_mutation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        field: str,
        replacement: object,
    ) -> None:
        bundle_path, public_key = c3_handoff_signed_run(
            tmp_path, monkeypatch, f"mutate-{field}"
        )
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle[field] = replacement
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

        verdict = verify_bundle(
            bundle_path, trusted_public_keys={"acgs-supervisor": public_key}
        )

        assert verdict["ok"] is False
        assert verdict["signature_status"] == "invalid"

    def test_valid_v2_bundle_verifies_with_trusted_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bundle_path, public_key = c3_handoff_signed_run(
            tmp_path, monkeypatch, "valid-v2"
        )

        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        verdict = verify_bundle(
            bundle_path, trusted_public_keys={"acgs-supervisor": public_key}
        )

        assert bundle["schema_version"] == 2
        assert verdict["ok"] is True
        assert verdict["summary_ok"] is True

    def test_verify_cli_accepts_trusted_v2_and_rejects_unsigned_summary_tampering(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        bundle_path, public_key = c3_handoff_signed_run(
            tmp_path, monkeypatch, "cli-trusted-v2"
        )
        verify_args = [
            "verify",
            "--bundle",
            str(bundle_path),
            "--trusted-key",
            f"acgs-supervisor={public_key}",
        ]

        assert governed_handoff_module.main(verify_args) == 0
        valid_output = json.loads(capsys.readouterr().out)
        assert valid_output["ok"] is True

        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle["tests_run"] = [{"command": "fake", "passed": True}]
        bundle["policy_decisions"] = [{"gate": "handoff", "outcome": "allow"}]
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

        assert governed_handoff_module.main(verify_args) == 1
        tampered_output = json.loads(capsys.readouterr().out)
        assert tampered_output["ok"] is False

    def test_embedded_events_are_authoritative_over_bundle_audit_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bundle_path, public_key = c3_handoff_signed_run(
            tmp_path, monkeypatch, "embedded-authority"
        )
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        external = tmp_path / "valid-external.audit.jsonl"
        external.write_text(
            "\n".join(json.dumps(event) for event in bundle["audit_events"]) + "\n",
            encoding="utf-8",
        )
        bundle["audit_path"] = str(external)
        bundle["audit_events"][1]["payload"]["task_hash"] = "tampered"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

        verdict = verify_bundle(
            bundle_path, trusted_public_keys={"acgs-supervisor": public_key}
        )

        assert verdict["ok"] is False
        assert verdict["chain_ok"] is False

    def test_unsigned_and_legacy_bundles_fail_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        c3_handoff_write_configs(tmp_path)
        task = tmp_path / "unsigned.md"
        task.write_text(
            "task_id: unsigned-v2\nACGS_WRITE output.txt :: ok\nACGS_TEST true\n",
            encoding="utf-8",
        )
        result = run_task(task, repo_root=tmp_path)
        unsigned = verify_bundle(result.bundle_path)
        assert unsigned["chain_ok"] is True
        assert unsigned["signature_status"] == "unsigned"
        assert unsigned["ok"] is False

        bundle_path, public_key = c3_handoff_signed_run(tmp_path, monkeypatch, "legacy")
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle["schema_version"] = 1
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        legacy = verify_bundle(
            bundle_path, trusted_public_keys={"acgs-supervisor": public_key}
        )
        assert legacy["chain_ok"] is True
        assert legacy["ok"] is False
        assert "schema" in legacy["error"]

    def test_summary_must_equal_values_derived_from_embedded_events(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bundle_path, public_key = c3_handoff_signed_run(
            tmp_path, monkeypatch, "summary-compare"
        )
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle["tests_run"] = []
        bundle.pop("signature")
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

        verdict = verify_bundle(
            bundle_path, trusted_public_keys={"acgs-supervisor": public_key}
        )

        assert verdict["summary_ok"] is False
        assert "tests_run" in verdict["summary_mismatches"]
        assert verdict["ok"] is False


class TestC3ProtectedPaths:
    @pytest.mark.parametrize(
        "raw_path",
        [
            ".git",
            ".git/config",
            ".GIT/config",
            "./.github/workflows/release.yml",
            "nested/repo/.git/config",
            "nested/../.acgs/evidence/bundle.json",
            ".acgs/",
            ".claude/settings.json",
            ".VSCODE/settings.json",
            ".husky/pre-commit",
            ".envrc",
            ".PRE-COMMIT-CONFIG.YAML",
        ],
    )
    def test_code_owned_metadata_roots_cannot_be_unprotected(
        self, tmp_path: Path, raw_path: str
    ) -> None:
        engine = PolicyEngine(
            {"policy": {"protected_paths": []}},
            {"roles": {}},
            tmp_path,
        )

        decision = engine.decide("file_write", raw_path)

        assert decision.outcome == "human_review_required"
        assert "protected path" in decision.reason

    @pytest.mark.parametrize(
        "raw_path",
        [".env", "secrets/api-token", "custom-protected/config.json"],
    )
    def test_configured_protections_extend_code_owned_defaults(
        self, tmp_path: Path, raw_path: str
    ) -> None:
        engine = PolicyEngine(
            {"policy": {"protected_paths": ["custom-protected/**"]}},
            {"roles": {}},
            tmp_path,
        )

        decision = engine.decide("file_write", raw_path)

        assert decision.outcome == "human_review_required"

    @pytest.mark.parametrize(
        "pattern,raw_path",
        [
            ("./custom-protected/**", "custom-protected/config.json"),
            ("custom-protected/", "custom-protected/"),
        ],
    )
    def test_configured_protection_patterns_are_normalized(
        self, tmp_path: Path, pattern: str, raw_path: str
    ) -> None:
        engine = PolicyEngine(
            {"policy": {"protected_paths": [pattern]}},
            {"roles": {}},
            tmp_path,
        )

        decision = engine.decide("file_write", raw_path)

        assert decision.outcome == "human_review_required"

    def test_symlink_alias_into_tool_configuration_is_protected(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / ".claude").mkdir()
        (tmp_path / "tool-config").symlink_to(
            tmp_path / ".claude", target_is_directory=True
        )
        engine = PolicyEngine(
            {"policy": {"protected_paths": []}},
            {"roles": {}},
            tmp_path,
        )

        decision = engine.decide("file_write", "tool-config/settings.json")

        assert decision.outcome == "human_review_required"
        assert decision.subject == ".claude/settings.json"

    def test_symlink_alias_into_metadata_root_is_protected(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / "git-alias").symlink_to(tmp_path / ".git", target_is_directory=True)
        engine = PolicyEngine(
            {"policy": {"protected_paths": ["protected/**"]}},
            {"roles": {}},
            tmp_path,
        )

        decision = engine.decide("file_write", "git-alias/config")

        assert decision.outcome == "human_review_required"
        assert decision.subject == ".git/config"

    def test_similarly_named_directory_remains_unprotected(self, tmp_path: Path) -> None:
        engine = PolicyEngine(
            {"policy": {"protected_paths": []}},
            {"roles": {}},
            tmp_path,
        )

        assert engine.decide("file_write", ".github-old/file").outcome == "allow"

    def test_run_task_does_not_modify_git_config(self, tmp_path: Path) -> None:
        c3_handoff_write_configs(tmp_path, protected_paths=[])
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        config = git_dir / "config"
        config.write_text("safe\n", encoding="utf-8")
        task = tmp_path / "protected.md"
        task.write_text(
            "task_id: protected-git\nACGS_WRITE .git/config :: malicious\nACGS_TEST true\n",
            encoding="utf-8",
        )

        result = run_task(task, repo_root=tmp_path)

        assert result.final_state == "human_review_required"
        assert config.read_text(encoding="utf-8") == "safe\n"

    @pytest.mark.parametrize("raw_path", ["", "."])
    def test_repository_root_is_denied_as_a_write_target(
        self, tmp_path: Path, raw_path: str
    ) -> None:
        engine = PolicyEngine(
            {"policy": {"protected_paths": []}},
            {"roles": {}},
            tmp_path,
        )

        decision = engine.decide("file_write", raw_path)

        assert decision.outcome == "deny"
        assert "repository root" in decision.reason

    def test_run_task_root_write_is_denied_and_still_emits_bundle(
        self, tmp_path: Path
    ) -> None:
        c3_handoff_write_configs(tmp_path, protected_paths=[])
        task = tmp_path / "root-write.md"
        task.write_text(
            "task_id: root-write\nACGS_WRITE . :: malicious\nACGS_TEST true\n",
            encoding="utf-8",
        )

        result = run_task(task, repo_root=tmp_path)
        bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))

        assert result.final_state == "blocked"
        assert result.bundle_path.is_file()
        assert any(
            decision["gate"] == "file_write"
            and decision["outcome"] == "deny"
            and "repository root" in decision["reason"]
            for decision in bundle["policy_decisions"]
        )
        assert bundle["file_changes"] == []

    def test_write_race_never_follows_replaced_symlink(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        c3_handoff_write_configs(tmp_path)
        victim = tmp_path / "victim.txt"
        victim.write_text("safe\n", encoding="utf-8")
        target = tmp_path / "output.txt"
        task = tmp_path / "race.md"
        task.write_text(
            "task_id: write-race\nACGS_WRITE output.txt :: governed\nACGS_TEST true\n",
            encoding="utf-8",
        )
        original_hash_file = governed_handoff_module.hash_file
        original_os_open = os.open
        injected = False

        def inject_symlink() -> None:
            nonlocal injected
            if injected:
                return
            injected = True
            target.unlink(missing_ok=True)
            target.symlink_to(victim)

        def racing_hash_file(path: Path) -> str | None:
            if path == target:
                inject_symlink()
            return original_hash_file(path)

        def racing_os_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if path == target.name and dir_fd is not None:
                inject_symlink()
            return original_os_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(governed_handoff_module, "hash_file", racing_hash_file)
        monkeypatch.setattr(governed_handoff_module.os, "open", racing_os_open)

        with pytest.raises(OSError):
            run_task(task, repo_root=tmp_path)

        assert injected is True
        assert victim.read_text(encoding="utf-8") == "safe\n"

    def test_descriptor_writer_creates_nested_regular_file(self, tmp_path: Path) -> None:
        c3_handoff_write_configs(tmp_path)
        task = tmp_path / "nested.md"
        task.write_text(
            "task_id: nested-write\n"
            "ACGS_WRITE generated/deep/output.txt :: governed\n"
            "ACGS_TEST true\n",
            encoding="utf-8",
        )

        result = run_task(task, repo_root=tmp_path)

        assert result.final_state == "handoff_ready"
        assert (tmp_path / "generated/deep/output.txt").read_text(
            encoding="utf-8"
        ) == "governed"

    def test_existing_target_probe_is_nonblocking(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        c3_handoff_write_configs(tmp_path)
        target = tmp_path / "output.txt"
        target.write_text("old\n", encoding="utf-8")
        task = tmp_path / "nonblocking.md"
        task.write_text(
            "task_id: nonblocking-write\n"
            "ACGS_WRITE output.txt :: governed\n"
            "ACGS_TEST true\n",
            encoding="utf-8",
        )
        original_os_open = os.open
        target_open_flags: list[int] = []

        def recording_os_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if path == target.name and dir_fd is not None:
                target_open_flags.append(flags)
            return original_os_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(governed_handoff_module.os, "open", recording_os_open)

        result = run_task(task, repo_root=tmp_path)

        assert result.final_state == "handoff_ready"
        assert target_open_flags
        assert target_open_flags[0] & os.O_NONBLOCK

    def test_hardlink_target_is_replaced_without_mutating_protected_inode(
        self, tmp_path: Path
    ) -> None:
        c3_handoff_write_configs(tmp_path)
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        protected = git_dir / "config"
        protected.write_text("safe\n", encoding="utf-8")
        target = tmp_path / "output.txt"
        os.link(protected, target)
        task = tmp_path / "hardlink.md"
        task.write_text(
            "task_id: hardlink-write\n"
            "ACGS_WRITE output.txt :: governed\n"
            "ACGS_TEST true\n",
            encoding="utf-8",
        )

        result = run_task(task, repo_root=tmp_path)

        assert result.final_state == "handoff_ready"
        assert target.read_text(encoding="utf-8") == "governed"
        assert protected.read_text(encoding="utf-8") == "safe\n"


def c3_transport_handler(request):
    from constitutional_swarm.mesh.vote_envelope import VoteEnvelope, canonical_assigned_peers_hash
    from constitutional_swarm.remote_vote_transport import RemoteVoteResponse

    return RemoteVoteResponse(
        VoteEnvelope(
            protocol_version=2,
            voter_id=request.voter_id,
            key_id="00" * 32,
            task_id=request.task_id or request.artifact_id,
            assignment_id=request.assignment_id,
            producer_id=request.producer_id,
            artifact_id=request.artifact_id,
            content_hash=request.content_hash,
            constitutional_hash=request.constitutional_hash,
            decision="approved",
            reason="ok",
            nonce=request.nonce,
            issued_at=request.timestamp,
            signature="00" * 64,
            assigned_peers_hash=canonical_assigned_peers_hash(request.assigned_peers),
            assigned_peer_count=len(request.assigned_peers),
            quorum=request.quorum,
            evidence_mode=request.evidence_mode,
        )
    )


def c3_transport_request(
    *,
    peer_constitution,
    request_constitution,
    content="safe content",
    request_content=None,
):
    import hashlib
    from dataclasses import replace

    from constitutional_swarm import ConstitutionalMesh, LocalRemotePeer
    from constitutional_swarm.mesh.vote_envelope import sign_assignment
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    request_signer = Ed25519PrivateKey.generate()
    assigner_key = Ed25519PrivateKey.generate()
    mesh = ConstitutionalMesh(
        request_constitution,
        peers_per_validation=2,
        quorum=2,
        seed=341,
        assigner_private_key=assigner_key,
        assigner_id="c3-transport-assigner",
        request_signing_private_key=request_signer,
    )
    peer = LocalRemotePeer(
        agent_id="peer-remote",
        constitution=peer_constitution,
        trusted_request_signers={mesh.get_request_signing_public_key()},
        trusted_assigners=mesh.vote_registry.frozen_copy(),
    )
    mesh.register_local_signer("producer")
    mesh.register_remote_agent("peer-remote", vote_public_key=peer.public_key_hex)
    mesh.register_local_signer("peer-local")
    assignment = mesh.request_validation("producer", content, "art-c3")
    request = mesh.prepare_remote_vote(assignment.assignment_id, "peer-remote")
    if request_content is not None:
        content_hash = hashlib.sha256(request_content.encode("utf-8")).hexdigest()[:32]
        original_assignment = request.signed_assignment
        assert original_assignment is not None
        signed_assignment = sign_assignment(
            assigner_key,
            task_id=original_assignment.task_id,
            assignment_id=original_assignment.assignment_id,
            assigner_id=original_assignment.assigner_id,
            producer_id=original_assignment.producer_id,
            artifact_id=original_assignment.artifact_id,
            content_hash=content_hash,
            constitutional_hash=original_assignment.constitutional_hash,
            assigned_peers=original_assignment.assigned_peers,
            quorum=original_assignment.quorum,
            selection_seed=original_assignment.selection_seed,
            issued_at=original_assignment.issued_at,
        )
        signature = request_signer.sign(
            ConstitutionalMesh.build_remote_vote_request_payload(
                assignment_id=request.assignment_id,
                voter_id=request.voter_id,
                producer_id=request.producer_id,
                artifact_id=request.artifact_id,
                content=request_content,
                content_hash=content_hash,
                constitutional_hash=request.constitutional_hash,
                voter_public_key=request.voter_public_key,
                nonce=request.nonce,
                timestamp=request.timestamp,
                task_id=request.task_id,
                assigned_peers=request.assigned_peers,
                quorum=request.quorum,
                evidence_mode=request.evidence_mode,
                protocol_version=request.protocol_version,
                signed_assignment=signed_assignment,
            )
        ).hex()
        request = replace(
            request,
            content=request_content,
            content_hash=content_hash,
            signed_assignment=signed_assignment,
            request_signature=signature,
        )
    return peer, request


def c3_transport_certificate(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certfile = tmp_path / "server-cert.pem"
    keyfile = tmp_path / "server-key.pem"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certfile, keyfile


def c3_transport_memory_bio_handshake(server_context, client_context):
    import ssl

    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client = client_context.wrap_bio(
        client_in,
        client_out,
        server_side=False,
        server_hostname="localhost",
    )
    server_done = client_done = False
    for _ in range(20):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        client_bytes = client_out.read()
        if client_bytes:
            server_in.write(client_bytes)
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        server_bytes = server_out.read()
        if server_bytes:
            client_in.write(server_bytes)
        if server_done and client_done:
            return
    raise AssertionError("TLS MemoryBIO handshake did not complete")


class TestC3Transport:
    def test_authenticated_foreign_constitution_is_rejected_by_dispatcher(self):
        import asyncio

        from acgs_lite import Constitution
        from constitutional_swarm.remote_vote_transport import (
            RemoteVoteServer,
            encode_remote_vote_request,
        )

        class C3TransportWebSocket:
            def __init__(self, request):
                self._incoming = [encode_remote_vote_request(request)]
                self.sent = []

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._incoming:
                    return self._incoming.pop(0)
                raise StopAsyncIteration

            async def send(self, message):
                self.sent.append(message)

        peer_constitution = Constitution.default()
        peer, request = c3_transport_request(
            peer_constitution=peer_constitution,
            request_constitution=Constitution(),
        )
        server = RemoteVoteServer(peer.handle_vote_request)
        websocket = C3TransportWebSocket(request)

        with pytest.raises(ValueError, match="constitutional hash does not match"):
            asyncio.run(server._handle_connection(websocket))
        assert websocket.sent == []

    def test_peer_constitution_cannot_be_reassigned_after_validator_construction(self):
        from acgs_lite import Constitution

        default_constitution = Constitution.default()
        peer, request = c3_transport_request(
            peer_constitution=Constitution(),
            request_constitution=default_constitution,
            request_content="password",
        )

        with pytest.raises(AttributeError):
            peer.constitution = default_constitution
        with pytest.raises(ValueError, match="constitutional hash does not match"):
            peer.handle_vote_request(request)

    def test_mutating_exposed_constitution_does_not_change_evaluated_policy(self):
        from acgs_lite import Constitution

        default_constitution = Constitution.default()
        peer, request = c3_transport_request(
            peer_constitution=Constitution(),
            request_constitution=default_constitution,
            request_content="password",
        )
        exposed_constitution = peer.constitution
        exposed_constitution.__dict__.update(
            default_constitution.model_copy(deep=True).__dict__
        )

        with pytest.raises(ValueError, match="constitutional hash does not match"):
            peer.handle_vote_request(request)

    def test_internal_constitution_drift_is_detected_before_signing(self):
        from acgs_lite import Constitution

        constitution = Constitution.default()
        peer, request = c3_transport_request(
            peer_constitution=constitution,
            request_constitution=constitution,
        )
        peer._dna.constitution.rules.clear()

        with pytest.raises(RuntimeError, match="constitution changed after initialization"):
            peer.handle_vote_request(request)

    def test_matching_constitution_response_is_signed_over_local_hash(self):
        from acgs_lite import Constitution
        from constitutional_swarm.mesh.vote_envelope import (
            VoteSignerRegistry,
            verify_vote_envelope,
        )

        constitution = Constitution.default()
        peer, request = c3_transport_request(
            peer_constitution=constitution,
            request_constitution=constitution,
        )

        response = peer.handle_vote_request(request)

        assert response.constitutional_hash == constitution.hash
        registry = VoteSignerRegistry()
        registry.register(response.voter_id, peer.public_key_hex, roles={"voter"})
        assert verify_vote_envelope(
            response.envelope,
            registry,
            task_id=request.task_id or request.artifact_id,
            assignment_id=request.assignment_id,
            producer_id=request.producer_id,
            artifact_id=request.artifact_id,
            content_hash=request.content_hash,
            constitutional_hash=constitution.hash,
        ) == response.envelope

    def test_authenticated_untrusted_request_does_not_mutate_nonce_cache(self):
        from collections import OrderedDict

        from acgs_lite import Constitution
        from constitutional_swarm import ConstitutionalMesh, LocalRemotePeer
        from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

        constitution = Constitution.default()
        trusted_mesh = ConstitutionalMesh(
            constitution, seed=341, assigner_id="trusted-assigner"
        )
        untrusted_mesh = ConstitutionalMesh(
            constitution, seed=342, assigner_id="untrusted-assigner"
        )
        assignment_authorities = VoteSignerRegistry()
        assignment_authorities.register(
            "trusted-assigner",
            trusted_mesh.get_assigner_public_key(),
            roles={"assigner"},
        )
        assignment_authorities.register(
            "untrusted-assigner",
            untrusted_mesh.get_assigner_public_key(),
            roles={"assigner"},
        )
        peer = LocalRemotePeer(
            agent_id="peer-remote",
            constitution=constitution,
            trusted_request_signers={trusted_mesh.get_request_signing_public_key()},
            trusted_assigners=assignment_authorities.frozen_copy(),
        )

        def prepare_request(mesh, artifact_id):
            mesh.register_local_signer("producer")
            mesh.register_remote_agent(
                "peer-remote", vote_public_key=peer.public_key_hex
            )
            mesh.register_local_signer("peer-local")
            assignment = mesh.request_validation(
                "producer", "safe content", artifact_id
            )
            return mesh.prepare_remote_vote(assignment.assignment_id, "peer-remote")

        trusted_request = prepare_request(trusted_mesh, "art-trusted")
        peer.handle_vote_request(trusted_request)
        cache_before = OrderedDict(peer._request_nonce_cache)

        untrusted_request = prepare_request(untrusted_mesh, "art-untrusted")
        assert ConstitutionalMesh.verify_remote_vote_request(
            untrusted_request, nonce_cache=OrderedDict()
        )
        with pytest.raises(ValueError, match="signer is not trusted"):
            peer.handle_vote_request(untrusted_request)

        assert peer._request_nonce_cache == cache_before

    def test_tls_server_requires_credentials_before_start(self):
        from constitutional_swarm.remote_vote_transport import RemoteVoteServer

        with pytest.raises(ValueError, match="TLS server requires ssl_context or certfile"):
            RemoteVoteServer(c3_transport_handler, transport_security="tls")
        with pytest.raises(ValueError, match="TLS server requires ssl_context or certfile"):
            RemoteVoteServer(
                c3_transport_handler,
                host="service.example",
                transport_security="auto",
            )

    def test_tls_server_accepts_certificate_paths_and_completes_handshake(self, tmp_path):
        import ssl

        from constitutional_swarm.remote_vote_transport import RemoteVoteServer

        certfile, keyfile = c3_transport_certificate(tmp_path)
        server = RemoteVoteServer(
            c3_transport_handler,
            transport_security="tls",
            certfile=certfile,
            keyfile=keyfile,
        )
        client_context = ssl.create_default_context(cafile=str(certfile))

        c3_transport_memory_bio_handshake(server.ssl_context, client_context)

    def test_tls_server_accepts_and_forwards_supplied_context(self, monkeypatch):
        import asyncio
        import ssl

        import websockets
        from constitutional_swarm.remote_vote_transport import RemoteVoteServer

        supplied = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        captured = {}

        class C3TransportStartedServer:
            sockets = []

        async def c3_transport_serve(handler, host, port, *, ssl=None):
            captured.update(handler=handler, host=host, port=port, ssl=ssl)
            return C3TransportStartedServer()

        monkeypatch.setattr(websockets, "serve", c3_transport_serve)
        server = RemoteVoteServer(
            c3_transport_handler,
            transport_security="tls",
            ssl_context=supplied,
        )

        asyncio.run(server.start())

        assert server.ssl_context is supplied
        assert captured["ssl"] is supplied

    def test_tls_client_accepts_and_forwards_supplied_context(self, monkeypatch):
        import asyncio
        import ssl

        import websockets
        from acgs_lite import Constitution
        from constitutional_swarm.remote_vote_transport import (
            RemoteVoteClient,
            encode_remote_vote_response,
        )

        constitution = Constitution.default()
        _, request = c3_transport_request(
            peer_constitution=constitution,
            request_constitution=constitution,
        )
        response = c3_transport_handler(request)
        supplied = ssl.create_default_context()
        captured = {}

        class C3TransportClientSocket:
            async def send(self, message):
                captured["message"] = message

            async def recv(self):
                return encode_remote_vote_response(response)

        class C3TransportConnect:
            async def __aenter__(self):
                return C3TransportClientSocket()

            async def __aexit__(self, *args):
                return None

        def c3_transport_connect(uri, ssl=None):
            captured.update(uri=uri, ssl=ssl)
            return C3TransportConnect()

        monkeypatch.setattr(websockets, "connect", c3_transport_connect)
        client = RemoteVoteClient(transport_security="tls", ssl_context=supplied)

        asyncio.run(client.request_vote("service.example", 9443, request))

        assert captured["uri"] == "wss://service.example:9443"
        assert captured["ssl"] is supplied

    def test_tls_configuration_rejects_conflicts_lone_key_and_plaintext_material(self, tmp_path):
        import ssl

        from constitutional_swarm.remote_vote_transport import RemoteVoteServer

        certfile, keyfile = c3_transport_certificate(tmp_path)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        with pytest.raises(ValueError, match="cannot combine ssl_context with certfile or keyfile"):
            RemoteVoteServer(
                c3_transport_handler,
                transport_security="tls",
                ssl_context=context,
                certfile=certfile,
                keyfile=keyfile,
            )
        with pytest.raises(ValueError, match="keyfile requires certfile"):
            RemoteVoteServer(
                c3_transport_handler,
                transport_security="tls",
                keyfile=keyfile,
            )
        with pytest.raises(ValueError, match="plaintext transport cannot use TLS material"):
            RemoteVoteServer(
                c3_transport_handler,
                transport_security="plaintext",
                certfile=certfile,
                keyfile=keyfile,
            )

    def test_tls_server_rejects_client_context_at_construction(self):
        import ssl

        from constitutional_swarm.remote_vote_transport import RemoteVoteServer

        client_context = ssl.create_default_context()

        with pytest.raises(ValueError, match="PROTOCOL_TLS_SERVER"):
            RemoteVoteServer(
                c3_transport_handler,
                transport_security="tls",
                ssl_context=client_context,
            )

    def test_tls_client_rejects_server_context_at_construction(self):
        import ssl

        from constitutional_swarm.remote_vote_transport import RemoteVoteClient

        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        with pytest.raises(ValueError, match="PROTOCOL_TLS_CLIENT"):
            RemoteVoteClient(
                transport_security="tls",
                ssl_context=server_context,
            )

    def test_auto_client_rejects_explicit_context_at_construction(self):
        import ssl

        from constitutional_swarm.remote_vote_transport import RemoteVoteClient

        client_context = ssl.create_default_context()

        with pytest.raises(ValueError, match="auto transport cannot use an explicit SSL context"):
            RemoteVoteClient(
                transport_security="auto",
                ssl_context=client_context,
            )


def c3_receipt_payload(
    *,
    decision: str = "approved",
    votes: list[ValidatorVote] | None = None,
) -> ReceiptPayload:
    validator_votes = votes or [
        ValidatorVote(
            validator_id=f"c3-validator-{index}", decision="approve", rationale="ok"
        )
        for index in range(3)
    ]
    from constitutional_swarm.mesh.vote_envelope import (
        sign_assignment,
        sign_vote_envelope,
        signed_assignment_digest,
        signed_assignment_to_dict,
        vote_envelope_to_dict,
    )

    assigned_peers = tuple(vote.validator_id for vote in validator_votes)
    quorum = max(3, len(assigned_peers) // 2 + 1) if len(assigned_peers) >= 3 else len(assigned_peers) // 2 + 1
    assigner_key = Ed25519PrivateKey.from_private_bytes(bytes([30]) * 32)
    signed_assignment = sign_assignment(
        assigner_key,
        task_id="c3-task",
        assignment_id="c3-assignment",
        assigner_id="c3-assigner",
        producer_id="c3-producer",
        artifact_id="release governed artifact",
        content_hash="sha256:c3-artifact",
        constitutional_hash="sha256:c3-policy",
        assigned_peers=assigned_peers,
        quorum=quorum,
        selection_seed="c3-selection-seed",
        issued_at=0.0,
    )
    assignment_digest = signed_assignment_digest(signed_assignment)
    envelopes = []
    for index, vote in enumerate(validator_votes):
        if vote.decision == "abstain":
            continue
        private_key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(vote.validator_id.encode()).digest()
        )
        envelopes.append(
            vote_envelope_to_dict(
                sign_vote_envelope(
                    private_key,
                    voter_id=vote.validator_id,
                    task_id="c3-task",
                    assignment_id="c3-assignment",
                    producer_id="c3-producer",
                    artifact_id="release governed artifact",
                    content_hash="sha256:c3-artifact",
                    constitutional_hash="sha256:c3-policy",
                    decision="approved" if vote.decision == "approve" else "denied",
                    reason=vote.rationale,
                    nonce=f"c3-{index}-{vote.validator_id}",
                    issued_at=float(index + 1),
                    assigned_peers=assigned_peers,
                    quorum=quorum,
                    assignment_digest=assignment_digest,
                )
            )
        )
    return ReceiptPayload(
        receipt_id="c3-receipt",
        action="release governed artifact",
        policy_version="c3-policy-v1",
        policy_hash="sha256:c3-policy",
        roles={
            role: RoleIdentity(role=role, identity_id=f"c3-{role}", display_name=role)
            for role in ("constitution_author", "executor", "validator", "auditor")
        },
        evidence_hashes={"artifact": "sha256:c3-artifact"},
        decision=decision,
        validator_votes=validator_votes,
        vote_envelopes=envelopes or None,
        assigned_peers=list(assigned_peers),
        signed_assignment=signed_assignment_to_dict(signed_assignment),
        rejected_alternative="release without governance evidence",
        metadata={
            "assignment_id": "c3-assignment",
            "assigned_peer_count": str(len(validator_votes)),
            "artifact_id": "release governed artifact",
            "content_hash": "sha256:c3-artifact",
            "vote_evidence_mode": "independent",
            "producer_id": "c3-producer",
            "quorum": str(quorum),
            "signer_role": "settlement",
            "task_id": "c3-task",
            "vote_evidence_version": "constitutional-swarm.vote-envelope.v3",
        },
    )


def c3_receipt_signed_bundle(
    payload: ReceiptPayload,
) -> tuple[GovernanceReceiptBundle, dict[str, object]]:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes([31]) * 32)
    public_hex = private_key.public_key().public_bytes(
        encoding=c3_receipt_serialization.Encoding.Raw,
        format=c3_receipt_serialization.PublicFormat.Raw,
    ).hex()
    signature = SignatureRecord(
        key_id="c3-auditor-key",
        algorithm="ed25519",
        public_key_hex=public_hex,
        signature_hex=private_key.sign(payload_canonical_bytes(payload)).hex(),
    )
    receipt = GovernanceReceipt.model_construct(
        payload=payload,
        payload_digest=payload_digest(payload),
        signatures=[signature],
    )
    trusted: dict[str, object] = {
        "c3-auditor-key": {
            "identity_id": "c3-coordinator",
            "public_key_hex": public_hex,
            "roles": ["settlement"],
        }
    }
    from constitutional_swarm.mesh.vote_envelope import key_id_for_public_key

    assigner_key = Ed25519PrivateKey.from_private_bytes(bytes([30]) * 32)
    assigner_public_key = assigner_key.public_key()
    trusted[key_id_for_public_key(assigner_public_key)] = {
        "identity_id": "c3-assigner",
        "public_key_hex": assigner_public_key.public_bytes(
            encoding=c3_receipt_serialization.Encoding.Raw,
            format=c3_receipt_serialization.PublicFormat.Raw,
        ).hex(),
        "roles": ["assigner"],
    }
    for envelope in payload.vote_envelopes or []:
        voter_id = str(envelope["voter_id"])
        voter_key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(voter_id.encode()).digest()
        ).public_key()
        trusted[str(envelope["key_id"])] = {
            "identity_id": voter_id,
            "public_key_hex": voter_key.public_bytes(
                encoding=c3_receipt_serialization.Encoding.Raw,
                format=c3_receipt_serialization.PublicFormat.Raw,
            ).hex(),
            "roles": ["validator"],
        }
    bundle = GovernanceReceiptBundle.model_construct(
        profile_version="acgs.local.intoto-dsse-shaped.v0.1",
        receipts=[receipt],
        answer_key={},
        benchmark_metadata={},
    )
    return bundle, trusted


class TestC3Receipts:
    def test_approved_receipt_rejects_one_approve_four_denies(self) -> None:
        votes = [
            ValidatorVote(
                validator_id="approver",
                decision="approve",
                rationale="minority approval",
            ),
            *[
                ValidatorVote(
                    validator_id=f"denier-{index}",
                    decision="deny",
                    rationale="majority denial",
                )
                for index in range(4)
            ],
        ]

        with pytest.raises(ValidationError, match="not supported by validator votes"):
            c3_receipt_payload(decision="approved", votes=votes)

        valid = c3_receipt_payload(
            decision="approved",
            votes=[
                ValidatorVote(
                    validator_id=f"valid-approver-{index}",
                    decision="approve",
                    rationale="valid approval",
                )
                for index in range(5)
            ],
        )
        invalid = valid.model_copy(update={"validator_votes": votes})
        bundle, trusted = c3_receipt_signed_bundle(invalid)

        verdict = verify_receipt_bundle(bundle, trusted_signers=trusted)
        assert verdict.valid is False
        assert "decision_vote_mismatch" in {issue.code for issue in verdict.issues}
        assert verdict.signature_status == "valid"

    def test_approved_receipt_accepts_three_approves_two_denies(self) -> None:
        votes = [
            *[
                ValidatorVote(
                    validator_id=f"approver-{index}",
                    decision="approve",
                    rationale="majority approval",
                )
                for index in range(3)
            ],
            *[
                ValidatorVote(
                    validator_id=f"denier-{index}",
                    decision="deny",
                    rationale="minority denial",
                )
                for index in range(2)
            ],
        ]

        payload = c3_receipt_payload(decision="approved", votes=votes)
        bundle, trusted = c3_receipt_signed_bundle(payload)

        assert build_receipt(payload=payload).payload.decision == "approved"
        assert verify_receipt_bundle(bundle, trusted_signers=trusted).valid is True

    def test_denied_receipt_rejects_two_approves_two_denies_tie(self) -> None:
        votes = [
            *[
                ValidatorVote(
                    validator_id=f"approver-{index}",
                    decision="approve",
                    rationale="tied approval",
                )
                for index in range(2)
            ],
            *[
                ValidatorVote(
                    validator_id=f"denier-{index}",
                    decision="deny",
                    rationale="tied denial",
                )
                for index in range(2)
            ],
        ]

        payload = c3_receipt_payload(decision="denied", votes=votes)
        bundle, trusted = c3_receipt_signed_bundle(payload)

        assert build_receipt(payload=payload).payload.decision == "denied"
        verdict = verify_receipt_bundle(bundle, trusted_signers=trusted)
        assert verdict.valid is False
        assert "vote_tally_no_majority" in {issue.code for issue in verdict.issues}
        assert verdict.signature_status == "valid"

    def test_denied_receipt_rejects_three_approves_two_denies_across_bypasses(
        self,
    ) -> None:
        valid = c3_receipt_payload(
            decision="denied",
            votes=[
                ValidatorVote(
                    validator_id="denier",
                    decision="deny",
                    rationale="initial denial",
                )
            ],
        )
        invalid_votes = [
            *[
                ValidatorVote(
                    validator_id=f"approver-{index}",
                    decision="approve",
                    rationale="majority approval",
                )
                for index in range(3)
            ],
            *[
                ValidatorVote(
                    validator_id=f"denier-{index}",
                    decision="deny",
                    rationale="minority denial",
                )
                for index in range(2)
            ],
        ]
        invalid = valid.model_copy(update={"validator_votes": invalid_votes})

        with pytest.raises(ValueError, match="not supported by validator votes"):
            build_receipt(payload=invalid)

        bundle, trusted = c3_receipt_signed_bundle(invalid)
        verdict = verify_receipt_bundle(bundle, trusted_signers=trusted)
        assert verdict.valid is False
        assert "decision_vote_mismatch" in {issue.code for issue in verdict.issues}
        assert verdict.signature_status == "valid"

    def test_payload_constructor_rejects_duplicate_validator_ids(self) -> None:
        duplicate_votes = [
            ValidatorVote(validator_id="same-validator", decision="approve", rationale="first"),
            ValidatorVote(validator_id="same-validator", decision="deny", rationale="second"),
        ]

        with pytest.raises(ValueError, match="distinct voter identities"):
            c3_receipt_payload(votes=duplicate_votes)

    def test_payload_constructor_rejects_normalized_duplicate_validator_ids(self) -> None:
        alias_votes = [
            ValidatorVote(validator_id="validator-a", decision="approve", rationale="first"),
            ValidatorVote(validator_id="VALIDATOR-A ", decision="deny", rationale="alias"),
        ]

        with pytest.raises(ValueError, match="distinct voter identities"):
            c3_receipt_payload(votes=alias_votes)

    def test_payload_constructor_rejects_blank_validator_id(self) -> None:
        with pytest.raises((ValueError, ValidationError), match="empty|blank"):
            ValidatorVote(
                validator_id="   ",
                decision="approve",
                rationale="blank identity",
            )

    @pytest.mark.parametrize(
        ("decision", "vote_decision"),
        [("approved", "deny"), ("denied", "approve"), ("escalated", "approve")],
    )
    def test_payload_constructor_requires_a_supporting_vote(
        self, decision: str, vote_decision: str
    ) -> None:
        votes = [
            ValidatorVote(
                validator_id="c3-validator",
                decision=vote_decision,
                rationale="does not support the recorded outcome",
            )
        ]

        with pytest.raises(ValidationError, match="not supported by validator votes"):
            c3_receipt_payload(decision=decision, votes=votes)

    def test_builder_revalidates_payload_copied_without_validation(self) -> None:
        payload = c3_receipt_payload()
        invalid = payload.model_copy(
            update={
                "validator_votes": [
                    ValidatorVote(
                        validator_id="c3-validator", decision="deny", rationale="tampered"
                    )
                ]
            }
        )

        with pytest.raises(ValueError, match="not supported by validator votes"):
            build_receipt(payload=invalid)

    def test_builder_rejects_normalized_duplicate_ids_copied_without_validation(
        self,
    ) -> None:
        payload = c3_receipt_payload()
        invalid = payload.model_copy(
            update={
                "validator_votes": [
                    ValidatorVote(
                        validator_id="validator-a", decision="approve", rationale="first"
                    ),
                    ValidatorVote(
                        validator_id=" VALIDATOR-A", decision="deny", rationale="alias"
                    ),
                ]
            }
        )

        with pytest.raises(ValueError, match="validator IDs must be unique"):
            build_receipt(payload=invalid)

    def test_verifier_rejects_semantically_invalid_resigned_payload(self) -> None:
        invalid = c3_receipt_payload().model_copy(
            update={
                "validator_votes": [
                    ValidatorVote(
                        validator_id="c3-validator", decision="deny", rationale="tampered"
                    )
                ]
            }
        )
        bundle, trusted = c3_receipt_signed_bundle(invalid)

        verdict = verify_receipt_bundle(bundle, trusted_signers=trusted)

        assert verdict.valid is False
        assert "decision_vote_mismatch" in {issue.code for issue in verdict.issues}
        assert verdict.signature_status == "valid"

    def test_verifier_rejects_resigned_duplicate_validator_ids(self) -> None:
        invalid = c3_receipt_payload().model_copy(
            update={
                "validator_votes": [
                    ValidatorVote(
                        validator_id="same-validator", decision="approve", rationale="first"
                    ),
                    ValidatorVote(
                        validator_id="same-validator", decision="deny", rationale="duplicate"
                    ),
                ]
            }
        )
        bundle, trusted = c3_receipt_signed_bundle(invalid)

        verdict = verify_receipt_bundle(bundle, trusted_signers=trusted)

        assert verdict.valid is False
        assert "duplicate_validator_id" in {issue.code for issue in verdict.issues}
        assert verdict.signature_status == "valid"

    def test_verifier_rejects_resigned_normalized_duplicate_validator_ids(self) -> None:
        invalid = c3_receipt_payload().model_copy(
            update={
                "validator_votes": [
                    ValidatorVote(
                        validator_id="validator-a", decision="approve", rationale="first"
                    ),
                    ValidatorVote(
                        validator_id="VALIDATOR-A ", decision="deny", rationale="alias"
                    ),
                ]
            }
        )
        bundle, trusted = c3_receipt_signed_bundle(invalid)

        verdict = verify_receipt_bundle(bundle, trusted_signers=trusted)

        assert verdict.valid is False
        assert "duplicate_validator_id" in {issue.code for issue in verdict.issues}
        assert verdict.signature_status == "valid"

    @pytest.mark.parametrize(
        ("decision", "vote_decision"),
        [("approved", "approve"), ("denied", "deny")],
    )
    def test_supported_decisions_remain_valid(
        self, decision: str, vote_decision: str
    ) -> None:
        payload = c3_receipt_payload(
            decision=decision,
            votes=[
                ValidatorVote(
                    validator_id=f"c3-validator-{index}",
                    decision=vote_decision,
                    rationale="supported",
                )
                for index in range(3)
            ],
        )
        bundle, trusted = c3_receipt_signed_bundle(payload)

        assert verify_receipt_bundle(bundle, trusted_signers=trusted).valid is True

    def test_escalated_aggregate_receipt_is_not_proof_grade(self) -> None:
        payload = c3_receipt_payload(
            decision="escalated",
            votes=[
                ValidatorVote(
                    validator_id="c3-validator",
                    decision="abstain",
                    rationale="human review required",
                )
            ],
        )
        bundle, trusted = c3_receipt_signed_bundle(payload)

        verdict = verify_receipt_bundle(bundle, trusted_signers=trusted)
        assert verdict.valid is False
        assert "vote_envelope_missing" in {issue.code for issue in verdict.issues}

    def test_shipped_fixtures_use_distinct_multi_validator_tallies(self) -> None:
        trusted = fixture_trusted_signers()
        bundles = [valid_provenance_bundle(), collusion_bundle(), slow_burn_bundle()]

        for bundle in bundles:
            assert verify_receipt_bundle(bundle, trusted_signers=trusted).valid is True
            for receipt in bundle.receipts:
                votes = receipt.payload.validator_votes
                envelopes = receipt.payload.vote_envelopes
                validator_ids = {vote.validator_id.strip().casefold() for vote in votes}
                approve_count = sum(vote.decision == "approve" for vote in votes)
                deny_count = sum(vote.decision == "deny" for vote in votes)

                assert envelopes is not None
                assert [envelope["voter_id"] for envelope in envelopes] == [
                    vote.validator_id for vote in votes
                ]
                assert len(votes) > 1
                assert len(validator_ids) == len(votes)
                if receipt.payload.decision == "approved":
                    assert approve_count > deny_count
                elif receipt.payload.decision == "denied":
                    assert deny_count > 0
                    assert deny_count >= approve_count

        collusion = collusion_bundle()
        assert collusion.receipts[0].payload.metadata["k_compromised"] == "1"
        assert collusion.receipts[0].payload.metadata["n_validators"] == "4"
        assert collusion.receipts[0].payload.metadata["first_failure_k"] == "1"
        collusion_votes = {
            vote.validator_id: vote for vote in collusion.receipts[0].payload.validator_votes
        }
        assert "compromised" in collusion_votes["review-agent"].rationale
        assert "relied on the compromised review-agent" in collusion_votes["deploy-agent"].rationale
        assert "compromised review-agent misled deploy-agent" in (
            collusion.answer_key["validator_dissent"]
        )

        provenance = valid_provenance_bundle()
        assert any(
            vote.validator_id == "deploy-agent" and vote.dissent
            for vote in provenance.receipts[1].payload.validator_votes
        )
        assert provenance.answer_key["validator_dissent"] == (
            "deploy-agent dissented from the denial"
        )

    def test_default_mesh_majority_emits_a_valid_receipt(self, tmp_path: Path) -> None:
        from acgs_lite import Constitution

        from constitutional_swarm import ConstitutionalMesh, JSONLSettlementStore
        from constitutional_swarm.mesh.vote_envelope import key_id_for_public_key
        from constitutional_swarm.settlement_evidence import RECEIPT_SIGNER_KEY_ID

        store = JSONLSettlementStore(tmp_path / "c3-majority-mesh.jsonl")
        receipt_key = Ed25519PrivateKey.generate()
        voter_keys = {
            f"c3-majority-agent-{index}": Ed25519PrivateKey.generate()
            for index in range(5)
        }
        mesh = ConstitutionalMesh(
            Constitution.default(),
            peers_per_validation=3,
            quorum=3,
            seed=41,
            settlement_store=store,
            evidence_mode="single_operator_dev",
            receipt_signing_private_key=receipt_key,
        )
        for voter_id, voter_key in voter_keys.items():
            mesh.register_local_signer(voter_id, vote_private_key=voter_key)
        assignment = mesh.request_validation(
            "c3-majority-agent-0", "safe", "c3-majority-artifact"
        )
        for voter in assignment.peers:
            reason = "majority approval"
            mesh.submit_vote(
                assignment.assignment_id,
                voter,
                approved=True,
                reason=reason,
                signature=mesh.sign_vote(
                    assignment.assignment_id,
                    voter,
                    approved=True,
                    reason=reason,
                ),
            )

        bundle = bundle_from_json(
            mesh._receipt_bundle_path(assignment.assignment_id).read_text(encoding="utf-8")
        )
        trusted_signers = {
            RECEIPT_SIGNER_KEY_ID: {
                "identity_id": "mesh-settlement",
                "public_key_hex": receipt_key.public_key().public_bytes_raw().hex(),
                "roles": ["settlement"],
            }
        }
        assigner_public_key = bytes.fromhex(mesh.get_assigner_public_key())
        trusted_signers[key_id_for_public_key(assigner_public_key)] = {
            "identity_id": mesh.assigner_id,
            "public_key_hex": mesh.get_assigner_public_key(),
            "roles": ["assigner"],
        }
        for voter_id, voter_key in voter_keys.items():
            public_key = voter_key.public_key()
            trusted_signers[key_id_for_public_key(public_key)] = {
                "identity_id": voter_id,
                "public_key_hex": public_key.public_bytes_raw().hex(),
                "roles": ["validator"],
            }
        assert bundle.receipts[0].payload.decision == "approved"
        verdict = verify_receipt_bundle(
            bundle,
            trusted_signers=trusted_signers,
            require_independent_votes=False,
        )
        assert verdict.valid is True
        assert verdict.evidence_policy == "development"

    def test_tie_capable_mesh_configuration_fails_before_persistence(
        self, tmp_path: Path
    ) -> None:
        from acgs_lite import Constitution

        from constitutional_swarm import ConstitutionalMesh, JSONLSettlementStore

        store = JSONLSettlementStore(tmp_path / "c3-tied-mesh.jsonl")
        with pytest.raises(ValueError, match="quorum must be a strict majority"):
            ConstitutionalMesh(
                Constitution.default(),
                peers_per_validation=4,
                quorum=2,
                seed=43,
                settlement_store=store,
            )

        assert store.load_all() == []
        assert store.load_pending() == []

    def test_mesh_does_not_emit_denial_for_approve_only_insufficient_quorum(
        self, tmp_path
    ) -> None:
        from acgs_lite import Constitution

        from constitutional_swarm import ConstitutionalMesh, JSONLSettlementStore

        store = JSONLSettlementStore(tmp_path / "c3-mesh.jsonl")
        mesh = ConstitutionalMesh(
            Constitution.default(),
            peers_per_validation=3,
            quorum=3,
            seed=31,
            settlement_store=store,
            evidence_mode="single_operator_dev",
        )
        for index in range(4):
            mesh.register_local_signer(f"c3-agent-{index}")
        assignment = mesh.request_validation("c3-agent-0", "safe", "c3-artifact")
        voter = assignment.peers[0]
        reason = "approve without quorum"
        mesh.submit_vote(
            assignment.assignment_id,
            voter,
            approved=True,
            reason=reason,
            signature=mesh.sign_vote(
                assignment.assignment_id,
                voter,
                approved=True,
                reason=reason,
            ),
        )

        result = mesh.get_result(assignment.assignment_id)

        assert result.accepted is False
        assert result.quorum_met is False
        assert result.settled is False
        assert store.load_all() == []

    def test_report_mode_unsigned_bundle_is_invalid_and_cli_exits_nonzero(
        self, tmp_path, capsys
    ) -> None:
        unsigned = GovernanceReceiptBundle(receipts=[build_receipt(payload=c3_receipt_payload())])
        verdict = verify_receipt_bundle(unsigned, report_mode=True, trusted_signers={})
        bundle_path = tmp_path / "unsigned-c3.json"
        bundle_path.write_text(bundle_to_json(unsigned), encoding="utf-8")

        exit_code = receipts_cli_main([str(bundle_path), "--report-mode"])
        cli_verdict = json.loads(capsys.readouterr().out)

        assert verdict.valid is False
        assert verdict.signature_status == "unverifiable"
        assert exit_code == 1
        assert cli_verdict["valid"] is False
