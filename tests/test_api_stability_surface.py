"""The 1.2.x stability boundary: every module has a tier, and the docs agree.

``docs/API_STABILITY.md`` is the statement users read.  This file is the check
that keeps it true:

* the stable façade (``constitutional_swarm.__all__``) and the execution
  gateway's public names are frozen snapshots, so adding or removing a public
  name is a deliberate edit here and in the document;
* every top-level module and every ``apcc`` module is assigned exactly one
  tier, so a new module cannot ship unclassified;
* nothing on the stable façade is defined in an experimental or internal
  module, and a default import loads no experimental module;
* the tier tables in the document list exactly the modules assigned here.
"""

from __future__ import annotations

import pkgutil
import re
import subprocess
import sys
from pathlib import Path

import constitutional_swarm
import constitutional_swarm.apcc as apcc_package
from constitutional_swarm.apcc import execution_gateway

_DOCUMENT = Path(__file__).resolve().parents[1] / "docs" / "API_STABILITY.md"

STABLE = "stable"
ADVANCED = "advanced"
PROVISIONAL = "provisional"
EXPERIMENTAL = "experimental"
INTERNAL = "internal"

# Top-level modules and subpackages of ``constitutional_swarm``.
MODULE_TIERS: dict[str, str] = {
    # Stable core: the modules that define the façade, plus the console scripts.
    "artifact": STABLE,
    "capability": STABLE,
    "compiler": STABLE,
    "contract": STABLE,
    "dna": STABLE,
    "execution": STABLE,
    "governance_errors": STABLE,
    "governance_receipts": STABLE,
    "governance_receipts_cli": STABLE,
    "governed_commit": STABLE,
    "governed_handoff": STABLE,
    "mesh": STABLE,
    "settlement_evidence": STABLE,
    "settlement_store": STABLE,
    "swarm": STABLE,
    # Advanced runtime: stable APIs, imported by module path, often behind an extra.
    "bittensor": ADVANCED,
    "evolution_log": ADVANCED,
    "langgraph_runtime": ADVANCED,
    "remote_vote_transport": ADVANCED,
    "spectral_sphere": ADVANCED,
    # Provisional: the APCC authority runtime, new in 1.2.
    "apcc": PROVISIONAL,
    "authority_child": PROVISIONAL,
    "authority_ipc": PROVISIONAL,
    "authority_isolation": PROVISIONAL,
    "authority_observer": PROVISIONAL,
    "authority_service": PROVISIONAL,
    # Research and experimental: no compatibility promise.
    "agent_self_evolve": EXPERIMENTAL,
    "apcc_empirical": EXPERIMENTAL,
    "bench": EXPERIMENTAL,
    "byzantine_census": EXPERIMENTAL,
    "debate_resolver": EXPERIMENTAL,
    "epoch_reconfig": EXPERIMENTAL,
    "eval": EXPERIMENTAL,
    "federated_bridge": EXPERIMENTAL,
    "forensic_benchmark": EXPERIMENTAL,
    "gossip_protocol": EXPERIMENTAL,
    "latent_dna": EXPERIMENTAL,
    "mac_acgs_loop": EXPERIMENTAL,
    "manifold": EXPERIMENTAL,
    "merkle_crdt": EXPERIMENTAL,
    "node_admission": EXPERIMENTAL,
    "privacy_accountant": EXPERIMENTAL,
    "private_vote": EXPERIMENTAL,
    "quorum_certificate": EXPERIMENTAL,
    "swarm_ode": EXPERIMENTAL,
    "swe_bench": EXPERIMENTAL,
    "validator_set": EXPERIMENTAL,
    "violation_subspace": EXPERIMENTAL,
    # Internal support: importable, but not an API.
    "constants": INTERNAL,
    "framing": INTERNAL,
    "governance_fixtures": INTERNAL,
    "governance_receipts_dsse": INTERNAL,
    "protocol": INTERNAL,
    "secure_files": INTERNAL,
    "strict_json": INTERNAL,
}

# Modules of ``constitutional_swarm.apcc``.  The package as a whole is
# provisional; this says which of its modules carry public names at all.
APCC_MODULE_TIERS: dict[str, str] = {
    "execution_gateway": PROVISIONAL,
    "migration_v3_to_v4": PROVISIONAL,
    "model": PROVISIONAL,
    "observation": PROVISIONAL,
    "ports": PROVISIONAL,
    "postgres_store": PROVISIONAL,
    "service": PROVISIONAL,
    "sqlite_store": PROVISIONAL,
    "verifier": PROVISIONAL,
    "codec": INTERNAL,
    "crypto": INTERNAL,
    "gcb_projection": INTERNAL,
}

STABLE_FACADE: frozenset[str] = frozenset(
    {
        "AgentDNA",
        "Artifact",
        "ArtifactStore",
        "AssignmentSettledError",
        "CANONICALIZATION_ALGORITHM",
        "Capability",
        "CapabilityRegistry",
        "CommitDecision",
        "CommitOutcome",
        "CommitRequest",
        "ConstitutionalMesh",
        "ContractStatus",
        "DAGCompiler",
        "DNADisabledError",
        "DuplicateSettlementError",
        "DuplicateVoteError",
        "ExecutionStatus",
        "GCB_RECEIPT_PROFILE",
        "GoalSpec",
        "GoalStep",
        "GovernanceBypassDenied",
        "GovernanceReceipt",
        "GovernanceReceiptBundle",
        "GovernedCommitBoundary",
        "GovernedNodeState",
        "GovernedReceiptPayload",
        "InsufficientPeersError",
        "InvalidVoteSignatureError",
        "JSONLSettlementStore",
        "MeshHaltedError",
        "MeshProof",
        "MeshResult",
        "MeshSnapshotStaleError",
        "PROFILE_VERSION",
        "PeerAssignment",
        "PredecessorBinding",
        "REQUIRED_ROLES",
        "ReceiptIssue",
        "ReceiptPayload",
        "ReconciliationReport",
        "RecoveredAssignmentError",
        "RemoteVoteReplayError",
        "RemoteVoteRequest",
        "RoleIdentity",
        "SQLiteSettlementStore",
        "SettlementPersistenceError",
        "SettlementRecord",
        "SettlementStore",
        "SignatureRecord",
        "SignedGovernedReceipt",
        "SwarmExecutor",
        "TaskContract",
        "TaskDAG",
        "TaskNode",
        "UnauthorizedVoterError",
        "ValidationVote",
        "ValidatorVote",
        "VerificationVerdict",
        "WorkReceipt",
        "build_receipt",
        "bundle_from_json",
        "bundle_to_json",
        "canonical_json_bytes",
        "constitutional_dna",
        "payload_digest",
        "predecessor_root",
        "receipt_from_mesh_settlement",
        "receipt_hash",
        "settlement_canonical_digest",
        "sign_governed_receipt",
        "verdict_to_json",
        "verify_bundle",
        "verify_committed_settlement_receipt",
    }
)

GATEWAY_PUBLIC: frozenset[str] = frozenset(
    {
        "APCCExecutionGateway",
        "CredentialBoundHttpTarget",
        "EffectDisposition",
        "ExecutionGatewayError",
        "ExternalSideEffectTarget",
        "GatewayEffectRecord",
        "GatewayExecutionOutcome",
        "SQLiteExecutionLedger",
        "SideEffectInvocation",
        "StaleFencingTokenError",
        "TargetAuthorizationError",
        "TargetExecutionReceipt",
        "derive_effect_idempotency_key",
    }
)


def _children(package: object) -> set[str]:
    return {module.name for module in pkgutil.iter_modules(package.__path__)}  # type: ignore[attr-defined]


def test_every_top_level_module_has_exactly_one_tier() -> None:
    assert _children(constitutional_swarm) == set(MODULE_TIERS)


def test_every_apcc_module_has_exactly_one_tier() -> None:
    assert _children(apcc_package) == set(APCC_MODULE_TIERS)


def test_stable_facade_is_frozen() -> None:
    assert set(constitutional_swarm.__all__) == STABLE_FACADE
    assert len(constitutional_swarm.__all__) == len(STABLE_FACADE)


def test_gateway_public_names_are_frozen() -> None:
    assert set(execution_gateway.__all__) == GATEWAY_PUBLIC


def test_facade_names_resolve_and_are_defined_in_stable_modules() -> None:
    for name in constitutional_swarm.__all__:
        value = getattr(constitutional_swarm, name)
        module = getattr(value, "__module__", "")
        if not module.startswith("constitutional_swarm."):
            continue  # constants and other plain values have no defining module
        top_level = module.split(".")[1]
        assert MODULE_TIERS[top_level] == STABLE, (name, module)


def test_default_import_loads_no_experimental_module() -> None:
    script = (
        "import sys, constitutional_swarm\n"
        "print('\\n'.join(sorted(k.split('.')[1] for k in sys.modules"
        " if k.startswith('constitutional_swarm.'))))\n"
    )
    loaded = set(
        subprocess.run(
            [sys.executable, "-c", script], check=True, capture_output=True, text=True
        ).stdout.split()
    )
    experimental = {name for name, tier in MODULE_TIERS.items() if tier == EXPERIMENTAL}
    assert loaded & experimental == set()


def test_no_experimental_name_is_on_the_stable_facade() -> None:
    lazy = constitutional_swarm._LAZY_ATTRS
    assert set(constitutional_swarm.__all__) & set(lazy) == set()


_SECTION = re.compile(r"^## (?P<title>.+)$")
_ROW_MODULE = re.compile(r"^\| `(?P<module>[a-z_0-9.]+)`")
_TIER_BY_HEADING = {
    "Stable core": STABLE,
    "Advanced runtime": ADVANCED,
    "Provisional: APCC authority runtime": PROVISIONAL,
    "Research and experimental": EXPERIMENTAL,
    "Internal support": INTERNAL,
}


def _documented() -> dict[str, str]:
    tiers: dict[str, str] = {}
    current: str | None = None
    for line in _DOCUMENT.read_text(encoding="utf-8").splitlines():
        heading = _SECTION.match(line)
        if heading:
            current = _TIER_BY_HEADING.get(heading["title"])
            continue
        row = _ROW_MODULE.match(line)
        if row and current is not None:
            assert row["module"] not in tiers, f"{row['module']} is listed twice"
            tiers[row["module"]] = current
    return tiers


def test_document_lists_exactly_the_modules_assigned_here() -> None:
    expected = dict(MODULE_TIERS)
    expected.update({f"apcc.{name}": tier for name, tier in APCC_MODULE_TIERS.items()})
    assert _documented() == expected
