#!/usr/bin/env python3
"""Bittensor Testnet Deployment Script for Constitutional Governance Subnet.

Usage:
    # Register subnet on testnet
    python scripts/testnet_deploy.py register --wallet-name <name> --wallet-hotkey <key>

    # Start miner
    python scripts/testnet_deploy.py miner --wallet-name <name> --wallet-hotkey <key> \
        --constitution constitution.yaml --netuid <id> --trusted-validators <ss58>[,<ss58>]

    # Start validator
    python scripts/testnet_deploy.py validator --wallet-name <name> --wallet-hotkey <key> \
        --constitution constitution.yaml --authorized-voters voters.json \
        --authority-keys authority-keys.json --netuid <id>

Requirements:
    pip install "bittensor>=7.0,<11"
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, nullcontext
from typing import BinaryIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

BRAINTRUST_PROJECT = "acgs-swarm"


class _AuthorizedVoter:
    __slots__ = ("public_key", "route")

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        route: tuple[str, int],
    ) -> None:
        self.public_key = public_key
        self.route = route


class _AuthorityKeys:
    __slots__ = ("assigner_id", "assigner_private_key", "request_signing_private_key")

    def __init__(
        self,
        *,
        assigner_id: str,
        assigner_private_key: Ed25519PrivateKey,
        request_signing_private_key: Ed25519PrivateKey,
    ) -> None:
        self.assigner_id = assigner_id
        self.assigner_private_key = assigner_private_key
        self.request_signing_private_key = request_signing_private_key


@contextmanager
def _open_authority_key_file(path: str) -> Iterator[BinaryIO]:
    """Open a private authority file through the shared H3 policy.

    ``secure_files.private_file`` validates one descriptor snapshot: regular
    file, owned by the effective user, no group/other or special mode bits,
    exactly one link. ``O_NOFOLLOW`` protects only the final path component;
    operators must keep every parent directory under trusted control.
    """
    from constitutional_swarm.secure_files import PrivateFileError, private_file

    try:
        with private_file(path) as handle:
            yield handle
    except PrivateFileError as exc:
        raise ValueError(
            "authority key file must be a regular file and not a symlink, owned by the "
            "current effective user, with no group or other permissions and a single "
            f"link (chmod 600): {path}: {exc}"
        ) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(
                f"authority key file must be a regular file and not a symlink: {path}"
            ) from exc
        raise ValueError(f"authority key file is unreadable: {path}") from exc


def _load_authority_keys(path: str) -> _AuthorityKeys:
    """Load preprovisioned assignment and request-signing authority keys.

    The secure open protects only the final component from symlink traversal;
    operators must keep parent directories under trusted control.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError("an authority key file is required")
    try:
        with _open_authority_key_file(path) as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"authority key file is unreadable: {path}") from exc
    expected = {
        "assigner_id",
        "assigner_private_key_hex",
        "request_signing_private_key_hex",
    }
    if not isinstance(document, Mapping) or set(document) != expected:
        raise ValueError(
            "authority key file must contain only assigner_id, "
            "assigner_private_key_hex, and request_signing_private_key_hex"
        )
    from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

    assigner_id = document["assigner_id"]
    if not isinstance(assigner_id, str):
        raise ValueError("authority assigner_id must be a string")

    def _private_key(name: str) -> Ed25519PrivateKey:
        value = document[name]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or value != value.lower()
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(f"authority {name} must be 64 lowercase hex chars")
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))

    return _AuthorityKeys(
        assigner_id=normalize_voter_id(assigner_id),
        assigner_private_key=_private_key("assigner_private_key_hex"),
        request_signing_private_key=_private_key("request_signing_private_key_hex"),
    )


def _load_authorized_voter_keys(path: str) -> dict[str, _AuthorizedVoter]:
    """Load public-only voter trust grants and remote vote routes."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("an authorized voter key file is required")
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"authorized voter key file is unreadable: {path}") from exc
    if not isinstance(document, Mapping):
        raise ValueError("authorized voter key file must contain a JSON object")
    raw_grants = document.get("authorized_voters")
    if not isinstance(raw_grants, list) or not raw_grants:
        raise ValueError("authorized voter key file must contain a non-empty authorized_voters list")

    from constitutional_swarm.mesh.vote_envelope import (
        key_id_for_public_key,
        normalize_voter_id,
    )

    voter_keys: dict[str, _AuthorizedVoter] = {}
    key_owners: dict[str, str] = {}
    for index, grant in enumerate(raw_grants):
        if not isinstance(grant, Mapping):
            raise ValueError(f"authorized voter grant {index} must be a JSON object")
        if set(grant) != {"identity_id", "public_key_hex", "vote_host", "vote_port"}:
            raise ValueError(
                f"authorized voter grant {index} must contain only identity_id, "
                "public_key_hex, vote_host, and vote_port"
            )
        identity_value = grant["identity_id"]
        key_hex = grant["public_key_hex"]
        vote_host = grant["vote_host"]
        vote_port = grant["vote_port"]
        if not isinstance(identity_value, str):
            raise ValueError(f"authorized voter grant {index} identity_id must be a string")
        if (
            not isinstance(key_hex, str)
            or len(key_hex) != 64
            or key_hex != key_hex.lower()
            or any(character not in "0123456789abcdef" for character in key_hex)
        ):
            raise ValueError(
                f"authorized voter grant {index} public_key_hex must be 64 lowercase hex chars"
            )
        if not isinstance(vote_host, str) or not vote_host.strip():
            raise ValueError(f"authorized voter grant {index} vote_host must be non-empty")
        if isinstance(vote_port, bool) or not isinstance(vote_port, int) or not 1 <= vote_port <= 65535:
            raise ValueError(f"authorized voter grant {index} vote_port must be in 1..65535")
        identity = normalize_voter_id(identity_value)
        if identity in voter_keys:
            raise ValueError(f"duplicate authorized voter identity: {identity!r}")
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
        key_id = key_id_for_public_key(public_key)
        previous_owner = key_owners.get(key_id)
        if previous_owner is not None:
            raise ValueError(
                f"authorized voter key is shared by {previous_owner!r} and {identity!r}"
            )
        voter_keys[identity] = _AuthorizedVoter(
            public_key=public_key,
            route=(vote_host.strip(), vote_port),
        )
        key_owners[key_id] = identity
    if len(voter_keys) < 6:
        raise ValueError(
            "at least 6 authorized voter identities are required to collect 5 distinct "
            "votes while excluding the judgment producer"
        )
    return voter_keys


def _build_validator_runtime(
    constitution_path: str,
    voter_keys: Mapping[str, _AuthorizedVoter],
    *,
    peers: int = 5,
    quorum: int = 3,
    assigner_private_key: Ed25519PrivateKey | None = None,
    assigner_id: str = "testnet-validator-assigner",
    request_signing_private_key: Ed25519PrivateKey | None = None,
):
    """Build separated validator and frozen owner voter trust roots.

    The CLI always supplies preprovisioned authority keys. Ephemeral defaults
    exist only for local test helpers that call this constructor directly.
    """
    from constitutional_swarm.bittensor.protocol import ValidatorConfig
    from constitutional_swarm.bittensor.subnet_owner import SubnetOwner
    from constitutional_swarm.bittensor.validator import ConstitutionalValidator
    from constitutional_swarm.mesh.vote_envelope import VoteSignerRegistry

    config = ValidatorConfig(
        constitution_path=constitution_path,
        peers_per_validation=peers,
        quorum=quorum,
        use_manifold=True,
    )
    required_signers = config.peers_per_validation + 1
    if len(voter_keys) < required_signers:
        raise ValueError(
            f"validator runtime requires at least {required_signers} authorized voter "
            "identities so the judgment producer can be excluded"
        )
    assigner_private_key = assigner_private_key or Ed25519PrivateKey.generate()
    request_signing_private_key = (
        request_signing_private_key or Ed25519PrivateKey.generate()
    )
    assigner_public_key = assigner_private_key.public_key()
    validator_registry = VoteSignerRegistry()
    validator_registry.register(
        assigner_id,
        assigner_public_key,
        roles={"assigner"},
    )
    validator = ConstitutionalValidator(
        config,
        vote_registry=validator_registry,
        assigner_private_key=assigner_private_key,
        assigner_id=assigner_id,
        request_signing_private_key=request_signing_private_key,
    )
    owner_registry = VoteSignerRegistry()
    owner_registry.register(
        assigner_id,
        assigner_public_key,
        roles={"assigner"},
    )
    for identity, grant in voter_keys.items():
        if not isinstance(grant, _AuthorizedVoter) or not isinstance(
            grant.public_key, Ed25519PublicKey
        ):
            raise TypeError(
                "validator runtime accepts only public-key authorized voter grants"
            )
        validator.register_miner(
            identity,
            domain="governance",
            vote_public_key=grant.public_key,
        )
        owner_registry.register(
            identity,
            grant.public_key,
            roles={"voter", "validator"},
        )
    owner = SubnetOwner(constitution_path, vote_registry=owner_registry)
    return validator, owner


def _authorized_metagraph_axons(metagraph, authorized_identities: set[str] | frozenset[str]):
    """Resolve configured identities to metagraph axons or fail closed."""
    from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

    authorized = {normalize_voter_id(identity) for identity in authorized_identities}
    resolved: dict[str, tuple[str, object]] = {}
    for hotkey, axon in zip(metagraph.hotkeys, metagraph.axons, strict=True):
        identity = normalize_voter_id(hotkey)
        if identity in resolved:
            raise RuntimeError(f"metagraph contains duplicate canonical hotkey {identity!r}")
        if identity in authorized:
            resolved[identity] = (hotkey, axon)
    missing = sorted(authorized - resolved.keys())
    if missing:
        raise RuntimeError(
            "metagraph is missing configured authorized voter identities: "
            + ", ".join(missing)
        )
    return [resolved[identity] for identity in sorted(resolved)]


def _weight_values_for_metagraph(
    weights: Mapping[str, float],
    hotkeys: list[str],
) -> list[float]:
    """Map canonical validator weights back onto raw metagraph hotkeys."""
    from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

    return [weights.get(normalize_voter_id(hotkey), 0.0) for hotkey in hotkeys]


async def _record_authenticated_response(
    response,
    *,
    expected_hotkey: str,
    expected_dendrite_hotkey: str,
    authorized_identities: set[str] | frozenset[str],
    validator,
    owner,
    case,
    peer_routes: Mapping[str, tuple[str, int]],
    vote_client=None,
):
    """Authenticate a response producer before validation or precedent admission.

    The allow-list check runs first; ``synapse_adapter.authenticate_response``
    then binds the response to the selected axon, the local dendrite and the
    dispatched request (axon signature plus request-bound body signature).
    """
    from constitutional_swarm.bittensor import synapse_adapter
    from constitutional_swarm.mesh.vote_envelope import normalize_voter_id

    if not isinstance(expected_hotkey, str) or not expected_hotkey.strip():
        raise ValueError("request target is missing an authenticated hotkey")
    expected_identity = normalize_voter_id(expected_hotkey)
    authorized = {normalize_voter_id(identity) for identity in authorized_identities}
    if expected_identity not in authorized:
        raise ValueError(
            f"authenticated response identity {expected_identity!r} is not authorized"
        )
    judgment = synapse_adapter.authenticate_response(
        response,
        dispatched=synapse_adapter.deliberation_to_bt(case.synapse),
        expected_axon_hotkey=expected_hotkey,
        expected_dendrite_hotkey=expected_dendrite_hotkey,
    )
    validation = await validator.validate_remote(
        judgment,
        peer_routes=dict(peer_routes),
        client=vote_client,
    )
    return owner.record_result(case, judgment, validation)


def _configure_braintrust(detail: str) -> object | None:
    """Enable Braintrust tracing when the runtime API key is present."""
    api_key = os.environ.get("BRAINTRUST_API_KEY", "").strip()
    if not api_key:
        return None

    try:
        import braintrust
    except ImportError:
        print("WARNING: Braintrust SDK unavailable; continuing without tracing.", file=sys.stderr)
        return None

    braintrust.init_logger(project=BRAINTRUST_PROJECT, api_key=api_key, force_login=True)
    if detail == "deep":
        braintrust.auto_instrument()
    return braintrust


@contextmanager
def _braintrust_detail_scope(detail: str):
    """Control third-party Braintrust instrumentation noise for the command body."""
    if detail == "deep":
        yield
        return

    api_key = os.environ.pop("BRAINTRUST_API_KEY", None)
    try:
        yield
    finally:
        if api_key is not None:
            os.environ["BRAINTRUST_API_KEY"] = api_key


def _run_with_braintrust_trace(
    braintrust: object | None,
    handler: Callable[[argparse.Namespace], None],
    args: argparse.Namespace,
) -> None:
    if braintrust is None:
        handler(args)
        return

    args._braintrust = braintrust
    command = args.command or "local"

    @braintrust.traced(
        name=f"testnet_deploy.{command}",
        type="task",
        metadata={
            "command": command,
            "braintrust_project": BRAINTRUST_PROJECT,
            "braintrust_detail": args.braintrust_detail,
        },
        notrace_io=True,
    )
    def _run_testnet_command() -> None:
        with _braintrust_detail_scope(args.braintrust_detail):
            handler(args)

    _run_testnet_command()


def _braintrust_span(
    braintrust: object | None,
    name: str,
    *,
    metadata: dict[str, object] | None = None,
    metrics: dict[str, float | int | bool] | None = None,
) -> object:
    if braintrust is None:
        return nullcontext(None)

    event: dict[str, object] = {}
    if metadata is not None:
        event["metadata"] = metadata
    if metrics is not None:
        event["metrics"] = metrics
    return braintrust.start_span(name=name, type="task", **event)


def _braintrust_log(
    braintrust: object | None,
    *,
    metadata: dict[str, object] | None = None,
    metrics: dict[str, float | int | bool] | None = None,
    output: dict[str, object] | None = None,
) -> None:
    if braintrust is None:
        return

    event: dict[str, object] = {}
    if metadata is not None:
        event["metadata"] = metadata
    if metrics is not None:
        event["metrics"] = metrics
    if output is not None:
        event["output"] = output
    if event:
        braintrust.current_span().log(**event)


def _check_bittensor() -> None:
    """Verify bittensor package is installed."""
    try:
        import bittensor  # noqa: F401
    except ImportError:
        print("ERROR: bittensor package not installed.")
        print('  pip install "bittensor>=7.0,<11"')
        sys.exit(1)


def cmd_local(args: argparse.Namespace) -> None:
    """Run a fully local no-network testnet simulation."""
    braintrust = getattr(args, "_braintrust", None)
    if not os.path.exists(args.constitution):
        print(f"ERROR: Constitution file not found: {args.constitution}")
        print("  Create a constitution.yaml or use the sample in examples/constitution.yaml")
        sys.exit(1)

    from acgs_lite import Constitution
    from constitutional_swarm.mesh import ConstitutionalMesh

    agents = tuple(f"local-agent-{idx}" for idx in range(5))
    cases = tuple(
        (
            f"local-case-{idx}",
            "Approve this local governance case with safety, transparency, "
            "proportionality, and pluralism documented.",
        )
        for idx in range(4)
    )
    with _braintrust_span(
        braintrust,
        "load_constitution",
        metadata={"mode": "local", "constitution_path": args.constitution},
    ):
        constitution = Constitution.from_yaml(args.constitution)
    with _braintrust_span(
        braintrust,
        "build_constitutional_mesh",
        metadata={
            "mode": "local",
            "peers_per_validation": 3,
            "quorum": 2,
            "use_manifold": True,
        },
    ):
        mesh = ConstitutionalMesh(
            constitution,
            peers_per_validation=3,
            quorum=2,
            seed=0,
            use_manifold=True,
            evidence_mode="single_operator_dev",
        )
        _braintrust_log(
            braintrust,
            metadata={"constitutional_hash": mesh.constitutional_hash},
        )

    with _braintrust_span(
        braintrust,
        "register_local_agents",
        metadata={"mode": "local", "agent_domain": "general"},
        metrics={"agent_count": len(agents)},
    ):
        for agent_id in agents:
            mesh.register_local_signer(agent_id, domain="general")

    print("Running local Constitutional Swarm testnet simulation...")
    print(
        "  Mode: local single-operator development simulation "
        "(evidence is not eligible for precedent admission)"
    )
    print(f"  Constitution: {args.constitution}")
    print(f"  Constitution hash: {mesh.constitutional_hash}")
    print(f"  Agents registered: {len(agents)}")

    accepted = 0
    rejected = 0
    for idx, (case_id, content) in enumerate(cases):
        producer_id = agents[idx]
        with _braintrust_span(
            braintrust,
            "validate_governance_case",
            metadata={
                "mode": "local",
                "case_id": case_id,
                "producer_id": producer_id,
                "artifact_id": f"{case_id}-artifact",
                "constitutional_hash": mesh.constitutional_hash,
            },
        ):
            result = mesh.full_validation(
                producer_id=producer_id,
                content=content,
                artifact_id=f"{case_id}-artifact",
            )
            _braintrust_log(
                braintrust,
                metadata={
                    "case_id": case_id,
                    "accepted": result.accepted,
                    "quorum_met": result.quorum_met,
                },
                metrics={
                    "votes_for": result.votes_for,
                    "votes_against": result.votes_against,
                },
                output={
                    "accepted": result.accepted,
                    "votes_for": result.votes_for,
                    "votes_against": result.votes_against,
                    "quorum_met": result.quorum_met,
                },
            )
        if result.accepted:
            accepted += 1
        else:
            rejected += 1
        print(
            f"  {case_id}: accepted={result.accepted} "
            f"votes_for={result.votes_for} votes_against={result.votes_against} "
            f"quorum_met={result.quorum_met}"
        )

    summary = mesh.summary()
    manifold = mesh.manifold_summary() or {}
    final_spectral_bound = float(manifold.get("spectral_bound", 0.0))
    stable = bool(manifold.get("is_stable", False))
    with _braintrust_span(
        braintrust,
        "summarize_local_testnet_run",
        metadata={
            "mode": "local",
            "constitutional_hash": mesh.constitutional_hash,
            "stable": stable,
        },
        metrics={
            "agents_registered": summary["agents"],
            "validations": summary["total_validations"],
            "votes_cast": summary["total_votes"],
            "accepted": accepted,
            "rejected": rejected,
            "final_spectral_bound": final_spectral_bound,
        },
    ):
        pass
    print(
        "MEASUREMENT "
        f"agents_registered={summary['agents']} "
        f"validations={summary['total_validations']} "
        f"votes_cast={summary['total_votes']} "
        f"accepted={accepted} "
        f"rejected={rejected} "
        f"final_spectral_bound={final_spectral_bound:.5f} "
        f"stable={stable}"
    )


def cmd_register(args: argparse.Namespace) -> None:
    """Register a new subnet on testnet."""
    _check_bittensor()
    import bittensor as bt

    wallet = bt.wallet(name=args.wallet_name, hotkey=args.wallet_hotkey)

    try:
        subtensor = bt.subtensor(network="test")
    except Exception as exc:
        print(f"ERROR: Could not connect to Bittensor testnet: {exc}")
        print("  Check: network connectivity, testnet RPC availability.")
        sys.exit(1)

    print(f"Registering subnet on testnet with wallet {wallet.name}...")
    print(f"  Wallet coldkey: {wallet.coldkeypub.ss58_address}")
    print("  Network: test")

    try:
        result = subtensor.register_subnet(wallet=wallet)
    except Exception as exc:
        print(f"ERROR: Subnet registration failed: {exc}")
        print("  Check: TAO balance (need ~1 TAO for registration), wallet configuration.")
        print("  Testnet faucet: https://test.taostats.io/faucet")
        sys.exit(1)

    if not result:
        print("ERROR: Subnet registration returned failure.")
        sys.exit(1)

    if isinstance(result, int):
        print(f"  Subnet registered. netuid={result}")
        print(f"  Use --netuid {result} with the miner/validator commands.")
    else:
        print("  Subnet registered successfully.")
        print("  Check the Bittensor dashboard for your assigned netuid,")
        print("  then use --netuid <id> with the miner/validator commands.")


def _trusted_validator_hotkeys(raw: object) -> set[str]:
    """Parse the comma-separated trusted validator hotkeys or fail closed."""
    if not isinstance(raw, str):
        raw = ""
    hotkeys = {item.strip() for item in raw.split(",") if item.strip()}
    if not hotkeys:
        raise ValueError(
            "at least one trusted validator hotkey is required "
            "(--trusted-validators <ss58>[,<ss58>...]); without one the miner "
            "would reject every request"
        )
    return hotkeys


def cmd_miner(args: argparse.Namespace) -> None:
    """Start a constitutional governance miner on testnet."""
    trusted_validators = _trusted_validator_hotkeys(getattr(args, "trusted_validators", ""))
    _check_bittensor()
    import asyncio
    import os

    import bittensor as bt
    from constitutional_swarm.bittensor.axon_server import MinerAxonServer
    from constitutional_swarm.bittensor.miner import ConstitutionalMiner
    from constitutional_swarm.bittensor.protocol import MinerConfig

    if not os.path.exists(args.constitution):
        print(f"ERROR: Constitution file not found: {args.constitution}")
        print("  Create a constitution.yaml or use the sample in examples/constitution.yaml")
        sys.exit(1)

    wallet = bt.wallet(name=args.wallet_name, hotkey=args.wallet_hotkey)

    try:
        subtensor = bt.subtensor(network="test")
    except Exception as exc:
        print(f"ERROR: Could not connect to Bittensor testnet: {exc}")
        sys.exit(1)

    print(f"Starting Constitutional Miner on testnet (netuid={args.netuid})...")
    print(f"  Constitution: {args.constitution}")
    print(f"  Wallet: {wallet.name} / {wallet.hotkey_str}")

    async def _deliberation_handler(task: str, context: str, meta: dict) -> tuple[str, str]:
        """Default AI-assisted deliberation handler.

        In production, replace with human-in-the-loop or
        specialized LLM pipeline.
        """
        return (
            f"Governance judgment for domain {context}: "
            "this case requires balancing competing constitutional principles. "
            "After analysis, the recommended approach prioritizes safety "
            "while maintaining transparency.",
            "Balanced analysis considering all stakeholder perspectives "
            "and constitutional requirements.",
        )

    config = MinerConfig(
        constitution_path=args.constitution,
        agent_id=wallet.hotkey.ss58_address,
        capabilities=tuple(args.capabilities.split(","))
        if args.capabilities
        else ("governance-judgment",),
        domains=tuple(args.domains.split(",")) if args.domains else ("general",),
    )

    miner = ConstitutionalMiner(
        config=config,
        deliberation_handler=_deliberation_handler,
    )
    server = MinerAxonServer(
        miner,
        trusted_validator_hotkeys=trusted_validators,
        response_signing_key=wallet.hotkey,
    )

    print(f"  Constitution hash: {miner.constitution_hash}")
    print(f"  Agent ID: {config.agent_id}")
    print(f"  Capabilities: {config.capabilities}")
    print(f"  Domains: {config.domains}")
    print(f"  Trusted validators: {len(trusted_validators)}")

    # Register on the metagraph
    subtensor.register(wallet=wallet, netuid=args.netuid)
    print(f"  Registered on metagraph (netuid={args.netuid})")

    # Set up axon with adapter layer handlers
    axon = bt.axon(wallet=wallet, port=args.port)
    # attach_to composes bittensor's default_verify (dendrite signature, nonce,
    # body-hash binding) in front of the local checks; never attach directly.
    server.attach_to(axon)
    axon.serve(netuid=args.netuid, subtensor=subtensor)
    axon.start()

    print(f"  Axon serving on port {args.port}")
    print("  Miner is running. Press Ctrl+C to stop.")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        bt.logging.info("Miner running...")
        loop.run_forever()
    except KeyboardInterrupt:
        print("\nShutting down miner...")
        axon.stop()
        print(f"  Final stats: {miner.stats}")
    finally:
        loop.close()


def cmd_validator(args: argparse.Namespace) -> None:
    """Start a constitutional governance validator on testnet."""
    voter_keys = _load_authorized_voter_keys(getattr(args, "authorized_voters", ""))
    authority_keys = _load_authority_keys(getattr(args, "authority_keys", ""))
    if not os.path.exists(args.constitution):
        raise ValueError(f"constitution file not found: {args.constitution}")
    validator, owner = _build_validator_runtime(
        args.constitution,
        voter_keys,
        peers=args.peers,
        quorum=args.quorum,
        assigner_private_key=authority_keys.assigner_private_key,
        assigner_id=authority_keys.assigner_id,
        request_signing_private_key=authority_keys.request_signing_private_key,
    )
    _check_bittensor()
    import asyncio
    import time

    import bittensor as bt
    from constitutional_swarm.bittensor.synapse_adapter import (
        GovernanceDeliberation,
        deliberation_to_bt,
    )

    wallet = bt.wallet(name=args.wallet_name, hotkey=args.wallet_hotkey)

    try:
        subtensor = bt.subtensor(network="test")
    except Exception as exc:
        print(f"ERROR: Could not connect to Bittensor testnet: {exc}")
        sys.exit(1)

    print(f"Starting Constitutional Validator on testnet (netuid={args.netuid})...")
    print(f"  Constitution: {args.constitution}")

    print(f"  Constitution hash: {validator.constitution_hash}")

    # Register on the metagraph
    subtensor.register(wallet=wallet, netuid=args.netuid)
    metagraph = subtensor.metagraph(netuid=args.netuid)
    authorized_identities = frozenset(voter_keys)
    peer_routes = {
        identity: grant.route for identity, grant in voter_keys.items()
    }
    authorized_targets = _authorized_metagraph_axons(metagraph, authorized_identities)

    print(f"  Registered. Metagraph has {metagraph.n} neurons.")
    print(f"  Authorized voter hotkeys present: {len(authorized_targets)}")
    print("  Validator is running. Press Ctrl+C to stop.")

    dendrite = bt.Dendrite(wallet=wallet)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        while True:
            # Refresh metagraph with retry/backoff
            for _attempt in range(3):
                try:
                    metagraph.sync()
                    break
                except Exception as _exc:
                    if _attempt == 2:
                        print(f"  WARNING: metagraph.sync() failed after 3 attempts: {_exc}")
                    time.sleep(2**_attempt)

            # Query miners with a governance case via adapter layer
            if metagraph.n > 0:
                authorized_targets = _authorized_metagraph_axons(
                    metagraph,
                    authorized_identities,
                )
                case = owner.package_case(
                    "Periodic governance validation",
                    "general",
                )
                bt_syn = deliberation_to_bt(case.synapse)

                try:
                    responses = loop.run_until_complete(
                        dendrite(
                            axons=[axon for _, axon in authorized_targets],
                            synapse=bt_syn,
                            timeout=args.epoch_seconds * 0.8,
                        )
                    )
                except Exception as _exc:
                    print(f"  WARNING: dendrite query failed: {_exc}")
                    responses = []

                if len(responses) != len(authorized_targets):
                    # Positional response-to-target binding is unreliable; fail closed.
                    print(
                        "  WARNING: dendrite returned "
                        f"{len(responses)} responses for {len(authorized_targets)} "
                        "authorized targets; discarding this round"
                    )
                    responses = []
                    targets = []
                else:
                    targets = list(authorized_targets)
                for (expected_hotkey, _axon), resp in zip(targets, responses, strict=True):
                    if not isinstance(resp, GovernanceDeliberation):
                        continue
                    if not resp.has_response or resp.error_message is not None:
                        continue
                    try:
                        loop.run_until_complete(
                            _record_authenticated_response(
                                resp,
                                expected_hotkey=expected_hotkey,
                                expected_dendrite_hotkey=wallet.hotkey.ss58_address,
                                authorized_identities=authorized_identities,
                                validator=validator,
                                owner=owner,
                                case=case,
                                peer_routes=peer_routes,
                            )
                        )
                    except (ValueError, KeyError) as exc:
                        print(
                            f"  WARNING: rejected response for {expected_hotkey!r}: {exc}",
                            file=sys.stderr,
                        )
                        continue

            # Compute and set weights every epoch
            weights = validator.compute_emission_weights()
            if weights:
                uids = list(range(metagraph.n))
                weight_values = _weight_values_for_metagraph(
                    weights,
                    [metagraph.hotkeys[uid] for uid in uids],
                )
                try:
                    subtensor.set_weights(
                        wallet=wallet,
                        netuid=args.netuid,
                        uids=uids,
                        weights=weight_values,
                    )
                    print(f"  Set weights for {len(weights)} miners")
                except Exception as _exc:
                    print(f"  WARNING: set_weights failed: {_exc}")

            print(f"  Stats: {validator.stats}")
            time.sleep(args.epoch_seconds)

    except KeyboardInterrupt:
        print("\nShutting down validator...")
        print(f"  Final stats: {validator.stats}")
    finally:
        loop.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Constitutional Governance Subnet - Testnet Deployment",
    )
    parser.add_argument(
        "--constitution",
        help="Path to constitution YAML for the default local simulation",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run the default no-network local simulation when no subcommand is given",
    )
    parser.add_argument(
        "--braintrust-detail",
        choices=("summary", "deep"),
        default="summary",
        help=(
            "Braintrust trace detail. 'summary' records high-level governance spans; "
            "'deep' also enables SDK auto-instrumentation for noisy internal debugging."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    # Register
    reg = subparsers.add_parser("register", help="Register subnet on testnet")
    reg.add_argument("--wallet-name", required=True)
    reg.add_argument("--wallet-hotkey", required=True)

    # Miner
    miner = subparsers.add_parser("miner", help="Start miner")
    miner.add_argument("--wallet-name", required=True)
    miner.add_argument("--wallet-hotkey", required=True)
    miner.add_argument("--constitution", required=True, help="Path to constitution YAML")
    miner.add_argument("--netuid", type=int, required=True)
    miner.add_argument("--port", type=int, default=8091)
    miner.add_argument("--capabilities", default="governance-judgment")
    miner.add_argument("--domains", default="general")
    miner.add_argument(
        "--trusted-validators",
        required=True,
        help=(
            "Comma-separated SS58 hotkeys of validators allowed to query this miner; "
            "requests from any other (or unauthenticated) caller are rejected"
        ),
    )

    # Validator
    val = subparsers.add_parser("validator", help="Start validator")
    val.add_argument("--wallet-name", required=True)
    val.add_argument("--wallet-hotkey", required=True)
    val.add_argument("--constitution", required=True, help="Path to constitution YAML")
    val.add_argument(
        "--authorized-voters",
        required=True,
        help=(
            "JSON public voter grants containing identity_id, public_key_hex, vote_host, "
            "and vote_port; each identity_id must equal the remote voter's authenticated "
            "Bittensor axon hotkey, and at least --peers + 1 identities are required"
        ),
    )
    val.add_argument(
        "--authority-keys",
        required=True,
        help=(
            "JSON secret key file containing assigner_id, assigner_private_key_hex, "
            "and request_signing_private_key_hex; must be a single-link regular file "
            "owned by the current user with mode 0600 (chmod 600 <file>); provision "
            "matching public keys to remote voters before startup"
        ),
    )
    val.add_argument("--netuid", type=int, required=True)
    val.add_argument("--peers", type=int, default=5)
    val.add_argument("--quorum", type=int, default=3)
    val.add_argument("--epoch-seconds", type=int, default=60)

    args = parser.parse_args()
    braintrust = _configure_braintrust(args.braintrust_detail)

    if args.command is None:
        if args.constitution is None:
            parser.print_help(sys.stderr)
            sys.exit(2)
        _run_with_braintrust_trace(braintrust, cmd_local, args)
    elif args.command == "register":
        _run_with_braintrust_trace(braintrust, cmd_register, args)
    elif args.command == "miner":
        _run_with_braintrust_trace(braintrust, cmd_miner, args)
    elif args.command == "validator":
        _run_with_braintrust_trace(braintrust, cmd_validator, args)


if __name__ == "__main__":
    main()
