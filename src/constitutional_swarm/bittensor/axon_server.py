"""Miner axon server wrapping ConstitutionalMiner for bittensor protocol.

Provides handlers for bittensor's axon:
  - forward: validates the request body, processes the case, signs the reply
  - blacklist: rejects untrusted validator hotkeys
  - verify / verify_transport: request field checks and transport authentication
  - priority: ranks authenticated requests by impact score

Usage (local testing):
    server = MinerAxonServer(miner, allow_unsigned_responses=True)
    result = await server.forward(governance_synapse)

Usage (real bittensor) -- always attach through ``attach_to`` so bittensor's
``default_verify`` (dendrite signature, nonce replay window, body-hash binding)
runs before any local check:
    axon = bt.Axon(wallet=wallet)
    server = MinerAxonServer(
        miner,
        trusted_validator_hotkeys={validator_hotkey},
        response_signing_key=wallet.hotkey,
    )
    server.attach_to(axon)
"""

from __future__ import annotations

import inspect
import time
from typing import Any, Tuple

from constitutional_swarm.bittensor.miner import (
    ConstitutionalMiner,
    ConstitutionMismatchError,
    DNAPreCheckFailedError,
    validate_deadline_seconds,
)
from constitutional_swarm.bittensor.synapse_adapter import (
    GovernanceDeliberation,
    bt_to_deliberation,
    judgment_to_bt,
    sign_judgment_response,
)
from constitutional_swarm.mesh.vote_envelope import normalize_voter_id


class MinerAxonServer:
    """Wraps a ConstitutionalMiner into bittensor axon-compatible handlers.

    The server converts between the bt.Synapse wire format
    (GovernanceDeliberation) and the internal frozen dataclass synapses,
    delegating actual processing to the ConstitutionalMiner.

    Responses are signed with ``response_signing_key``, whose SS58 address
    must be the miner's ``agent_id``. Unsigned responses require the explicit
    ``allow_unsigned_responses=True`` local-development opt-in.
    """

    def __init__(
        self,
        miner: ConstitutionalMiner,
        *,
        trusted_validator_hotkeys: set[str] | None = None,
        allow_unauthenticated: bool = False,
        response_signing_key: Any | None = None,
        allow_unsigned_responses: bool = False,
    ) -> None:
        if response_signing_key is None:
            if allow_unsigned_responses is not True:
                raise ValueError(
                    "response_signing_key is required; pass "
                    "allow_unsigned_responses=True only for local development"
                )
        else:
            signer = getattr(response_signing_key, "ss58_address", None)
            if not isinstance(signer, str) or not signer.strip():
                raise ValueError("response signing key must expose an SS58 address")
            agent_id = getattr(miner, "agent_id", None)
            if (
                not isinstance(agent_id, str)
                or not agent_id.strip()
                or (normalize_voter_id(agent_id) != normalize_voter_id(signer))
            ):
                raise ValueError("response signing key does not match the miner agent_id")
        self._miner = miner
        self._trusted_validator_hotkeys = set(trusted_validator_hotkeys or set())
        self._allow_unauthenticated = allow_unauthenticated
        self._response_signing_key = response_signing_key

    @property
    def miner(self) -> ConstitutionalMiner:
        return self._miner

    async def forward(
        self,
        synapse: GovernanceDeliberation,
    ) -> GovernanceDeliberation:
        """Process a governance deliberation request.

        Converts the bt synapse to an internal DeliberationSynapse,
        runs it through the ConstitutionalMiner, and fills response
        fields on the bt synapse.

        On error (constitution mismatch, DNA failure, timeout), the
        error_message field is set instead of raising — following
        bittensor's pattern where forward_fn should not raise.
        """
        try:
            self.verify(synapse)
        except ValueError as exc:
            synapse.error_message = f"Invalid request: {exc}"
            return synapse
        try:
            delib = bt_to_deliberation(synapse)
            judgment = await self._miner.process(delib)
            judgment_to_bt(judgment, synapse)
            synapse.response_timestamp = time.time()
            if self._response_signing_key is not None:
                sign_judgment_response(synapse, self._response_signing_key)
        except ConstitutionMismatchError as exc:
            synapse.error_message = f"Constitution mismatch: {exc}"
        except DNAPreCheckFailedError as exc:
            synapse.error_message = f"DNA pre-check failed: {exc}"
        except TimeoutError:
            synapse.error_message = "Deliberation timed out"
        except Exception as exc:
            synapse.error_message = f"Processing error: {type(exc).__name__}"
        return synapse

    def blacklist(self, synapse: GovernanceDeliberation) -> bool:
        """Decide whether to reject a request outright.

        Returns True to blacklist (reject), False to allow.
        Fail-closed unless the server is explicitly configured for local
        unauthenticated operation or the caller hotkey is in the trusted
        validator set.
        """
        if self._allow_unauthenticated:
            return False
        caller = self._caller_hotkey(synapse)
        if not caller:
            return True
        return caller not in self._trusted_validator_hotkeys

    def verify(self, synapse: GovernanceDeliberation) -> None:
        """Validate required request-body fields.

        Raises ValueError if critical fields are missing or the deadline is not
        in ``(0, MAX_DELIBERATION_SECONDS]``. ``forward`` runs this on the full
        body; bittensor's middleware verify hook only sees headers, so it is
        not used there (see ``verify_transport``).
        """
        if not synapse.task_id:
            raise ValueError("task_id is required")
        if not synapse.constitution_hash:
            raise ValueError("constitution_hash is required")
        if not synapse.task_dag_json:
            raise ValueError("task_dag_json is required")
        validate_deadline_seconds(synapse.deadline_seconds)

    @staticmethod
    async def verify_transport(synapse: Any, default_verify: Any) -> None:
        """Authenticate the transport request, then defer to bittensor.

        bittensor's ``default_verify`` skips the signature check when the
        dendrite signature is empty, so a present hotkey and signature are
        required first. ``default_verify`` then checks the signature over
        nonce, hotkeys, UUID and the header body hash, and the nonce replay
        window. The axon route separately recomputes the body hash from the
        body over ``required_hash_fields``.
        """
        dendrite = getattr(synapse, "dendrite", None)
        hotkey = getattr(dendrite, "hotkey", None)
        signature = getattr(dendrite, "signature", None)
        if not isinstance(hotkey, str) or not hotkey.strip():
            raise ValueError("request is missing the dendrite hotkey")
        if not isinstance(signature, str) or not signature:
            raise ValueError("request dendrite signature is missing")
        if not getattr(synapse, "computed_body_hash", None):
            raise ValueError("request is missing its signed body hash")
        result = default_verify(synapse)
        if inspect.isawaitable(result):
            await result

    def attach_to(self, axon: Any) -> Any:
        """Attach this server to a bittensor axon with transport auth composed.

        ``verify_fn`` replaces bittensor's ``default_verify``, so the attached
        verifier runs ``verify_transport`` (which calls the axon's own
        ``default_verify``) and can never skip it. Handler signatures carry the
        concrete synapse class because bittensor compares them at attach time.
        """
        default_verify = getattr(axon, "default_verify", None)
        if not callable(default_verify):
            raise ValueError("axon does not expose default_verify; refusing to attach")

        async def forward_fn(synapse: GovernanceDeliberation) -> GovernanceDeliberation:
            return await self.forward(synapse)

        def blacklist_fn(synapse: GovernanceDeliberation) -> Tuple[bool, str]:
            if self.blacklist(synapse):
                return True, "caller hotkey is not a trusted validator"
            return False, "trusted validator"

        async def verify_fn(synapse: GovernanceDeliberation) -> None:
            await self.verify_transport(synapse, default_verify)

        def priority_fn(synapse: GovernanceDeliberation) -> float:
            return self.priority(synapse)

        # This module uses postponed (string) annotations, but bittensor
        # compares handler signatures against the concrete synapse class, so
        # bind the resolved annotation objects explicitly.
        forward_fn.__annotations__ = {
            "synapse": GovernanceDeliberation,
            "return": GovernanceDeliberation,
        }
        blacklist_fn.__annotations__ = {
            "synapse": GovernanceDeliberation,
            "return": Tuple[bool, str],
        }
        verify_fn.__annotations__ = {"synapse": GovernanceDeliberation, "return": None}
        priority_fn.__annotations__ = {"synapse": GovernanceDeliberation, "return": float}
        axon.attach(
            forward_fn=forward_fn,
            blacklist_fn=blacklist_fn,
            verify_fn=verify_fn,
            priority_fn=priority_fn,
        )
        return axon

    def priority(self, synapse: GovernanceDeliberation) -> float:
        """Assign processing priority based on impact score.

        Higher impact cases get processed first when the miner
        has a backlog of authenticated requests.  Untrusted callers get zero
        priority so an attacker cannot self-rank by setting impact_score.
        """
        if self.blacklist(synapse):
            return 0.0
        return max(float(synapse.impact_score), 0.0)

    @staticmethod
    def _caller_hotkey(synapse: Any) -> str:
        """Extract the authenticated Bittensor caller hotkey.

        Only ``dendrite.hotkey`` is populated by the transport authentication
        path. Request-body and axon fields are attacker-controlled and are not
        accepted as caller identity.
        """
        dendrite = getattr(synapse, "dendrite", None)
        hotkey = getattr(dendrite, "hotkey", None)
        if not isinstance(hotkey, str):
            return ""
        return hotkey.strip()
