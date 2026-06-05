"""Miner axon server wrapping ConstitutionalMiner for bittensor protocol.

Provides handler functions compatible with bittensor's axon.attach() API:
  - forward_fn: async handler that processes governance cases
  - blacklist_fn: rejects unauthenticated / untrusted validator requests
  - verify_fn: validates required fields before processing
  - priority_fn: ranks requests by impact score

Usage (local testing):
    server = MinerAxonServer(miner)
    result = await server.forward(governance_synapse)

Usage (real bittensor):
    axon = bt.Axon(wallet=wallet)
    server = MinerAxonServer(miner)
    axon.attach(
        forward_fn=server.forward,
        blacklist_fn=server.blacklist,
        verify_fn=server.verify,
        priority_fn=server.priority,
    )
"""

from __future__ import annotations

import time
from typing import Any

from constitutional_swarm.bittensor.miner import (
    ConstitutionalMiner,
    ConstitutionMismatchError,
    DNAPreCheckFailedError,
)
from constitutional_swarm.bittensor.synapse_adapter import (
    GovernanceDeliberation,
    bt_to_deliberation,
    judgment_to_bt,
)


class MinerAxonServer:
    """Wraps a ConstitutionalMiner into bittensor axon-compatible handlers.

    The server converts between the bt.Synapse wire format
    (GovernanceDeliberation) and the internal frozen dataclass synapses,
    delegating actual processing to the ConstitutionalMiner.
    """

    def __init__(
        self,
        miner: ConstitutionalMiner,
        *,
        trusted_validator_hotkeys: set[str] | None = None,
        allow_unauthenticated: bool = False,
    ) -> None:
        self._miner = miner
        self._trusted_validator_hotkeys = set(trusted_validator_hotkeys or set())
        self._allow_unauthenticated = allow_unauthenticated

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
            delib = bt_to_deliberation(synapse)
            judgment = await self._miner.process(delib)
            judgment_to_bt(judgment, synapse)
            synapse.response_timestamp = time.time()
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
        """Validate required fields before processing.

        Raises ValueError if critical fields are missing.
        Called by bittensor's axon before forward_fn.
        """
        if not synapse.task_id:
            raise ValueError("task_id is required")
        if not synapse.constitution_hash:
            raise ValueError("constitution_hash is required")
        if not synapse.task_dag_json:
            raise ValueError("task_dag_json is required")

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
        """Best-effort Bittensor caller hotkey extraction.

        Real bt.Synapse objects carry caller identity under ``dendrite``; local
        tests may provide a flat validator_hotkey/request_hotkey field.
        """

        for container_name in ("dendrite", "axon"):
            container = getattr(synapse, container_name, None)
            hotkey = getattr(container, "hotkey", "")
            if hotkey:
                return str(hotkey)
        for field_name in ("validator_hotkey", "request_hotkey", "hotkey"):
            hotkey = getattr(synapse, field_name, "")
            if hotkey:
                return str(hotkey)
        return ""
