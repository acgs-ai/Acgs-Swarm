"""The sole typed entry point for APCC authority-producing operations.

The service deliberately contains no persistence policy.  It validates that the
ephemeral authority keys match the public configuration and delegates each state
transition exactly once. Request-dependent validation remains inside the store's
guarded transaction so replay and equivocation precedence cannot be bypassed.
"""

from __future__ import annotations

from .ports import (
    APCCAuthorityConfig,
    AssembleEvidenceRequest,
    AssembleEvidenceResult,
    AtomicCommitRequest,
    AuthorityExecutionStore,
    AuthorityRuntime,
    CommitResult,
    ProposeCommitRequest,
    ProposeCommitResult,
    StageResultRequest,
    StageResultResult,
    validate_runtime_signers,
)


class APCCCommitService:
    """Validate authority identity and delegate through execution capability."""

    def __init__(
        self,
        *,
        store: AuthorityExecutionStore,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
    ) -> None:
        if store.authority_store_id != config.authority_store_id:
            raise ValueError("authority store ID does not match APCC configuration")
        # Concrete stores expose the configuration they attested at open; a
        # service configured differently must not front them.  Structural
        # capability doubles that carry no configuration skip this check.
        store_config = getattr(store, "authority_config", None)
        if store_config is not None and store_config != config:
            raise ValueError("APCC configuration does not match the store")
        validate_runtime_signers(config, runtime)
        self._store = store
        self._config = config
        self._runtime = runtime

    def stage_result(self, request: StageResultRequest) -> StageResultResult:
        return self._store.stage_result(request)

    def assemble_evidence(
        self, request: AssembleEvidenceRequest
    ) -> AssembleEvidenceResult:
        return self._store.assemble_evidence(request)

    def propose_commit(self, request: ProposeCommitRequest) -> ProposeCommitResult:
        return self._store.propose_commit(request)

    def commit(self, request: AtomicCommitRequest) -> CommitResult:
        return self._store.atomic_commit(request)
