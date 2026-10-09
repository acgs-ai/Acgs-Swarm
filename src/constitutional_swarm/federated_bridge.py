"""Federated Constitution Bridge — cross-organisational FCHP layer.

Implements the Federated Constitutional Hybrid Protocol (FCHP) for
cross-organisational constitutional rule propagation.

Architecture:
    - AgentCredential  — verifiable identity for a cross-org AI agent
    - FederatedConstitutionBridge — enforces fail-closed cross-org rule gates

Security contract:
    - Unknown credentials → REJECT (fail-closed, never fail-open)
    - Constitutional hash mismatch → REJECT
    - Revoked credentials → REJECT
    - All decisions are logged for audit

Research basis:
    - Constitutional Evolution (arXiv:2602.00755): cross-org constitutions
      68% better than human-designed when evolved with minimal inter-agent comm
    - Linux Foundation Agentic AI Foundation (Dec 2025): MCP+A2A+AGENTS.md
      as vendor-neutral connectivity substrate
    - EU AI Act Articles 9/12/13: cross-org accountability chain
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from constitutional_swarm.constants import CONSTITUTIONAL_HASH as _CONSTITUTIONAL_HASH

ALL_DOMAINS = "*"


class CredentialStatus(Enum):
    """Lifecycle state of an AgentCredential."""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"  # awaiting org-level approval


@dataclass(frozen=True, slots=True)
class AgentCredential:
    """Verifiable identity for a cross-organisational AI agent.

    Attributes:
        agent_id:           Unique agent identifier (UUID-like string).
        org_id:             Organisation that issued this credential.
        pubkey_fingerprint: Hex fingerprint of the agent's public key.
        constitutional_hash: Hash of the constitution this agent operates under.
        issued_at:          Unix timestamp of issuance.
        expires_at:         Unix timestamp of expiry (0 = never expires).
        domains:            Governance domains this agent is authorised for.
                            Use ``ALL_DOMAINS`` for explicit unrestricted access.
        metadata:           Arbitrary issuer metadata.

    Example::

        cred = AgentCredential(
            agent_id="agent-finance-42",
            org_id="acme-corp",
            pubkey_fingerprint="deadbeef1234",
            constitutional_hash="608508a9bd224290",
            issued_at=int(time.time()),
        )
    """

    agent_id: str
    org_id: str
    pubkey_fingerprint: str
    constitutional_hash: str
    issued_at: float
    expires_at: float = 0.0
    domains: tuple[str, ...] = ()
    status: CredentialStatus = CredentialStatus.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and canonicalise security-relevant credential fields."""
        for field_name in (
            "agent_id",
            "org_id",
            "pubkey_fingerprint",
            "constitutional_hash",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        # Fingerprints are hex: canonicalise so case/whitespace variants of a
        # revoked key cannot be re-registered as a "new" key.
        object.__setattr__(
            self, "pubkey_fingerprint", self.pubkey_fingerprint.strip().lower()
        )
        if not isinstance(self.status, CredentialStatus):
            raise ValueError("status must be a CredentialStatus")
        for field_name in ("issued_at", "expires_at"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{field_name} must be a finite number")
            if not math.isfinite(value):
                raise ValueError(f"{field_name} must be finite")
            object.__setattr__(self, field_name, float(value))
        if any(not isinstance(domain, str) or not domain.strip() for domain in self.domains):
            raise ValueError("domains must contain only non-empty strings")
        object.__setattr__(self, "domains", tuple(sorted(set(self.domains))))

    @property
    def fingerprint(self) -> str:
        """Full SHA-256 digest of the canonical authorisation fields."""
        payload = {
            "agent_id": self.agent_id,
            "constitutional_hash": self.constitutional_hash,
            "domains": self.domains,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "org_id": self.org_id,
            "pubkey_fingerprint": self.pubkey_fingerprint,
            "status": self.status.value,
        }
        encoded = json.dumps(
            payload,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def is_expired(self, now: float | None = None) -> bool:
        """True if the credential has passed its expiry timestamp."""
        if self.expires_at == 0.0:
            return False
        _now = time.time() if now is None else now
        if isinstance(_now, bool) or not isinstance(_now, (int, float)) or not math.isfinite(_now):
            raise ValueError("now must be finite")
        return _now >= self.expires_at

    def is_not_yet_valid(self, now: float | None = None) -> bool:
        """True if the credential's issuance time is still in the future."""
        _now = time.time() if now is None else now
        if isinstance(_now, bool) or not isinstance(_now, (int, float)) or not math.isfinite(_now):
            raise ValueError("now must be finite")
        return _now < self.issued_at

    def authorised_for(self, domain: str) -> bool:
        """True if this credential covers the requested domain."""
        return ALL_DOMAINS in self.domains or domain in self.domains


@dataclass(frozen=True, slots=True)
class FederationDecision:
    """Record of a single bridge access decision.

    Attributes:
        agent_id:   Agent that attempted access.
        org_id:     Organisation of the agent.
        domain:     Requested governance domain.
        allowed:    True if access was granted.
        reason:     Human-readable decision rationale.
        timestamp:  Unix timestamp of decision.
        rule_hash:  Constitutional hash validated against.
    """

    agent_id: str
    org_id: str
    domain: str
    allowed: bool
    reason: str
    timestamp: float = field(default_factory=time.time)
    rule_hash: str = _CONSTITUTIONAL_HASH

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "org_id": self.org_id,
            "domain": self.domain,
            "allowed": self.allowed,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "rule_hash": self.rule_hash,
        }


class FederatedConstitutionBridge:
    """Enforces cross-organisational constitutional rule gates.

    Implements fail-closed semantics: any unknown, revoked, expired, or
    hash-mismatched credential is rejected.  No silent failures.

    Usage::

        bridge = FederatedConstitutionBridge(
            local_constitutional_hash="608508a9bd224290",
        )

        cred = AgentCredential(
            agent_id="agent-42",
            org_id="partner-corp",
            pubkey_fingerprint="abcdef",
            constitutional_hash="608509bd224290",  # WRONG HASH
            issued_at=time.time(),
        )
        bridge.register_credential(cred)

        decision = bridge.gate(
            cred.agent_id,
            org_id=cred.org_id,
            domain="privacy",
        )
        assert not decision.allowed   # hash mismatch → fail-closed

    Args:
        local_constitutional_hash: The constitutional hash this bridge enforces.
        require_hash_match: If True (default), cross-org agents must present
            the same constitutional hash (strict federation mode).
        audit_log_size: Maximum retained decisions. Defaults to 1000;
            ``None`` retains all.
        audit_overflow_sink: Optional callback receiving each evicted immutable
            decision. The callback runs after the gate lock is released. Sink
            failures are counted and re-raised as ``RuntimeError``.
    """

    def __init__(
        self,
        local_constitutional_hash: str = _CONSTITUTIONAL_HASH,
        *,
        require_hash_match: bool = True,
        audit_log_size: int | None = 1000,
        audit_overflow_sink: Callable[[FederationDecision], None] | None = None,
    ) -> None:
        if not isinstance(local_constitutional_hash, str) or not local_constitutional_hash.strip():
            raise ValueError("local_constitutional_hash must be a non-empty string")
        if audit_log_size is not None and (
            isinstance(audit_log_size, bool)
            or not isinstance(audit_log_size, int)
            or audit_log_size <= 0
        ):
            raise ValueError("audit_log_size must be None or a positive integer")
        if audit_overflow_sink is not None and not callable(audit_overflow_sink):
            raise ValueError("audit_overflow_sink must be callable or None")
        self._local_hash = local_constitutional_hash
        self._require_hash = require_hash_match
        self._audit_log_size = audit_log_size
        self._audit_overflow_sink = audit_overflow_sink

        self._credentials: dict[tuple[str, str], AgentCredential] = {}
        self._revoked: set[tuple[str, str]] = set()
        self._revoked_fingerprints: set[tuple[str, str, str]] = set()
        self._audit_log: deque[FederationDecision] = deque(maxlen=audit_log_size)
        self._total_decisions = 0
        self._dropped_decisions = 0
        self._allowed_decisions = 0
        self._denied_decisions = 0
        self._audit_sink_failures = 0
        self._last_audit_sink_error: str | None = None
        self._lock = threading.RLock()

    # ── Credential management ────────────────────────────────────────────

    def register_credential(self, cred: AgentCredential) -> None:
        """Register a cross-org agent credential.

        Registration does not grant access — the credential is vetted
        at gate() time.

        Args:
            cred: Agent credential issued by a federated organisation.
        """
        key = (cred.org_id, cred.agent_id)
        with self._lock:
            if key in self._credentials:
                raise ValueError(
                    f"credential already registered for org_id={cred.org_id!r}, "
                    f"agent_id={cred.agent_id!r}"
                )
            self._credentials[key] = cred
            if cred.status is CredentialStatus.REVOKED:
                self._revoked.add(key)
                self._revoked_fingerprints.add(
                    (cred.org_id, cred.agent_id, cred.pubkey_fingerprint)
                )

    def renew_credential(self, cred: AgentCredential) -> None:
        """Replace a credential through an explicit, strictly newer renewal.

        Revocation remains sticky for each public-key fingerprint. Rotation to
        never-revoked key material can reinstate an identity, but rotating back
        to any historically revoked fingerprint cannot.
        """
        key = (cred.org_id, cred.agent_id)
        with self._lock:
            current = self._credentials.get(key)
            if current is None:
                raise ValueError("cannot renew an unregistered credential")
            if cred.issued_at <= current.issued_at:
                raise ValueError("renewed credential must have a newer issued_at")
            was_revoked = (
                key in self._revoked or current.status is CredentialStatus.REVOKED
            )
            key_rotated = cred.pubkey_fingerprint != current.pubkey_fingerprint
            fingerprint_key = (
                cred.org_id,
                cred.agent_id,
                cred.pubkey_fingerprint,
            )
            fingerprint_was_revoked = fingerprint_key in self._revoked_fingerprints
            self._credentials[key] = cred
            if cred.status is CredentialStatus.REVOKED:
                self._revoked_fingerprints.add(fingerprint_key)
            if (
                cred.status is CredentialStatus.REVOKED
                or fingerprint_was_revoked
                or (was_revoked and not key_rotated)
            ):
                self._revoked.add(key)
            elif key_rotated:
                self._revoked.discard(key)

    def revoke(self, agent_id: str, *, org_id: str) -> bool:
        """Revoke a credential immediately.

        Returns True if the credential was known, False otherwise.
        """
        key = (org_id, agent_id)
        with self._lock:
            credential = self._credentials.get(key)
            if credential is None:
                return False
            self._revoked.add(key)
            self._revoked_fingerprints.add(
                (org_id, agent_id, credential.pubkey_fingerprint)
            )
            return True

    def registered_agents(self) -> list[str]:
        """List all registered agent IDs (including revoked)."""
        with self._lock:
            return list(dict.fromkeys(agent_id for _, agent_id in self._credentials))

    # ── Gate ─────────────────────────────────────────────────────────────

    def gate(
        self,
        agent_id: str,
        *,
        org_id: str,
        domain: str,
        now: float | None = None,
    ) -> FederationDecision:
        """Evaluate cross-org access for an agent.

        Fail-closed: returns allowed=False for any rejection reason.

        Rejection conditions:
            1. Credential not registered → UNKNOWN
            2. Credential revoked → REVOKED
            3. Credential expired → EXPIRED
            4. Constitutional hash mismatch (if require_hash_match) → HASH_MISMATCH
            5. Domain not authorised → DOMAIN_DENIED

        Args:
            agent_id: Agent requesting cross-org access.
            org_id:   Organisation that issued the credential.
            domain:   Governance domain for the operation.
            now:      Override current time (for testing).

        Returns:
            FederationDecision with allowed flag and reason.
        """
        _now = time.time() if now is None else now
        if isinstance(_now, bool) or not isinstance(_now, (int, float)) or not math.isfinite(_now):
            raise ValueError("now must be finite")
        _now = float(_now)

        with self._lock:
            if not isinstance(org_id, str) or not org_id.strip():
                result = self._deny(agent_id, "", domain, "ORG_REQUIRED", _now)
            elif not isinstance(domain, str) or not domain.strip():
                result = self._deny(agent_id, org_id, "", "DOMAIN_REQUIRED", _now)
            else:
                key = (org_id, agent_id)
                cred = self._credentials.get(key)
                status_reasons = {
                    CredentialStatus.PENDING: "CREDENTIAL_PENDING",
                    CredentialStatus.REVOKED: "CREDENTIAL_REVOKED",
                    CredentialStatus.EXPIRED: "CREDENTIAL_EXPIRED",
                }
                if cred is None:
                    result = self._deny(
                        agent_id, org_id, domain, "UNKNOWN_CREDENTIAL", _now
                    )
                elif cred.status is not CredentialStatus.ACTIVE:
                    result = self._deny(
                        agent_id,
                        org_id,
                        domain,
                        status_reasons.get(cred.status, "CREDENTIAL_NOT_ACTIVE"),
                        _now,
                    )
                elif key in self._revoked:
                    result = self._deny(agent_id, org_id, domain, "REVOKED", _now)
                elif cred.is_not_yet_valid(now=_now):
                    result = self._deny(
                        agent_id, org_id, domain, "NOT_YET_VALID", _now
                    )
                elif cred.is_expired(now=_now):
                    result = self._deny(agent_id, org_id, domain, "EXPIRED", _now)
                elif self._require_hash and cred.constitutional_hash != self._local_hash:
                    result = self._deny(
                        agent_id, org_id, domain, "HASH_MISMATCH", _now
                    )
                elif not cred.authorised_for(domain):
                    result = self._deny(
                        agent_id, org_id, domain, "DOMAIN_DENIED", _now
                    )
                else:
                    result = self._allow(agent_id, org_id, domain, _now)

        decision, evicted = result
        self._emit_audit_overflow(evicted)
        return decision

    # ── Audit ─────────────────────────────────────────────────────────────

    def audit_log(self, *, require_complete: bool = True) -> list[dict[str, Any]]:
        """Return decision snapshots, rejecting an incomplete log by default."""
        with self._lock:
            if require_complete and self._dropped_decisions:
                raise RuntimeError(
                    "audit log was truncated; pass require_complete=False "
                    "to retrieve the retained suffix"
                )
            return [d.to_dict() for d in self._audit_log]

    def denied_count(self) -> int:
        """Number of denied gate decisions."""
        with self._lock:
            return self._denied_decisions

    def allowed_count(self) -> int:
        """Number of allowed gate decisions."""
        with self._lock:
            return self._allowed_decisions

    def summary(self) -> dict[str, Any]:
        """Bridge status summary."""
        with self._lock:
            return {
                "local_constitutional_hash": self._local_hash,
                "registered_credentials": len(self._credentials),
                "revoked_credentials": len(self._revoked),
                "total_decisions": self._total_decisions,
                "retained_decisions": len(self._audit_log),
                "dropped_decisions": self._dropped_decisions,
                "audit_overflow_count": self._dropped_decisions,
                "audit_truncated": self._dropped_decisions > 0,
                "audit_sink_failures": self._audit_sink_failures,
                "last_audit_sink_error": self._last_audit_sink_error,
                "allowed": self._allowed_decisions,
                "denied": self._denied_decisions,
                "require_hash_match": self._require_hash,
            }

    # ── Internal ──────────────────────────────────────────────────────────

    def _allow(
        self, agent_id: str, org_id: str, domain: str, now: float
    ) -> tuple[FederationDecision, tuple[FederationDecision, ...]]:
        decision = FederationDecision(
            agent_id=agent_id,
            org_id=org_id,
            domain=domain,
            allowed=True,
            reason="ALLOWED",
            timestamp=now,
            rule_hash=self._local_hash,
        )
        return decision, self._record(decision)

    def _deny(
        self, agent_id: str, org_id: str, domain: str, reason: str, now: float
    ) -> tuple[FederationDecision, tuple[FederationDecision, ...]]:
        decision = FederationDecision(
            agent_id=agent_id,
            org_id=org_id,
            domain=domain,
            allowed=False,
            reason=reason,
            timestamp=now,
            rule_hash=self._local_hash,
        )
        return decision, self._record(decision)

    def _record(self, decision: FederationDecision) -> tuple[FederationDecision, ...]:
        """Append a decision atomically, including lifetime counters."""
        with self._lock:
            evicted = (
                (self._audit_log[0],)
                if self._audit_log.maxlen is not None
                and len(self._audit_log) == self._audit_log.maxlen
                else ()
            )
            self._audit_log.append(decision)
            self._total_decisions += 1
            if decision.allowed:
                self._allowed_decisions += 1
            else:
                self._denied_decisions += 1
            self._dropped_decisions += len(evicted)
            return evicted

    def _emit_audit_overflow(
        self, evicted: tuple[FederationDecision, ...]
    ) -> None:
        """Deliver evicted decisions after releasing the gate's state lock."""
        sink = self._audit_overflow_sink
        if sink is None:
            return
        for decision in evicted:
            try:
                sink(decision)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                with self._lock:
                    self._audit_sink_failures += 1
                    self._last_audit_sink_error = error
                raise RuntimeError(f"audit overflow sink failed: {error}") from exc

    def __repr__(self) -> str:
        with self._lock:
            return (
                f"FederatedConstitutionBridge("
                f"credentials={len(self._credentials)}, "
                f"decisions={self._total_decisions})"
            )
