"""Agent DNA — embedded constitutional governance co-processor.

Every agent carries an immutable constitutional validator that intercepts
outputs before they leave. Governance is local, not networked.
No central bus needed. Scales to 800+ agents with O(1) governance cost.
"""

from __future__ import annotations

import functools
import inspect
import json
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, TypeVar

from acgs_lite import (
    Z3_RISK_THRESHOLD,
    Constitution,
    ConstitutionalImpactScorer,
    ConstitutionalViolationError,
    GovernanceEngine,
    MACIEnforcer,
    MACIRole,
    Rule,
    Z3ConstraintVerifier,
    Z3VerifyResult,
)

F = TypeVar("F", bound=Callable[..., Any])

_MAX_GOVERNED_DEPTH = 64
_MAX_GOVERNED_NODES = 10_000
_MAX_GOVERNED_CONTAINER_ITEMS = 10_000
_MAX_GOVERNED_TEXT_CHARS = 1_000_000


class DNADisabledError(RuntimeError):
    """Raised when validate() is called on a disabled AgentDNA."""


@dataclass(frozen=True, slots=True)
class DNAValidationResult:
    """Result of a DNA validation check."""

    valid: bool
    action: str
    violations: tuple[str, ...] = ()
    latency_ns: int = 0
    constitutional_hash: str = ""
    risk_score: float = 0.0
    risk_level: str = "unknown"
    scoring_method: str = "keyword"
    # acgs-lite ships no py.typed, so some builds expose Z3* as runtime variables
    # rather than types; tolerate that here (warn_unused_ignores is off).
    z3_result: Z3VerifyResult | None = None  # type: ignore[valid-type]


@dataclass
class AgentDNA:
    """Constitutional co-processor embedded in every agent.

    Validates inputs and outputs locally via acgs-lite.
    No network calls. No central bus. O(1) per validation.
    There is no published Rust/nanosecond product claim.

    Usage:
        dna = AgentDNA.from_rules([...])
        dna = AgentDNA.from_yaml("constitution.yaml")
        dna = AgentDNA(constitution=my_constitution)

        # Validate explicitly
        result = dna.validate("some action")

        # Or use as decorator
        @dna.govern
        def my_agent(input: str) -> str: ...
    """

    constitution: Constitution
    agent_id: str = "anonymous"
    maci_role: MACIRole | None = None
    strict: bool = True
    validate_output: bool = True
    risk_scoring: bool = False
    z3_verify: bool = False
    _engine: GovernanceEngine = field(init=False, repr=False)
    _maci: MACIEnforcer | None = field(init=False, repr=False, default=None)
    _scorer: ConstitutionalImpactScorer | None = field(
        init=False, repr=False, default=None
    )
    _z3: Z3ConstraintVerifier | None = field(init=False, repr=False, default=None)  # type: ignore[valid-type]
    _call_count: int = field(init=False, repr=False, default=0)
    _violation_count: int = field(init=False, repr=False, default=0)
    _total_latency_ns: int = field(init=False, repr=False, default=0)
    _disabled: bool = field(init=False, repr=False, default=False)
    # Per-instance lock protecting the mutable counter fields (_call_count,
    # _violation_count, _total_latency_ns, _disabled). Declared init=False with
    # no default and created imperatively in __post_init__ (threading.Lock is not
    # picklable, so it must not be a default value); excluded from repr/compare.
    _stats_lock: threading.Lock = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "_engine", GovernanceEngine(self.constitution, strict=self.strict)
        )
        object.__setattr__(self, "_stats_lock", threading.Lock())
        if self.maci_role is not None:
            enforcer = MACIEnforcer()
            enforcer.assign_role(self.agent_id, self.maci_role)
            object.__setattr__(self, "_maci", enforcer)
        if self.risk_scoring:
            object.__setattr__(self, "_scorer", ConstitutionalImpactScorer())
        if self.z3_verify:
            object.__setattr__(self, "_z3", Z3ConstraintVerifier())  # type: ignore[operator]

    @classmethod
    def from_rules(
        cls,
        rules: list[Rule],
        *,
        name: str = "agent-dna",
        agent_id: str = "anonymous",
        maci_role: MACIRole | None = None,
        strict: bool = True,
        validate_output: bool = True,
        risk_scoring: bool = False,
        z3_verify: bool = False,
    ) -> AgentDNA:
        """Create DNA from a list of rules."""
        return cls(
            constitution=Constitution.from_rules(rules, name=name),
            agent_id=agent_id,
            maci_role=maci_role,
            strict=strict,
            validate_output=validate_output,
            risk_scoring=risk_scoring,
            z3_verify=z3_verify,
        )

    @classmethod
    def from_yaml(
        cls,
        path: str | Path,
        *,
        agent_id: str = "anonymous",
        maci_role: MACIRole | None = None,
        strict: bool = True,
        validate_output: bool = True,
        risk_scoring: bool = False,
        z3_verify: bool = False,
    ) -> AgentDNA:
        """Create DNA from a YAML constitution file."""
        return cls(
            constitution=Constitution.from_yaml(path),
            agent_id=agent_id,
            maci_role=maci_role,
            strict=strict,
            validate_output=validate_output,
            risk_scoring=risk_scoring,
            z3_verify=z3_verify,
        )

    @classmethod
    def default(
        cls,
        *,
        agent_id: str = "anonymous",
        maci_role: MACIRole | None = None,
        validate_output: bool = True,
        risk_scoring: bool = False,
        z3_verify: bool = False,
    ) -> AgentDNA:
        """Create DNA with the default ACGS constitution."""
        return cls(
            constitution=Constitution.default(),
            agent_id=agent_id,
            maci_role=maci_role,
            validate_output=validate_output,
            risk_scoring=risk_scoring,
            z3_verify=z3_verify,
        )

    def disable(self) -> None:
        """Kill switch — disable all constitutional validation.

        While disabled, validate() raises DNADisabledError.
        EU AI Act Art. 14(3): human-initiated halt capability.
        """
        with self._stats_lock:
            object.__setattr__(self, "_disabled", True)

    def enable(self) -> None:
        """Re-enable constitutional validation after a halt."""
        with self._stats_lock:
            object.__setattr__(self, "_disabled", False)

    @property
    def is_disabled(self) -> bool:
        """Whether this DNA co-processor is currently disabled."""
        with self._stats_lock:
            return self._disabled

    @property
    def hash(self) -> str:
        """Constitutional hash — must match across all swarm agents."""
        return self.constitution.hash

    @property
    def stats(self) -> dict[str, Any]:
        """Governance statistics (thread-safe snapshot)."""
        with self._stats_lock:
            calls = self._call_count
            violations = self._violation_count
            total_latency = self._total_latency_ns
        return {
            "agent_id": self.agent_id,
            "constitutional_hash": self.hash,
            "maci_role": self.maci_role.value if self.maci_role else None,
            "calls": calls,
            "violations": violations,
            "avg_latency_ns": (total_latency // calls if calls > 0 else 0),
        }

    def validate(self, action: str) -> DNAValidationResult:
        """Validate an action against the embedded constitution.

        In strict mode, raises ConstitutionalViolationError on critical violations.
        In non-strict mode, returns result with violations listed.

        Raises:
            DNADisabledError: If the DNA co-processor has been disabled via kill switch.
        """
        # Read _disabled without the stats lock (fast path; booleans are
        # atomically readable in CPython but we hold stats_lock for correctness
        # on other runtimes and for correctness of the disable/enable protocol).
        with self._stats_lock:
            if self._disabled:
                raise DNADisabledError(
                    f"Agent {self.agent_id} DNA is disabled — all actions blocked"
                )

        # Layer 1: semantic risk scoring (opt-in, ~1ms)
        risk_score = 0.0
        risk_lv = "unknown"
        scoring_method = "keyword"
        if self._scorer is not None:
            impact = self._scorer.score(action)
            risk_score = impact["score"]
            risk_lv = impact["risk_level"]
            scoring_method = impact["scoring_method"]

        # Layer 2: constitutional keyword/rule engine (always; unit bound <50us)
        start = time.perf_counter_ns()
        try:
            result = self._engine.validate(action)
            elapsed = time.perf_counter_ns() - start
            violations = tuple(f"{v.rule_id}: {v.rule_text}" for v in result.violations)
            has_violations = bool(violations)

            # Atomically update counters under the lock.
            with self._stats_lock:
                object.__setattr__(self, "_call_count", self._call_count + 1)
                object.__setattr__(
                    self, "_total_latency_ns", self._total_latency_ns + elapsed
                )
                if has_violations:
                    object.__setattr__(
                        self, "_violation_count", self._violation_count + 1
                    )

            # Layer 3: Z3 formal verification (opt-in, ~50-500ms).
            # Only invoked for critical-risk actions to keep cost proportional.
            z3_result: Z3VerifyResult | None = None  # type: ignore[valid-type]
            if self._z3 is not None and risk_score >= Z3_RISK_THRESHOLD:
                z3_result = self._z3.verify(action)

            return DNAValidationResult(
                valid=result.valid,
                action=action,
                violations=violations,
                latency_ns=elapsed,
                constitutional_hash=self.hash,
                risk_score=risk_score,
                risk_level=risk_lv,
                scoring_method=scoring_method,
                z3_result=z3_result,
            )
        except ConstitutionalViolationError:
            elapsed = time.perf_counter_ns() - start
            with self._stats_lock:
                object.__setattr__(self, "_call_count", self._call_count + 1)
                object.__setattr__(self, "_violation_count", self._violation_count + 1)
                object.__setattr__(
                    self, "_total_latency_ns", self._total_latency_ns + elapsed
                )
            raise

    def check_maci(self, action_type: str) -> None:
        """Verify MACI role permits this action type.

        Raises MACIViolationError if the agent's role cannot perform the action.
        """
        if self._maci is not None:
            self._maci.check(self.agent_id, action_type)

    def govern(self, fn: F) -> F:
        """Decorator that wraps a function with constitutional DNA validation.

        Validates input before execution and output after.
        """
        return _GovernedCallable(self, fn)  # type: ignore[return-value]


class _GovernedCallable:
    """Callable descriptor that distinguishes Python binding from direct calls."""

    def __init__(self, dna: AgentDNA, fn: Callable[..., Any]) -> None:
        self._dna = dna
        self._fn = fn
        self._signature = inspect.signature(fn)
        self._is_async = inspect.iscoroutinefunction(fn)
        functools.update_wrapper(self, fn)
        if self._is_async:
            # Python 3.11's inspect.iscoroutinefunction() recognizes callable
            # function-like objects from these standard metadata attributes.
            self.__code__ = fn.__code__  # type: ignore[attr-defined]
            self.__defaults__ = getattr(fn, "__defaults__", None)
            self.__kwdefaults__ = getattr(fn, "__kwdefaults__", None)
            if hasattr(inspect, "markcoroutinefunction"):
                inspect.markcoroutinefunction(self)

    def __get__(self, instance: Any, owner: type[Any] | None = None) -> Any:
        if instance is None:
            return self
        parameters = tuple(self._signature.parameters.values())
        bound_signature = self._signature.replace(parameters=parameters[1:])
        if self._is_async:

            @functools.wraps(self._fn)
            async def async_bound(*args: Any, **kwargs: Any) -> Any:
                return await self._invoke_async(
                    (instance, *args), kwargs, receiver_bound=True
                )

            async_bound.__signature__ = bound_signature  # type: ignore[attr-defined]
            return async_bound

        @functools.wraps(self._fn)
        def sync_bound(*args: Any, **kwargs: Any) -> Any:
            return self._invoke_sync((instance, *args), kwargs, receiver_bound=True)

        sync_bound.__signature__ = bound_signature  # type: ignore[attr-defined]
        return sync_bound

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if self._is_async:
            return self._invoke_async(args, kwargs, receiver_bound=False)
        return self._invoke_sync(args, kwargs, receiver_bound=False)

    def _input_text(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        receiver_bound: bool,
    ) -> str:
        bound = self._signature.bind(*args, **kwargs)
        bound.apply_defaults()
        values = dict(bound.arguments)
        if receiver_bound:
            first = next(iter(self._signature.parameters), None)
            if first is not None:
                values.pop(first, None)
        if len(values) == 1:
            return _extract_output(next(iter(values.values())))
        return _extract_output(values) if values else ""

    def _invoke_sync(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        receiver_bound: bool,
    ) -> Any:
        self._dna.validate(
            self._input_text(args, kwargs, receiver_bound=receiver_bound)
        )
        result = self._fn(*args, **kwargs)
        if self._dna.validate_output and result is not None:
            self._dna.validate(_extract_output(result))
        return result

    async def _invoke_async(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        receiver_bound: bool,
    ) -> Any:
        self._dna.validate(
            self._input_text(args, kwargs, receiver_bound=receiver_bound)
        )
        result = await self._fn(*args, **kwargs)
        if self._dna.validate_output and result is not None:
            self._dna.validate(_extract_output(result))
        return result


def constitutional_dna(
    fn: F | None = None,
    *,
    constitution: Constitution | None = None,
    rules: list[Rule] | None = None,
    yaml_path: str | Path | None = None,
    agent_id: str = "anonymous",
    maci_role: MACIRole | None = None,
    strict: bool = True,
    validate_output: bool = True,
) -> F | Callable[[F], F]:
    """Decorator that embeds constitutional DNA into any callable.

    Usage:
        @constitutional_dna
        def my_agent(input: str) -> str: ...

        @constitutional_dna(rules=[...], agent_id="worker-01")
        def my_agent(input: str) -> str: ...

        @constitutional_dna(yaml_path="governance.yaml")
        async def my_agent(input: str) -> str: ...
    """

    def _build_dna() -> AgentDNA:
        if constitution is not None:
            return AgentDNA(
                constitution=constitution,
                agent_id=agent_id,
                maci_role=maci_role,
                strict=strict,
                validate_output=validate_output,
            )
        if rules is not None:
            return AgentDNA.from_rules(
                rules,
                agent_id=agent_id,
                maci_role=maci_role,
                strict=strict,
                validate_output=validate_output,
            )
        if yaml_path is not None:
            return AgentDNA.from_yaml(
                yaml_path,
                agent_id=agent_id,
                maci_role=maci_role,
                strict=strict,
                validate_output=validate_output,
            )
        return AgentDNA.default(
            agent_id=agent_id,
            maci_role=maci_role,
            validate_output=validate_output,
        )

    def decorator(f: F) -> F:
        dna = _build_dna()
        governed = dna.govern(f)
        governed._dna = dna  # type: ignore[attr-defined]
        return governed

    if fn is not None:
        return decorator(fn)
    return decorator


@dataclass
class _GovernanceTraversal:
    active: set[int] = field(default_factory=set)
    nodes: int = 0

    def visit(self, depth: int) -> None:
        if depth > _MAX_GOVERNED_DEPTH:
            raise ValueError("governed value exceeds maximum depth")
        self.nodes += 1
        if self.nodes > _MAX_GOVERNED_NODES:
            raise ValueError("governed value exceeds maximum node count")


def _check_governed_container_size(size: int) -> None:
    if size > _MAX_GOVERNED_CONTAINER_ITEMS:
        raise ValueError("governed container exceeds maximum item count")


def _governed_json_value(
    value: Any,
    traversal: _GovernanceTraversal | None = None,
    *,
    depth: int = 0,
) -> Any:
    """Build a JSON-safe governance view without invoking object copy hooks."""
    traversal = _GovernanceTraversal() if traversal is None else traversal
    traversal.visit(depth)
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value) > _MAX_GOVERNED_TEXT_CHARS:
            raise ValueError("governed text exceeds maximum character count")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("governed JSON numbers must be finite")
        return value

    if isinstance(value, dict):
        identity = id(value)
        if identity in traversal.active:
            raise ValueError("cyclic governed value")
        _check_governed_container_size(dict.__len__(value))
        if any(type(key) is not str for key in dict.__iter__(value)):
            raise TypeError("governed mappings require string keys")
        if any(
            len(key) > _MAX_GOVERNED_TEXT_CHARS for key in dict.__iter__(value)
        ):
            raise ValueError("governed mapping key exceeds maximum character count")
        traversal.active.add(identity)
        try:
            return {
                key: _governed_json_value(nested, traversal, depth=depth + 1)
                for key, nested in dict.items(value)
            }
        finally:
            traversal.active.remove(identity)
    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in traversal.active:
            raise ValueError("cyclic governed value")
        if isinstance(value, list):
            size = list.__len__(value)
            iterator = list.__iter__(value)
        else:
            size = tuple.__len__(value)
            iterator = tuple.__iter__(value)
        _check_governed_container_size(size)
        traversal.active.add(identity)
        try:
            return [
                _governed_json_value(nested, traversal, depth=depth + 1)
                for nested in iterator
            ]
        finally:
            traversal.active.remove(identity)

    if is_dataclass(value) and not isinstance(value, type):
        identity = id(value)
        if identity in traversal.active:
            raise ValueError("cyclic governed value")
        dataclass_fields = fields(value)
        _check_governed_container_size(len(dataclass_fields))
        traversal.active.add(identity)
        try:
            return {
                item.name: _governed_json_value(
                    object.__getattribute__(value, item.name),
                    traversal,
                    depth=depth + 1,
                )
                for item in dataclass_fields
            }
        finally:
            traversal.active.remove(identity)

    if (
        type(value).__repr__ is object.__repr__
        and type(value).__str__ is object.__str__
    ):
        raise TypeError(f"unsupported governed value type: {type(value).__name__}")

    representation = repr(value)
    if len(representation) > _MAX_GOVERNED_TEXT_CHARS:
        raise ValueError("governed representation exceeds maximum character count")
    if type(value).__str__ is not object.__str__:
        custom_text = str(value)
        if len(custom_text) > _MAX_GOVERNED_TEXT_CHARS:
            raise ValueError("governed string exceeds maximum character count")
        if custom_text and custom_text != representation:
            representation = (
                f"{representation}\n{custom_text}" if representation else custom_text
            )
    if not representation:
        raise ValueError("governed value has no representation")
    return representation


def _extract_output(result: Any) -> str:
    """Extract validatable string from any output type.

    The same representation governs bound inputs and returned values. Serialization
    errors propagate: an unrepresentable value must never silently bypass governance.
    """
    if isinstance(result, str):
        return result
    if result is None:
        return ""
    governed = _governed_json_value(result)
    if isinstance(governed, str):
        return governed
    return json.dumps(
        governed,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
