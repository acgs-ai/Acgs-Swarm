"""Nothing a target sends back may carry its bytes, or our token, onward.

These tests drive ``CredentialBoundHttpTarget`` through its public ``opener``
seam with responses a hostile or buggy target could produce.  The end-to-end
suite in ``test_apcc_execution_gateway_fault_e2e.py`` covers the same error
paths over a real socket; this file covers the shapes that are awkward to
produce there (reason phrases, malformed status lines, hostile receipts).
"""

from __future__ import annotations

import email.message
import http.client
import io
import json
import traceback
import urllib.error
from typing import Any

import pytest

from constitutional_swarm.apcc.execution_gateway import (
    CredentialBoundHttpTarget,
    ExecutionGatewayError,
    SideEffectInvocation,
    StaleFencingTokenError,
    TargetAuthorizationError,
)

TOKEN = "untrusted-response-token-9c41"
ECHO = f"Bearer {TOKEN}"
URL = "https://target.invalid/effects"


def _invocation() -> SideEffectInvocation:
    return SideEffectInvocation(
        authority_store_id="store-1",
        event_id="event-1",
        commit_id="commit-1",
        certificate_digest="digest-1",
        workflow_id="workflow-1",
        node_id="node-1",
        attempt_id="attempt-1",
        agent_id="agent-1",
        output_digest="output-1",
        idempotency_key="key-1",
        fencing_token=7,
        certificate_envelope=b"envelope",
        trust_log_sequence="1",
        trust_log_head="head-1",
    )


class _Response:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = io.BytesIO(body)

    def read(self, amount: int | None = None) -> bytes:
        return self._body.read() if amount is None else self._body.read(amount)

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _target(opener: Any) -> CredentialBoundHttpTarget:
    return CredentialBoundHttpTarget(URL, bearer_token=TOKEN, opener=opener)


def _receipt(**overrides: object) -> bytes:
    body: dict[str, object] = {
        "idempotency_key": "key-1",
        "fencing_token": 7,
        "target_reference": "ref-1",
        "applied_digest": "digest-applied-1",
        "replayed": False,
    }
    body.update(overrides)
    return json.dumps(body).encode("utf-8")


def _everything_reachable_from(error: BaseException) -> str:
    """The message, the chain, and the formatted traceback, as one string."""
    parts = [str(error), repr(error), "".join(traceback.format_exception(error))]
    for linked in (error.__cause__, error.__context__):
        if linked is not None:
            parts += [str(linked), repr(linked), repr(getattr(linked, "headers", ""))]
    return "\n".join(parts)


@pytest.mark.parametrize(
    ("status", "expected", "message"),
    (
        (401, TargetAuthorizationError, "external target rejected authorization (401)"),
        (403, TargetAuthorizationError, "external target rejected authorization (403)"),
        (409, StaleFencingTokenError, "external target rejected stale fence or conflict (409)"),
        (429, ExecutionGatewayError, "external target HTTP error (429)"),
        (503, ExecutionGatewayError, "external target HTTP error (503)"),
        (302, ExecutionGatewayError, "external target HTTP redirect refused (302)"),
    ),
)
def test_http_error_reports_the_status_code_and_nothing_from_the_target(
    status: int, expected: type[Exception], message: str
) -> None:
    def opener(request: Any, timeout: float) -> Any:
        headers = email.message.Message()
        headers["X-Echo"] = ECHO
        raise urllib.error.HTTPError(
            URL, status, f"reason {ECHO}", headers, io.BytesIO(f"body {ECHO}".encode())
        )

    with pytest.raises(expected) as caught:
        _target(opener).execute(_invocation())
    assert type(caught.value) is expected
    assert str(caught.value) == message
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert TOKEN not in _everything_reachable_from(caught.value)


@pytest.mark.parametrize(
    "protocol_error",
    (
        http.client.BadStatusLine(f"HTTP/1.1 200 {ECHO}"),
        http.client.IncompleteRead(ECHO.encode(), 10),
        http.client.RemoteDisconnected(ECHO),
    ),
)
def test_protocol_error_reports_only_its_type(protocol_error: Exception) -> None:
    def opener(request: Any, timeout: float) -> Any:
        raise protocol_error

    with pytest.raises(ExecutionGatewayError) as caught:
        _target(opener).execute(_invocation())
    name = type(protocol_error).__name__
    assert str(caught.value) == f"external target transport error: {name}"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert TOKEN not in _everything_reachable_from(caught.value)


def test_local_transport_error_keeps_its_cause() -> None:
    def opener(request: Any, timeout: float) -> Any:
        raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))

    with pytest.raises(ExecutionGatewayError, match="transport error") as caught:
        _target(opener).execute(_invocation())
    assert isinstance(caught.value.__cause__, urllib.error.URLError)


def test_unparseable_receipt_does_not_keep_the_body() -> None:
    def opener(request: Any, timeout: float) -> Any:
        return _Response(201, f"not json {ECHO}".encode())

    with pytest.raises(ExecutionGatewayError) as caught:
        _target(opener).execute(_invocation())
    assert str(caught.value) == "external target returned invalid JSON receipt"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert TOKEN not in _everything_reachable_from(caught.value)


@pytest.mark.parametrize(
    "overrides",
    (
        {"target_reference": ECHO},
        {"target_reference": f"ref-{TOKEN}"},
        {"applied_digest": TOKEN},
        {"target_reference": "ref\nINFO forged log line"},
        {"applied_digest": "digest\x1b[2Jcleared"},
        {"target_reference": "ref with space"},
        {"target_reference": "réf"},
        {"target_reference": "x" * 513},
        {"applied_digest": ""},
        {"target_reference": 7},
    ),
)
def test_receipt_text_that_is_unsafe_to_store_is_rejected(overrides: dict[str, object]) -> None:
    def opener(request: Any, timeout: float) -> Any:
        return _Response(201, _receipt(**overrides))

    with pytest.raises(ExecutionGatewayError) as caught:
        _target(opener).execute(_invocation())
    assert str(caught.value) == "external target receipt fields are invalid"
    assert TOKEN not in _everything_reachable_from(caught.value)


def test_longest_allowed_receipt_text_is_accepted() -> None:
    reference = "https://target.example/effects/" + "a" * (512 - 31)

    def opener(request: Any, timeout: float) -> Any:
        return _Response(200, _receipt(target_reference=reference, replayed=True))

    receipt = _target(opener).execute(_invocation())
    assert receipt.target_reference == reference
    assert receipt.replayed is True


def test_oversized_receipt_is_rejected_without_reading_it_all() -> None:
    reads: list[int | None] = []

    class _Huge(_Response):
        def read(self, amount: int | None = None) -> bytes:
            reads.append(amount)
            return super().read(amount)

    def opener(request: Any, timeout: float) -> Any:
        return _Huge(201, _receipt(padding="p" * (2 * 64 * 1024)))

    with pytest.raises(ExecutionGatewayError) as caught:
        _target(opener).execute(_invocation())
    assert str(caught.value) == "external target receipt is too large"
    assert reads == [64 * 1024 + 1]
