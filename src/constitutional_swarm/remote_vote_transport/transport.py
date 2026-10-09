"""Client/server runtime for remote vote exchange."""

from __future__ import annotations

import asyncio
import inspect
import os
import ssl
from collections.abc import Awaitable, Callable
from typing import Any

from constitutional_swarm.mesh import RemoteVoteRequest
from constitutional_swarm.remote_vote_transport.protocol import (
    RemoteVoteResponse,
    TransportSecurity,
    _build_ssl_context,
    _format_uri_host,
    _parse_ws_endpoint,
    _resolve_transport_security,
    decode_remote_vote_request,
    decode_remote_vote_response,
    encode_remote_vote_request,
    encode_remote_vote_response,
)


class RemoteVoteClient:
    """WebSocket client for one-shot remote vote requests.

    ``transport_security="plaintext"`` always uses ``ws://`` with no SSL
    context. ``"tls"`` uses ``wss://`` with the supplied context or a default
    client context. ``"auto"`` derives the scheme from the endpoint, otherwise
    defaulting to plaintext for loopback hosts and TLS for non-loopback hosts;
    explicit contexts therefore require ``transport_security="tls"``.
    """

    def __init__(
        self,
        *,
        transport_security: TransportSecurity = "auto",
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.transport_security = transport_security
        if ssl_context is None:
            self.ssl_context = None
        elif transport_security == "auto":
            raise ValueError("auto transport cannot use an explicit SSL context")
        else:
            self.ssl_context = _build_ssl_context(
                transport_security,
                server_side=False,
                ssl_context=ssl_context,
            )

    async def request_vote(
        self,
        host: str,
        port: int,
        request: RemoteVoteRequest,
        *,
        timeout: float = 5.0,
    ) -> RemoteVoteResponse:
        try:
            import websockets  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "Remote vote transport requires 'websockets>=12.0'. "
                "Install with: pip install 'constitutional-swarm[transport]'"
            ) from exc

        scheme, parsed_host, parsed_port = _parse_ws_endpoint(host)
        resolved_port = parsed_port or port
        resolved_mode = _resolve_transport_security(
            transport_security=self.transport_security,
            scheme=scheme,
            host=parsed_host,
        )
        ssl_context = _build_ssl_context(
            resolved_mode,
            server_side=False,
            ssl_context=self.ssl_context,
        )
        uri = f"{'wss' if resolved_mode == 'tls' else 'ws'}://{_format_uri_host(parsed_host)}:{resolved_port}"
        async with asyncio.timeout(timeout):
            async with websockets.connect(uri, ssl=ssl_context) as ws:
                await ws.send(encode_remote_vote_request(request))
                message = await ws.recv()
        return decode_remote_vote_response(str(message))


class RemoteVoteServer:
    """WebSocket server that handles one request-response remote vote RPCs.

    ``transport_security="plaintext"`` binds a ``ws://`` server without TLS.
    TLS mode requires either a caller-provided server ``ssl_context`` or a
    ``certfile`` (and optional separate ``keyfile``). ``"auto"`` derives from a
    host URL scheme, otherwise using plaintext only for loopback hosts.
    """

    def __init__(
        self,
        handler: Callable[[RemoteVoteRequest], RemoteVoteResponse | Awaitable[RemoteVoteResponse]],
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        transport_security: TransportSecurity = "auto",
        ssl_context: ssl.SSLContext | None = None,
        certfile: str | os.PathLike[str] | None = None,
        keyfile: str | os.PathLike[str] | None = None,
    ) -> None:
        scheme, parsed_host, parsed_port = _parse_ws_endpoint(host)
        resolved_mode = _resolve_transport_security(
            transport_security=transport_security,
            scheme=scheme,
            host=parsed_host,
        )
        self._handler = handler
        self.host = parsed_host
        self.port = parsed_port or port
        self.transport_security = transport_security
        self.ssl_context = _build_ssl_context(
            resolved_mode,
            server_side=True,
            ssl_context=ssl_context,
            certfile=certfile,
            keyfile=keyfile,
        )
        self._server: Any = None
        self._actual_port: int = self.port

    async def start(self) -> None:
        try:
            import websockets  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "Remote vote transport requires 'websockets>=12.0'. "
                "Install with: pip install 'constitutional-swarm[transport]'"
            ) from exc
        self._server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port,
            ssl=self.ssl_context,
        )
        sockets = self._server.sockets
        if sockets:
            self._actual_port = sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> RemoteVoteServer:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    @property
    def actual_port(self) -> int:
        return self._actual_port

    async def _handle_connection(self, websocket: Any) -> None:
        async for message in websocket:
            request = decode_remote_vote_request(str(message))
            response = self._handler(request)
            # isawaitable (not iscoroutine) narrows the union to RemoteVoteResponse
            # in the else branch and also covers non-coroutine awaitables.
            if inspect.isawaitable(response):
                response = await response
            await websocket.send(encode_remote_vote_response(response))


__all__ = ["RemoteVoteClient", "RemoteVoteServer"]
