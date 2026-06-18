"""
Attach EXTERNAL MCP servers behind a Cerberus Gateway.

``Gateway.register_remote(name, session, ...)`` expects a *synchronous*, duck-typed
session: ``list_tools() -> {tool: description}`` and ``call(tool, args) -> ToolResult``.
A real MCP client is async and owns a subprocess, so ``RemoteMCPServer`` runs the async
``ClientSession`` on a private event-loop thread and exposes that sync facade — letting
the synchronous Sentinel/Tracer/Warden core mediate any real MCP server unchanged.

Output labelling is declared per server: an untrusted server (e.g. a web-fetch tool)
is registered ``trusted=False`` so its content arms L2; a server that can reach external
URLs is registered ``is_egress=True`` so it arms L3; ``sensitivity``/``readers`` set how
its results are labelled. This is how Cerberus stays framework-agnostic: it does not care
what the downstream server is, only how its data is labelled.
"""
from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from typing import Callable, Dict, Optional

from .gateway import ToolResult
from .labels import WILDCARD, Sensitivity


class RemoteMCPServer:
    """Sync facade over an async MCP ``ClientSession`` running on its own loop thread."""

    def __init__(self, name: str, *, command: Optional[str] = None,
                 args: Optional[list] = None, env: Optional[dict] = None,
                 sensitivity: Sensitivity = Sensitivity.PUBLIC,
                 readers: frozenset = frozenset({WILDCARD}),
                 session_factory: Optional[Callable] = None, timeout: float = 30.0):
        self.name = name
        self._command, self._args, self._env = command, args or [], env
        self._sensitivity = int(sensitivity)
        self._readers = readers
        self._timeout = timeout
        # session_factory() -> async context manager yielding a ClientSession.
        # Defaults to spawning the stdio subprocess; tests inject an in-memory one.
        self._session_factory = session_factory
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._session = None
        self._tools: Dict[str, str] = {}
        self._ready = threading.Event()
        self._exc: Optional[BaseException] = None
        self._stop: Optional[asyncio.Event] = None

    # ---- lifecycle ----------------------------------------------------------

    def start(self) -> "RemoteMCPServer":
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True, name=f"mcp-{self.name}")
        self._thread.start()
        if not self._ready.wait(self._timeout):
            raise TimeoutError(f"MCP server {self.name!r} did not become ready in {self._timeout}s")
        if self._exc:
            raise self._exc
        return self

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        except Exception as e:           # surface startup failures to start()
            self._exc = e
            self._ready.set()

    @asynccontextmanager
    async def _default_cm(self):
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        params = StdioServerParameters(command=self._command, args=self._args, env=self._env)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                yield session

    async def _serve(self) -> None:
        cm = self._session_factory() if self._session_factory else self._default_cm()
        async with cm as session:
            await session.initialize()
            listed = await session.list_tools()
            self._tools = {t.name: (t.description or "") for t in listed.tools}
            self._session = session
            self._stop = asyncio.Event()
            self._ready.set()
            await self._stop.wait()      # keep the session open until close()

    def close(self) -> None:
        if self._loop and self._stop and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread:
            self._thread.join(timeout=self._timeout)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()

    # ---- the duck-typed contract Gateway.register_remote needs --------------

    def list_tools(self) -> Dict[str, str]:
        return dict(self._tools)

    def call(self, tool: str, args: dict) -> ToolResult:
        clean = {k: v for k, v in (args or {}).items() if not str(k).startswith("_")}
        fut = asyncio.run_coroutine_threadsafe(self._session.call_tool(tool, clean), self._loop)
        res = fut.result(timeout=self._timeout)
        text = "".join(getattr(c, "text", "") for c in res.content
                       if getattr(c, "type", None) == "text")
        return ToolResult(value=text, sensitivity=self._sensitivity, readers=self._readers)
