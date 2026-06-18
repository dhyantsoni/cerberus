"""
Cerberus Gateway — the reference monitor.

Sits between a host agent and its downstream MCP servers. It:
  * merges tool catalogs from every downstream server (running Sentinel at register)
  * intercepts every ``tools/call`` and runs it through Tracer -> Warden
  * emits structured events for the live DAG dashboard + the signed receipt log

This module exposes a transport-agnostic ``Gateway.handle_call(...)`` so the core
is unit-testable in-process (see ``host/agent.py``). Wiring it as a real MCP server
that proxies stdio/HTTP to downstream MCP servers is the integration layer -- see
the TODOs; the security logic does not depend on the transport.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .events import EventBus
from .labels import Capability
from .sentinel import Sentinel, ServerManifest
from .tracer import Tracer
from .warden import Decision, Mode, Warden


@dataclass
class DownstreamServer:
    name: str
    trusted: bool
    manifest: ServerManifest
    call: Callable[[str, dict], "ToolResult"]   # (tool, args) -> result
    is_egress: bool = False                       # does this server reach external sinks?


@dataclass
class ToolResult:
    value: str
    sensitivity: int = 0          # labels.Sensitivity
    readers: frozenset = frozenset({"*"})


class Gateway:
    def __init__(self, policy_path: str | Path = "policies/default.yaml",
                 session_path: str | Path = "session.jsonl",
                 confirm_fn: Optional[Callable[[str], bool]] = None,
                 enabled: bool = True):
        self.enabled = enabled                    # the demo "Cerberus ON/OFF" switch
        self.bus = EventBus(session_path)
        self.sentinel = Sentinel(bus=self.bus)
        self.tracer = Tracer(bus=self.bus)
        self.warden = Warden(policy_path, self.bus, confirm_fn=confirm_fn)
        self.servers: Dict[str, DownstreamServer] = {}

    # ---- registration -------------------------------------------------------

    def register(self, server: DownstreamServer) -> List:
        findings = self.sentinel.register(server.manifest)
        self.servers[server.name] = server
        # A BLOCK-severity Sentinel finding quarantines the server's tools.
        return findings

    # ---- the intercepted call -----------------------------------------------

    def handle_call(self, server_name: str, tool: str, args: dict) -> dict:
        server = self.servers[server_name]
        self.bus.emit("tool_call", server=server_name, tool=tool, args=args)

        # Cerberus OFF: pass straight through (Act 1 -- the kill).
        if not self.enabled:
            res = server.call(tool, args)
            return {"ok": True, "value": res.value, "cerberus": "OFF"}

        # Label every incoming argument value by where it came from. In a full
        # build, the gateway threads caps from prior results; here callers pass
        # caps via args["_caps"] for the in-process demo.
        arg_caps: List[Capability] = args.get("_caps", [])
        payload = str({k: v for k, v in args.items() if not k.startswith("_")})

        sink = args.get("_sink", server_name)
        trifecta = self.tracer.evaluate(is_egress_sink=server.is_egress,
                                        arg_caps=arg_caps, payload=payload)
        acl_violation = (self.tracer.reader_acl_violation(sink, arg_caps)
                         if server.is_egress else None)

        decision: Decision = self.warden.decide(
            tool=tool, sink=sink, is_egress_sink=server.is_egress,
            arg_caps=arg_caps, payload=payload, trifecta=trifecta,
            acl_violation=acl_violation)

        if decision.mode in (Mode.BLOCK, Mode.QUARANTINE):
            return {"ok": False, "blocked": True, "mode": decision.mode.value,
                    "reason": decision.reason, "blast_radius": decision.blast_radius}

        # ALLOW / REDACT / CONFIRM-approved -> execute downstream
        res = server.call(tool, args)
        return {"ok": True, "value": res.value, "mode": decision.mode.value}


# ---- TODO: real MCP transport ------------------------------------------------
# Wrap the above as an MCP server (mcp.server.Server) whose tools/list returns the
# merged catalog and whose tools/call proxies to downstream MCP clients
# (mcp.client). Point Claude Desktop / Cursor at THIS server. The Sentinel /
# Tracer / Warden pipeline above is unchanged -- only the I/O edges differ.
