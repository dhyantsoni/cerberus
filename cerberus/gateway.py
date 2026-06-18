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
from .labels import Capability, Sensitivity
from .sentinel import Finding, Sentinel, ServerManifest
from .session_state import LabelLedger
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
                 enabled: bool = True,
                 auto_label: bool = True):
        self.enabled = enabled                    # the demo "Cerberus ON/OFF" switch
        # auto_label: label every downstream result and reconstruct missing
        # arg_caps from the LabelLedger. Real callers (LLM loop, MCP client,
        # benchmark) need this; the in-process demo passes _caps explicitly and
        # constructs with auto_label=False so its event stream stays identical.
        self.auto_label = auto_label
        self.bus = EventBus(session_path)
        self.sentinel = Sentinel(bus=self.bus)
        self.tracer = Tracer(bus=self.bus)
        self.warden = Warden(policy_path, self.bus, confirm_fn=confirm_fn)
        self.servers: Dict[str, DownstreamServer] = {}
        self.ledger = LabelLedger()
        self._findings: Dict[str, List[Finding]] = {}

    # ---- registration -------------------------------------------------------

    def register(self, server: DownstreamServer) -> List[Finding]:
        findings = self.sentinel.register(server.manifest)
        self.servers[server.name] = server
        self._findings[server.name] = findings
        # A BLOCK-severity Sentinel finding quarantines the server's tools
        # (see list_tools, which omits them from the advertised catalog).
        return findings

    def register_remote(self, name: str, session, *, trusted: bool = False,
                        is_egress: bool = False) -> List[Finding]:
        """Register a downstream MCP server reachable over a live client session.

        ``session`` is duck-typed (the real MCP client is WS-A): it must expose
        ``list_tools() -> {tool: description}`` and ``call(tool, args) -> ToolResult``.
        The same Sentinel/Tracer/Warden pipeline applies — only the I/O edge differs.
        """
        manifest = ServerManifest(name=name, tools=session.list_tools())
        server = DownstreamServer(name=name, trusted=trusted, manifest=manifest,
                                  call=session.call, is_egress=is_egress)
        return self.register(server)

    def list_tools(self) -> List[dict]:
        """Merged catalog of every registered server's tools, namespaced
        ``server__tool``. Servers carrying a BLOCK-severity Sentinel finding
        are quarantined — their tools are omitted so a hijacked host can never
        even select a poisoned tool (a visible Sentinel win)."""
        catalog: List[dict] = []
        for name, server in self.servers.items():
            if any(f.severity == "BLOCK" for f in self._findings.get(name, [])):
                continue
            for tool, desc in server.manifest.tools.items():
                catalog.append({"name": f"{name}__{tool}", "server": name,
                                "tool": tool, "description": desc,
                                "is_egress": server.is_egress})
        return catalog

    # ---- the intercepted call -----------------------------------------------

    def handle_call(self, server_name: str, tool: str, args: dict) -> dict:
        server = self.servers[server_name]
        self.bus.emit("tool_call", server=server_name, tool=tool, args=args)

        # Cerberus OFF: pass straight through (Act 1 -- the kill).
        if not self.enabled:
            res = server.call(tool, args)
            self._label_result(server, res)
            return {"ok": True, "value": res.value, "cerberus": "OFF"}

        # Label every incoming argument value by where it came from. The
        # in-process demo passes caps explicitly via args["_caps"]; a real
        # caller passes none, so we reconstruct them from the LabelLedger.
        arg_caps: Optional[List[Capability]] = args.get("_caps")
        if arg_caps is None:
            arg_caps = self.ledger.infer_caps(args) if self.auto_label else []
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
        self._label_result(server, res)
        return {"ok": True, "value": res.value, "mode": decision.mode.value}

    # ---- automatic labeling -------------------------------------------------

    def _label_result(self, server: DownstreamServer, res: "ToolResult") -> None:
        """Record a downstream result's capability so a later egress call can be
        attributed. No-op in the explicit-caps demo path (auto_label=False)."""
        if not self.auto_label:
            return
        cap = self.tracer.observe_tool_result(
            server.trusted, Sensitivity(res.sensitivity), res.value,
            readers=res.readers)
        self.ledger.record(res.value, cap)


# ---- real MCP transport ------------------------------------------------------
# WS-A wraps this Gateway as an MCP server (cerberus/mcp_server.py) whose
# tools/list returns self.list_tools() and whose tools/call bridges to
# handle_call; downstream MCP servers are attached via register_remote().
# Point Claude Desktop / Cursor at THAT server. The Sentinel / Tracer / Warden
# pipeline above is unchanged -- only the I/O edges differ.
