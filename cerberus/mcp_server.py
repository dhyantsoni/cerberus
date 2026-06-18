"""
Cerberus as a REAL MCP server (stdio) — point Claude Desktop / Cursor at this.

This is the integration edge promised by gateway.py: a Model Context Protocol
server whose ``tools/list`` is the gateway's merged catalog (poisoned servers
already quarantined by Sentinel) and whose ``tools/call`` runs every call through
the Sentinel -> Tracer -> Warden pipeline before it touches a downstream tool. The
host model never talks to a tool directly; it talks to Cerberus.

    python -m cerberus.mcp_server            # serve over stdio (what a client spawns)

Drop this into a client's MCP config (see claude_desktop_config.json) and every
tool call the model makes is mediated. When the model is hijacked into exfiltrating
a SECRET to an external sink, the call comes back as an MCP tool error carrying the
Warden's reason — the refusal is legible inside the chat, and the sink stays empty.

Downstream tools here are the in-process demo servers (filesystem, weather,
status_page; the poisoned docsearch is withheld). To instead proxy real external
MCP servers, attach them with ``Gateway.register_remote`` via cerberus/mcp_client.py.
"""
from __future__ import annotations

from typing import Optional

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server

from cerberus.gateway import Gateway

# Light input-schema hints so a client model knows what to pass. Kept permissive
# (additionalProperties) and unvalidated so the demo never fails on a schema quibble.
_SCHEMA_HINTS = {
    "read_file": {"path": "path of the file to read"},
    "write_file": {"path": "path to write", "content": "text to write"},
    "get_forecast": {"city": "city name"},
    "post": {"body": "payload to POST to the external sink"},
    "search_docs": {"query": "documentation search query"},
}


def _input_schema(tool_base: str) -> dict:
    props = {k: {"type": "string", "description": v}
             for k, v in _SCHEMA_HINTS.get(tool_base, {}).items()}
    return {"type": "object", "properties": props, "additionalProperties": True}


def build_server(gw: Optional[Gateway] = None):
    """Build the MCP Server around a Gateway. Returns (server, gateway).

    If no gateway is supplied, wires the in-process demo servers with auto-labelling
    on (a real client passes no per-value caps, so the LabelLedger must reconstruct them).
    """
    if gw is None:
        from host.agent import build_gateway
        gw, _ = build_gateway(enabled=True, auto_label=True)

    server = Server("cerberus")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=t["name"],
                description=("[egress] " if t["is_egress"] else "") + t["description"],
                inputSchema=_input_schema(t["tool"]),
            )
            for t in gw.list_tools()
        ]

    @server.call_tool(validate_input=False)
    async def _call_tool(name: str, arguments: dict) -> types.CallToolResult:
        server_name, _, tool = name.partition("__")
        if server_name not in gw.servers:
            return types.CallToolResult(
                content=[types.TextContent(type="text",
                         text=f"unknown or quarantined tool: {name}")],
                isError=True)
        # The capability core is synchronous; run it off the event loop.
        result = await anyio.to_thread.run_sync(
            lambda: gw.handle_call(server_name, tool, dict(arguments or {})))

        if result.get("blocked"):
            reason = result.get("reason", "policy violation")
            averted = result.get("blast_radius", "")
            text = (f"⛔ BLOCKED by Cerberus — {reason}."
                    + (f" Averted: {averted}." if averted else "")
                    + " The call did not reach the tool.")
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=text)], isError=True)

        return types.CallToolResult(
            content=[types.TextContent(type="text", text=str(result.get("value", "")))])

    return server, gw


async def _amain() -> None:
    import os
    import sys

    from mcp.server.stdio import stdio_server

    server, gw = build_server()
    remotes = []
    servers_path = os.environ.get("CERBERUS_SERVERS")
    if servers_path:
        from cerberus.mcp_config import attach_servers
        try:
            remotes = attach_servers(gw, servers_path)
            print(f"[cerberus] attached {len(remotes)} external MCP server(s) from {servers_path}",
                  file=sys.stderr)
        except Exception as e:   # a bad downstream must not take the gateway down
            print(f"[cerberus] failed to attach external servers: {e}", file=sys.stderr)

    try:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        for r in remotes:
            r.close()


def main() -> None:
    anyio.run(_amain)


if __name__ == "__main__":
    main()
