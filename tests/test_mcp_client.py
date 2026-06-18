"""WS-A: the external-attach path. RemoteMCPServer presents a real async MCP
ClientSession as the sync session Gateway.register_remote needs. Verified over the
in-memory transport against a trivial downstream server."""
from __future__ import annotations

import pytest

pytest.importorskip("mcp")

import mcp.types as types  # noqa: E402
from mcp.server.lowlevel import Server  # noqa: E402
from mcp.shared.memory import create_connected_server_and_client_session as connect  # noqa: E402

from cerberus.gateway import Gateway
from cerberus.mcp_client import RemoteMCPServer


def _tiny_server():
    s = Server("tiny")

    @s.list_tools()
    async def _lt():
        return [types.Tool(name="echo", description="echo the text back",
                           inputSchema={"type": "object",
                                        "properties": {"text": {"type": "string"}},
                                        "additionalProperties": True})]

    @s.call_tool(validate_input=False)
    async def _ct(name, arguments):
        return [types.TextContent(type="text", text=str((arguments or {}).get("text", "")))]

    return s


def test_remote_mcp_server_sync_bridge():
    remote = RemoteMCPServer("tiny", session_factory=lambda: connect(_tiny_server())).start()
    try:
        assert "echo" in remote.list_tools()
        assert remote.call("echo", {"text": "hello"}).value == "hello"
    finally:
        remote.close()


def test_register_remote_routes_through_gateway(session_path):
    remote = RemoteMCPServer("tiny", session_factory=lambda: connect(_tiny_server())).start()
    try:
        gw = Gateway(enabled=True, auto_label=True, session_path=str(session_path))
        gw.register_remote("tiny", remote, trusted=True, is_egress=False)
        assert "tiny__echo" in {t["name"] for t in gw.list_tools()}
        out = gw.handle_call("tiny", "echo", {"text": "hi there"})
        assert out["ok"] and out["value"] == "hi there"
    finally:
        remote.close()
