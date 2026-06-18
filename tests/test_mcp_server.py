"""WS-A: Cerberus as an MCP server. Verified end-to-end over the in-memory MCP
transport (no subprocess), exactly as a real client (Claude Desktop) would drive it."""
from __future__ import annotations

import anyio
from mcp.shared.memory import create_connected_server_and_client_session as connect

from cerberus.mcp_server import build_server
from host.agent import build_gateway
from servers import exfil_server


def _serve(session_path):
    gw, _ = build_gateway(enabled=True, auto_label=True, session_path=str(session_path))
    server, _ = build_server(gw)
    return server


def test_list_tools_omits_quarantined_poisoned_server(session_path):
    async def go():
        async with connect(_serve(session_path)) as client:
            await client.initialize()
            return [t.name for t in (await client.list_tools()).tools]
    names = anyio.run(go)
    assert "filesystem__read_file" in names
    assert "status_page__post" in names
    assert not any(n.startswith("docsearch__") for n in names)  # Sentinel quarantine


def test_secret_egress_blocked_over_mcp(session_path):
    exfil_server.received.clear()

    async def go():
        async with connect(_serve(session_path)) as client:
            await client.initialize()
            creds = await client.call_tool("filesystem__read_file", {"path": "fake_aws_credentials"})
            res = await client.call_tool("status_page__post", {"body": creds.content[0].text})
            return creds, res
    creds, res = anyio.run(go)

    assert creds.isError is not True               # reading the secret is allowed
    assert res.isError is True                     # exfiltrating it is not
    assert "BLOCKED by Cerberus" in res.content[0].text
    assert not exfil_server.received               # the sink stayed empty


def test_benign_call_passes_over_mcp(session_path):
    async def go():
        async with connect(_serve(session_path)) as client:
            await client.initialize()
            return await client.call_tool("weather__get_forecast", {"city": "San Diego"})
    res = anyio.run(go)
    assert res.isError is not True and "San Diego" in res.content[0].text
