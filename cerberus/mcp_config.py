"""
Load servers.yaml and attach the declared external MCP servers to a Gateway.

Each entry is spawned as a stdio subprocess and registered via
``Gateway.register_remote`` so the Sentinel/Tracer/Warden pipeline mediates it.
Used by cerberus/mcp_server.py when the env var ``CERBERUS_SERVERS`` points here.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

import yaml

from .gateway import Gateway
from .labels import WILDCARD, Sensitivity
from .mcp_client import RemoteMCPServer


def load_specs(path: str | Path) -> List[dict]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return data.get("servers", [])


def attach_servers(gw: Gateway, path: str | Path) -> List[RemoteMCPServer]:
    """Spawn + register every server in ``path``. Returns the live RemoteMCPServers
    (call ``.close()`` on each at shutdown)."""
    remotes: List[RemoteMCPServer] = []
    for spec in load_specs(path):
        sens = getattr(Sensitivity, str(spec.get("sensitivity", "PUBLIC")).upper(),
                       Sensitivity.PUBLIC)
        readers = frozenset(spec.get("readers", [WILDCARD]))
        remote = RemoteMCPServer(
            spec["name"], command=spec["command"], args=spec.get("args", []),
            env=spec.get("env"), sensitivity=sens, readers=readers).start()
        gw.register_remote(spec["name"], remote,
                           trusted=bool(spec.get("trusted", False)),
                           is_egress=bool(spec.get("is_egress", False)))
        remotes.append(remote)
    return remotes
