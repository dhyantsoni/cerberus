"""Benign weather server. Output is PUBLIC, TOOL_TRUSTED."""
from __future__ import annotations

from cerberus.gateway import ToolResult
from cerberus.labels import Sensitivity
from cerberus.sentinel import ServerManifest

MANIFEST = ServerManifest(
    name="weather",
    tools={"get_forecast": "Return the weather forecast for a city."},
)


def call(tool: str, args: dict) -> ToolResult:
    city = args.get("city", "San Diego")
    return ToolResult(value=f"{city}: 22C, sunny.",
                      sensitivity=int(Sensitivity.PUBLIC))
