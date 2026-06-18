"""Shared fixtures: an isolated session log per test + a clean exfil sink."""
from __future__ import annotations

import pytest

from servers import exfil_server


@pytest.fixture
def session_path(tmp_path):
    """A throwaway session.jsonl so receipt chains never bleed between tests."""
    return tmp_path / "session.jsonl"


@pytest.fixture(autouse=True)
def _clear_exfil():
    """Every test starts with an empty attacker collection endpoint."""
    exfil_server.received.clear()
    yield
    exfil_server.received.clear()
