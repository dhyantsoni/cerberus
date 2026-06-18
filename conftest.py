"""Ensure the project root is importable under any pytest invocation.

The installed package list covers cerberus/host/servers, but the top-level
``siem``, ``dashboard``, ``eval``, and ``adversary`` modules are run from the repo
root (``python -m ...``) rather than installed. Putting the root on sys.path here
keeps ``pytest`` (bare or ``python -m pytest``, locally or in CI) able to import them.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
