"""Zone-B agents (docs/ARCHITECTURE.md §3) that are pure logic modules, not
long-running processes: no probe generation (Red Team, Zone A), no
independent scoring (Judge), no directive planning (Orchestrator) lives
here. Currently: the Documentation Agent (P3.9, ``documentation.py``).
"""

from __future__ import annotations
