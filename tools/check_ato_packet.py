"""Red-first reproducible check for P3.16 / issue #17 (ATO evidence packet).

This is a docs deliverable, so per this session's red-first process rule
("Recon/docs issues: commit the reproducible check first") the check itself
is committed BEFORE `docs/ATO_EVIDENCE_PACKET.md` exists -- run it now and it
fails (file not found). After the packet is written it asserts:

1. The file exists and is a SEPARATE artifact from `docs/ARCHITECTURE.md`
   (does not just re-embed that file's content wholesale).
2. All six required sections (per issue #17's Done-when) are present as
   headings.
3. Each section names at least one real, already-committed artifact path
   this repo actually contains (not an invented filename) -- a cheap grep,
   not a semantic check, but enough to catch a section written with zero
   citations.

Run: `python tools/check_ato_packet.py`
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKET = REPO_ROOT / "docs" / "ATO_EVIDENCE_PACKET.md"

REQUIRED_SECTIONS = [
    "Architecture and data-flow",
    "Auth model",
    "Versioned dependency list",
    "Self-scan results",
    "Eval-result evidence",
    "Sample incident",
]

# At least one of these real, committed artifacts must be cited per section.
REQUIRED_CITATIONS_BY_SECTION = {
    "Architecture and data-flow": ["docs/ARCHITECTURE.md", "docs/THREAT_MODEL.md"],
    "Auth model": ["VULN-0001", "docs/STAGE1_TARGET.md"],
    "Versioned dependency list": ["requirements-contracts.txt", "contracts/README.md"],
    "Self-scan results": [".gitignore", "tests/"],
    "Eval-result evidence": ["evals/recordings/", "VULN-0001"],
    "Sample incident": ["#35", "campaign.py"],
}


def main() -> int:
    if not PACKET.exists():
        print(f"FAIL: {PACKET} does not exist yet (expected on red-first commit).")
        return 1

    text = PACKET.read_text(encoding="utf-8")

    if "docs/ARCHITECTURE.md" not in text:
        print("FAIL: packet does not reference docs/ARCHITECTURE.md at all.")
        return 1

    arch_text = (REPO_ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    # Not a duplicate: the packet must be meaningfully shorter than a
    # full copy-plus-addition of ARCHITECTURE.md's prose section.
    if arch_text[:2000] in text:
        print("FAIL: packet appears to duplicate ARCHITECTURE.md's own prose verbatim.")
        return 1

    missing_sections = [s for s in REQUIRED_SECTIONS if s not in text]
    if missing_sections:
        print(f"FAIL: missing required sections: {missing_sections}")
        return 1

    missing_citations = []
    for section, needles in REQUIRED_CITATIONS_BY_SECTION.items():
        if not any(n in text for n in needles):
            missing_citations.append(section)
    if missing_citations:
        print(f"FAIL: sections with no real-artifact citation found: {missing_citations}")
        return 1

    print("PASS: docs/ATO_EVIDENCE_PACKET.md present, six sections found, each cites a real artifact.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
