"""Offline PHP version risk assessor; no exploitation or network requests."""
import json
import re
import sys

FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}


def assess(version: str) -> dict:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version.strip())
    if not match:
        raise ValueError("Expected PHP version MAJOR.MINOR.PATCH (e.g. 8.3.35)")
    major, minor, patch = map(int, match.groups())
    fixed_patch = FIXED.get((major, minor))
    if fixed_patch is None:
        status = "unknown"
        note = "Branch not covered by this table. Consult vendor advisories."
    elif patch < fixed_patch:
        status = "potentially_vulnerable"
        note = f"Update to {major}.{minor}.{fixed_patch} or a vendor-backported fix."
    else:
        status = "fixed_by_upstream_version"
        note = "Upstream fixed-version threshold met; check vendor advisories."
    return {
        "version": version,
        "status": status,
        "note": note,
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "warning": "Version-only heuristic; not proof of exploitability or safety."
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 app.py 8.3.35", file=sys.stderr)
        sys.exit(2)
    try:
        print(json.dumps(assess(sys.argv[1]), ensure_ascii=False, indent=2))
    except ValueError as error:
        print(error, file=sys.stderr)
        sys.exit(2)
