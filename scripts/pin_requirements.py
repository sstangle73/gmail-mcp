"""Write requirements.txt from requirements.in, with the sha256 of every file PyPI has for each pinned version.

    python scripts/pin_requirements.py

requirements.in lists every package the Lambda needs, each pinned as name==version (the direct dependencies, mcp
and uvicorn, and everything they need). pip then installs with --require-hashes, so a file that changed on PyPI, or
a mirror that serves something else, fails the build instead of reaching a server that reads mail. Hashes come from
PyPI's JSON API for exactly that version: every wheel and the sdist, so the same file works for the Lambda's Linux
arm64 build and for a local install.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def hashes(name: str, version: str) -> list[str]:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "gmail-mcp pin"}), timeout=30) as r:
        doc = json.load(r)
    got = sorted({f["digests"]["sha256"] for f in doc.get("urls") or [] if not f.get("yanked")})
    if not got:
        sys.exit(f"PyPI has no files for {name}=={version}")
    return got


def main() -> None:
    src = (ROOT / "requirements.in").read_text(encoding="utf-8").splitlines()
    out = ["# Written by scripts/pin_requirements.py from requirements.in: edit that, then run it again.",
           "# pip installs these with --require-hashes (deploy.py does), so every file is checked against its sha256."]
    for line in src:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)", s)
        if not m:
            sys.exit(f"requirements.in: {s!r} isn't name==version")
        hs = hashes(*m.groups())
        out.append(f"{s} \\")
        out += [f"    --hash=sha256:{h} \\" for h in hs[:-1]] + [f"    --hash=sha256:{hs[-1]}"]
        print(f"{s}: {len(hs)} file(s)")
    (ROOT / "requirements.txt").write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
