"""A source-pinned release manifest: the SHA-256 of every shipped file, the git commit, and one digest over all.

    python tools/manifest.py -o MANIFEST.sha256.json       # write
    python tools/manifest.py --check MANIFEST.sha256.json  # verify a checkout or an unpacked release

The tree digest is SHA-256 over the sorted "sha256  path" lines, so two people can compare one
value.  The commit pins the source; the per-file hashes let anyone check an unpacked zip without git.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "build", "dist", ".venv", "venv", "node_modules",
             "demo", "cluster", ".mypy_cache"}
SKIP_SUFFIXES = {".pyc", ".db", ".egg-info"}


def files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        listed = [line for line in out.splitlines() if line]
        if listed:
            return sorted(p for p in listed if (ROOT / p).is_file() and p != "MANIFEST.sha256.json")
    except (OSError, subprocess.CalledProcessError):
        pass
    found = []
    for p in ROOT.rglob("*"):
        rel = p.relative_to(ROOT)
        if p.is_file() and not set(rel.parts) & SKIP_DIRS and p.suffix not in SKIP_SUFFIXES \
                and not any(part.endswith(".egg-info") for part in rel.parts) and rel.as_posix() != "MANIFEST.sha256.json":
            found.append(rel.as_posix())
    return sorted(found)


def build() -> dict:
    hashes = {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in files()}
    tree = hashlib.sha256("".join(f"{h}  {f}\n" for f, h in sorted(hashes.items())).encode()).hexdigest()
    commit = dirty = None
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        pass
    sys.path.insert(0, str(ROOT))
    from jurisledger import __version__
    return {"format": "jurisledger/manifest/v1", "version": __version__, "git_commit": commit, "git_dirty": dirty,
            "tree_sha256": tree, "files": hashes}


def main(argv: list[str]) -> int:
    if argv[:1] == ["--check"]:
        want = json.loads(Path(argv[1]).read_text())
        bad = [f for f, h in want["files"].items()
               if not (ROOT / f).is_file() or hashlib.sha256((ROOT / f).read_bytes()).hexdigest() != h]
        print(f"{len(want['files']) - len(bad)} of {len(want['files'])} files match; tree {want['tree_sha256'][:16]}…"
              + (f"\nMISMATCH: {', '.join(bad[:10])}" if bad else ""))
        return 1 if bad else 0
    m = build()
    out = argv[argv.index("-o") + 1] if "-o" in argv else None
    text = json.dumps(m, indent=1, sort_keys=True)
    if out:
        Path(out).write_text(text + "\n")
        print(f"{len(m['files'])} files, tree {m['tree_sha256']}, commit {m['git_commit'] or '(no git)'} -> {out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
