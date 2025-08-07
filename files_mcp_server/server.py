from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import TextContent
from unidiff import PatchSet


# ----------------------
# Configuration & Limits
# ----------------------


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


ALLOW_ROOT = Path(os.environ.get("FILES_MCP_ROOT", os.getcwd())).resolve()
MAX_READ_BYTES = env_int("FILES_MCP_MAX_READ_BYTES", 1_048_576)  # 1MB
MAX_RESULTS = env_int("FILES_MCP_MAX_RESULTS", 200)
RG_BIN = os.environ.get("RIPGREP_PATH", "rg")


# ----------------------
# Utilities
# ----------------------


def ensure_within_root(path: Path) -> Path:
    resolved = path.resolve()
    if not str(resolved).startswith(str(ALLOW_ROOT)):
        raise ValueError(f"Path not allowed outside root: {resolved}")
    return resolved


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def run_rg(query: str, globs: Optional[List[str]], cwd: Path) -> List[dict]:
    # Build ripgrep args
    args = [RG_BIN, "--json", "--line-number", "--column", "--no-heading", "--hidden", "--smart-case", query]
    if globs:
        for g in globs:
            args.extend(["--glob", g])
    # Respect .gitignore by default; allow hidden enables dotfiles but still respects ignore unless --no-ignore
    proc = subprocess.run(
        args,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    results: List[dict] = []
    for line in proc.stdout.splitlines():
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if evt.get("type") == "match":
            data = evt.get("data", {})
            path_text = data.get("path", {}).get("text")
            lines = data.get("lines", {}).get("text", "")
            sub = data.get("submatches", [])
            line_num = data.get("line_number")
            # Include a short preview
            preview = lines.rstrip("\n")
            results.append(
                {
                    "path": str(Path(cwd, path_text).resolve()),
                    "line": line_num,
                    "preview": preview,
                    "submatches": [
                        {"start": s.get("start"), "end": s.get("end"), "match": s.get("match", {}).get("text")}
                        for s in sub
                    ],
                }
            )
            if len(results) >= MAX_RESULTS:
                break
    return results


# ----------------------
# Server
# ----------------------


server = FastMCP("files-mcp")


@server.tool()
async def search(query: str, globs: Optional[List[str]] = None) -> List[dict]:
    """Ripgrep-based search within the allowlist root.

    - query: search pattern (literal or regex supported by ripgrep)
    - globs: optional ripgrep --glob patterns to narrow files
    Returns a list of matches: {path, line, preview, submatches[{start, end, match}]}.
    """

    return run_rg(query=query, globs=globs, cwd=ALLOW_ROOT)


@server.tool()
async def read(path: str) -> dict:
    """Read a file's contents with size cap. Returns {path, size, sha256, content}."""

    p = ensure_within_root(ALLOW_ROOT / path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(str(p))
    size = p.stat().st_size
    if size > MAX_READ_BYTES:
        raise ValueError(f"File too large to read entirely: {size} bytes > {MAX_READ_BYTES}")
    data = p.read_bytes()
    return {"path": str(p), "size": size, "sha256": sha256_bytes(data), "content": data.decode("utf-8", "replace")}


@server.tool()
async def write(path: str, content: str, checksum: str) -> dict:
    """Safely write a file. Requires checksum of current content on disk.

    - path: file path relative to allowlist root
    - content: utf-8 text to write
    - checksum: expected sha256 of existing file (use read() first). Use "NEW" to allow creating new file.
    Returns {path, size, sha256}.
    """

    p = ensure_within_root(ALLOW_ROOT / path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        current_hash = sha256_file(p)
        if checksum != current_hash:
            raise ValueError(f"Checksum mismatch. Provided {checksum}, current {current_hash}.")
    else:
        if checksum != "NEW":
            raise ValueError("File does not exist; pass checksum=NEW to create it.")
    data = content.encode("utf-8")
    if len(data) > MAX_READ_BYTES:
        raise ValueError(f"Write too large: {len(data)} > {MAX_READ_BYTES}")
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, p)
    return {"path": str(p), "size": len(data), "sha256": sha256_bytes(data)}


@server.tool()
async def rename(src: str, dest: str) -> dict:
    """Rename or move a file within the allowlist root. Returns {src, dest}."""

    s = ensure_within_root(ALLOW_ROOT / src)
    d = ensure_within_root(ALLOW_ROOT / dest)
    d.parent.mkdir(parents=True, exist_ok=True)
    if not s.exists():
        raise FileNotFoundError(str(s))
    os.replace(s, d)
    return {"src": str(s), "dest": str(d)}


@server.tool()
async def delete(path: str) -> dict:
    """Delete a file within the allowlist root. Returns {path, deleted: bool}."""

    p = ensure_within_root(ALLOW_ROOT / path)
    if not p.exists():
        return {"path": str(p), "deleted": False}
    if p.is_dir():
        raise IsADirectoryError(str(p))
    p.unlink()
    return {"path": str(p), "deleted": True}


@server.tool()
async def preview_refactor(diff: str) -> dict:
    """Validate a unified diff without applying it. Returns a summary of intended changes per file.

    Expects a unified diff (e.g., git diff -U0) and lists files to be modified and counts of additions/deletions.
    """

    try:
        patch = PatchSet(diff)
    except Exception as e:
        raise ValueError(f"Invalid diff: {e}")
    files = []
    for pf in patch:
        # Determine target file path
        target = pf.path or pf.target_file or pf.source_file
        if target is None:
            continue
        # Strip a/ and b/ prefixes commonly used by git
        clean = re.sub(r"^(a/|b/)", "", target)
        abs_path = ensure_within_root(ALLOW_ROOT / clean)
        add = sum(h.added for h in pf)
        rem = sum(h.removed for h in pf)
        files.append({"path": str(abs_path), "hunks": len(pf), "additions": add, "deletions": rem})
        if len(files) >= MAX_RESULTS:
            break
    return {"files": files}


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()


