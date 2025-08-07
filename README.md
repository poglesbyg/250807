Project Files + Ripgrep MCP Server

Tools exposed
- search(query, globs?): ripgrep-based code search, returns file/line/preview matches.
- read(path): read file contents with size cap.
- write(path, content, checksum): safe write with SHA256 precondition.
- rename(src, dest): move/rename within allowlist root.
- delete(path): delete with safeguard.
- preview_refactor(diff): validate a unified diff and report what would change.

Safety
- Path allowlist: operations constrained to a configured root (defaults to CWD).
- Size caps: prevent huge reads/writes.
- Checksums: write requires caller-provided checksum of current on-disk content.
- Dry-run previews for diffs; no automatic mass edits.

Setup with uv

1. Install uv: https://docs.astral.sh/uv/
2. Create and sync env:
   uv venv
   uv pip install -e .

Run

uv run files-mcp-server

Claude Desktop config example

Add to claude_desktop_config.json:

{
  "mcpServers": {
    "files-mcp": {
      "command": "/ABS/PATH/to/uv",
      "args": ["run", "files-mcp-server"],
      "env": {"FILES_MCP_ROOT": "/ABS/PATH/TO/YOUR/PROJECT"}
    }
  }
}

Environment variables
- FILES_MCP_ROOT: absolute path allowlist root (default: process CWD).
- FILES_MCP_MAX_READ_BYTES: default 1048576.
- FILES_MCP_MAX_RESULTS: default 200.
- RIPGREP_PATH: optional path to rg binary (default: "rg" on PATH).


