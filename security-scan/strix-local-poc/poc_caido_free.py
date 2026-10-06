#!/usr/bin/env python3
"""PoC2: `local` バックエンドで caido 非依存に session_manager.create_or_reuse が
   完走することを検証する。LLM 非依存。

確認項目:
  - create_or_reuse が caido bootstrap を呼ばずにセッションを返す
  - bundle["caido_client"] is None（proxy ツールは "unavailable" に degrade）
  - セッション内に caido プロキシ env（http_proxy 等）が注入されていない
  - exec がホスト上で動く
"""
import asyncio
import os
import shutil
import tempfile
from pathlib import Path

# backend は env で決まる。import 前に設定。
os.environ["STRIX_RUNTIME_BACKEND"] = "local"
os.environ.setdefault("STRIX_LLM", "anthropic/claude-sonnet-5-5")
os.environ.setdefault("LLM_API_KEY", "dummy-not-used-here")
os.environ["DOCKER_HOST"] = "unix:///nonexistent-docker.sock"

SRC_REPO = "/home/user/ai-agent-attack-defense"


async def main() -> int:
    from strix.config import load_settings
    from strix.runtime import session_manager
    from strix.runtime.backends import backend_supports_caido

    print("backend:", load_settings().runtime.backend)
    print("backend_supports_caido('local'):", backend_supports_caido("local"))
    print("backend_supports_caido('docker'):", backend_supports_caido("docker"))
    assert backend_supports_caido("local") is False
    assert backend_supports_caido("docker") is True

    # `-t ./` 相当: 対象を CWD 配下に。
    parent = tempfile.mkdtemp(prefix="strix-caido-free-")
    shutil.copytree(
        SRC_REPO, Path(parent) / "repo",
        ignore=shutil.ignore_patterns(".git", "*.pptx"), symlinks=False,
    )
    os.chdir(parent)
    local_sources = [{"workspace_subdir": "repo", "source_path": str(Path(parent) / "repo")}]

    scan_id = "poc-caido-free"
    print("\ncalling session_manager.create_or_reuse(backend=local) ...")
    bundle = await session_manager.create_or_reuse(
        scan_id, image="(ignored)", local_sources=local_sources, extra_files=None,
    )
    try:
        print("session:", type(bundle["session"]).__name__)
        print("caido_client:", bundle["caido_client"], "(None = proxy unavailable, expected)")
        assert bundle["caido_client"] is None, "caido should be skipped on local backend"

        session = bundle["session"]
        print("\n== exec on host ==")
        r = await session.exec("echo proxy=[$http_proxy] all=[$ALL_PROXY]", timeout=10)
        out = r.stdout.decode("utf-8", "replace").strip()
        print("  ", out)
        assert "proxy=[]" in out and "all=[]" in out, "caido proxy env must NOT be set"

        r = await session.exec("ls -1 repo | head -3", timeout=10)
        print("  ls repo:", r.stdout.decode("utf-8", "replace").split())

        print("\nPoC2 OK: local backend brought up caido-free; proxy env absent; host exec works.")
        return 0
    finally:
        await session_manager.cleanup(scan_id)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
