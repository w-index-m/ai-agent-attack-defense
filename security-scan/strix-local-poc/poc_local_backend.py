#!/usr/bin/env python3
"""PoC: Strix の `local` ランタイムバックエンドが Docker なしで
   セッションを起動し、ホスト上でコマンド実行＋ソース materialize できることを検証する。

LLM 非依存。strix のバックエンド登録と openai-agents SDK の UnixLocalSandbox を使う。

重要な実挙動: SDK の LocalDir 展開は base_dir=Path.cwd() 配下のソースしか許さない。
Strix の正規の使い方 `-t ./`（対象=カレントディレクトリ）では常に満たされる。
本 PoC もその形に合わせ、CWD を対象ワークツリーにして `src="."` 相当を使う。
"""
import asyncio
import os
import shutil
import tempfile
from pathlib import Path

from agents.sandbox.entries import LocalDir
from agents.sandbox.manifest import Environment, Manifest

from strix.runtime.backends import (
    backend_supports_bind_mounts,
    get_backend,
    supported_backends,
)

SRC_REPO = "/home/user/ai-agent-attack-defense"


async def main() -> int:
    print("== 1. backend registry ==")
    print("supported backends:", supported_backends())
    assert "local" in supported_backends(), "local backend not registered"
    backend = get_backend("local")
    print("get_backend('local') ->", backend.__name__)
    print("supports_bind_mounts('local'):", backend_supports_bind_mounts("local"))

    # `-t ./` を再現: 解析対象を CWD 配下に置く(.git やシンボリックリンクは除外)。
    target_parent = tempfile.mkdtemp(prefix="strix-local-target-")
    target = Path(target_parent) / "repo"
    shutil.copytree(
        SRC_REPO, target,
        ignore=shutil.ignore_patterns(".git", "*.pptx"),
        symlinks=False,
    )
    os.chdir(target_parent)  # base_dir = Path.cwd() がこの配下になる
    print("\ncwd (manifest base_dir):", os.getcwd())
    print("target (relative src):   repo")

    workspace = tempfile.mkdtemp(prefix="strix-local-ws-")
    print("\n== 2. bring up session (no docker) ==")
    print("workspace root:", workspace)
    manifest = Manifest(
        root=workspace,
        entries={"repo": LocalDir(src=Path("repo"))},  # CWD 配下 -> grant OK
        environment=Environment(value={"PYTHONUNBUFFERED": "1"}),
    )
    # docker デーモンに触れていないことを示すため DOCKER_HOST を無効値に。
    os.environ["DOCKER_HOST"] = "unix:///nonexistent-docker.sock"

    client, session = await backend(
        image="(ignored-no-container)",
        manifest=manifest,
        exposed_ports=(),
        bind_mounts=None,
    )
    print("session started:", type(session).__name__)

    try:
        print("\n== 3. exec on host (no container) ==")
        for cmd in ("uname -a", "whoami", "python3 --version", "echo DOCKER_HOST=$DOCKER_HOST"):
            r = await session.exec(cmd, timeout=15)
            out = r.stdout.decode("utf-8", "replace").strip()
            print(f"  $ {cmd}\n    -> [exit {r.exit_code}] {out}")

        print("\n== 4. workspace materialization (LocalDir -> <workspace>/repo) ==")
        r = await session.exec("ls -1 repo", timeout=15)
        listing = r.stdout.decode("utf-8", "replace").strip()
        print(f"  $ ls -1 repo  [exit {r.exit_code}]")
        for line in listing.splitlines():
            print("    ", line)
        assert "netcheck" in listing and "scripts" in listing, "source not materialized"

        print("\n== 5. run one of the target's own tools inside the session ==")
        # summarize.py を空ディレクトリに対して動かし、ホスト実行で完走することを確認。
        await session.exec("mkdir -p empty_reports", timeout=10)
        r = await session.exec("python3 repo/scripts/summarize.py empty_reports", timeout=30)
        print(f"  $ python3 repo/scripts/summarize.py empty_reports  [exit {r.exit_code}]")
        print("   ", r.stdout.decode("utf-8", "replace").strip().replace("\n", "\n    "))

        print("\nPoC OK: local backend ran host commands + materialized sources, no Docker.")
        return 0
    finally:
        try:
            await client.delete(session)
        except Exception as e:
            print("cleanup note:", e)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
