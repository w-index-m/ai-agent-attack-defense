#!/usr/bin/env python3
"""container_privilege_check: コンテナランタイムのイベントログを読み、R2(特権cap/host
ネットのコンテナ起動)相当のパターンを確認する(確認専用、読み取りのみ)。

背景:
  - `security-scan/detections/sigma/r2_privileged_container_spawn.yml`は、「NET_RAW/NET_ADMIN
    ケイパビリティ付与、privileged実行、またはhostネットワーク名前空間への参加」という、
    Cairnスタイルのワーカーコンテナに典型的なパターンを検知対象にしている。
  - `verification-gates.md`の棚卸しで見つかったギャップの1つ。Falcoがより自然な一次情報源
    だが(ルール自体に"Falco is usually the better native source"と明記)、Dockerの
    コンテナイベントログ(`docker events --format '{{json .}}'`等)を直接読む版も作成した。

対応するログ形式:
  - JSON Lines形式。各行は1つのコンテナ起動イベント。`image`/`container_name`の
    いずれかと、`capabilities`(リスト、または文字列)・`privileged`(真偽値)・
    `network_mode`のいずれかを認識する。

安全のための制限:
  - **ログファイルを読むだけ**。コンテナの起動・停止、Dockerへの接続は一切しない。

使用例:
  python3 scripts/container_privilege_check.py --log-path container_events.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

# r2_privileged_container_spawn.yml の selection_caps.capabilities|contains と完全に同じ
# (大文字小文字は無視してcontains判定する)。
R2_PRIVILEGED_CAPS = ("cap_net_raw", "cap_net_admin")


@dataclass
class ContainerEvent:
    image: str
    container_name: str
    capabilities: list[str]
    privileged: bool
    network_mode: str


def parse_jsonl_line(line: str) -> ContainerEvent | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    image = obj.get("image") or obj.get("Image") or ""
    container_name = obj.get("container_name") or obj.get("Name") or ""
    if not image and not container_name:
        return None

    caps_raw = obj.get("capabilities") or obj.get("CapAdd") or []
    if isinstance(caps_raw, str):
        caps = [caps_raw]
    elif isinstance(caps_raw, list):
        caps = [str(c) for c in caps_raw]
    else:
        caps = []

    privileged = bool(obj.get("privileged") or obj.get("Privileged") or False)
    network_mode = str(obj.get("network_mode") or obj.get("NetworkMode") or "")

    return ContainerEvent(str(image), str(container_name), caps, privileged, network_mode)


def _matches_r2(ev: ContainerEvent) -> str | None:
    caps_joined = " ".join(ev.capabilities).lower()
    hit_caps = [c for c in R2_PRIVILEGED_CAPS if c in caps_joined]
    if hit_caps:
        return "特権ケイパビリティ付与(%s)" % ", ".join(hit_caps)
    if ev.privileged:
        return "privileged実行"
    if ev.network_mode.lower() == "host":
        return "hostネットワーク名前空間への参加"
    return None


def scan_log(log_path: str) -> tuple[list[tuple[ContainerEvent, str]], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return [], 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    hits: list[tuple[ContainerEvent, str]] = []
    for line in lines:
        ev = parse_jsonl_line(line)
        if not ev:
            continue
        reason = _matches_r2(ev)
        if reason:
            hits.append((ev, reason))

    return hits, len(lines), None


def print_report(hits: list[tuple[ContainerEvent, str]], total_lines: int, log_path: str) -> None:
    print("対象ログ: %s (%d行)" % (log_path, total_lines))
    print("-" * 60)
    if not hits:
        print("R2(特権cap/hostネットのコンテナ起動)相当のパターンは見つかりませんでした。")
        return

    print("%d 件のコンテナ起動でR2相当のパターンが見つかりました:\n" % len(hits))
    for ev, reason in hits:
        name = ev.container_name or ev.image
        print("  [R2] %s (image=%s): %s" % (name, ev.image, reason))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="コンテナランタイムのイベントログ(JSON Lines)")
    args = parser.parse_args()

    hits, total_lines, err = scan_log(args.log_path)
    if err:
        print(err, file=sys.stderr)
        return 2

    print_report(hits, total_lines, args.log_path)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
