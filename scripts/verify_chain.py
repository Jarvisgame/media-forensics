#!/usr/bin/env python3
"""哈希链校验脚本（W1 · 2c）。

按案件独立校验：顺序读取链记录并
1) 重算 record_hash 与存储值比对：SHA256(prev_hash + canonical_json(payload))；
2) 检查 prev_hash 与上一条记录首尾相接（案件首条必须为全 0）。

用法（建议在仓库根目录执行）：
    python scripts/verify_chain.py                 # 校验默认案件库 cases/forensics.db
    python scripts/verify_chain.py <数据库路径>
    python scripts/verify_chain.py <数据库路径> --case <案件ID>

退出码：0 = 全部通过；1 = 存在校验失败；2 = 用法 / 数据库错误。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from forensics import store  # noqa: E402（先补 sys.path，再导入项目包）


def _short(hash_value: str, width: int = 12) -> str:
    return hash_value[:width] + "…" if len(hash_value) > width else hash_value


def verify_case(
    conn: sqlite3.Connection, case_id: int
) -> tuple[list[sqlite3.Row], list[str]]:
    """校验单个案件的哈希链；返回（链记录列表, 问题列表）。"""

    rows = store.iter_chain(conn, case_id)
    issues: list[str] = []
    expected_prev = store.GENESIS_PREV_HASH
    for row in rows:
        if row["prev_hash"] != expected_prev:
            issues.append(
                f"记录 #{row['id']}：prev_hash 断链"
                f"（存储 {_short(row['prev_hash'])}，期望 {_short(expected_prev)}）"
            )
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError as exc:
            issues.append(f"记录 #{row['id']}：payload_json 无法解析（{exc}）")
            expected_prev = row["record_hash"]
            continue
        recomputed = store.compute_record_hash(row["prev_hash"], payload)
        if recomputed != row["record_hash"]:
            issues.append(
                f"记录 #{row['id']}：record_hash 不匹配"
                f"（重算 {_short(recomputed)}，存储 {_short(row['record_hash'])}）"
            )
        expected_prev = row["record_hash"]
    return rows, issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="media-forensics 哈希链校验（按案件独立校验）"
    )
    parser.add_argument(
        "db",
        nargs="?",
        default=str(store.DEFAULT_DB_PATH),
        help="案件库路径（默认 cases/forensics.db，在仓库根目录执行）",
    )
    parser.add_argument("--case", type=int, default=None, help="只校验指定案件 id")
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"错误：数据库不存在：{db_path}")
        return 2

    try:
        conn = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        print(f"错误：无法以只读方式打开数据库：{exc}")
        return 2
    conn.row_factory = sqlite3.Row

    try:
        if args.case is not None:
            found = conn.execute("SELECT 1 FROM cases WHERE id = ?", (args.case,)).fetchone()
            if found is None:
                print(f"错误：案件 {args.case} 不存在")
                return 2
            case_ids = [args.case]
        else:
            case_ids = [row["id"] for row in conn.execute("SELECT id FROM cases ORDER BY id")]

        print(f"哈希链校验：{db_path.resolve()}")
        if not case_ids:
            print("提示：数据库中没有案件（空库）")

        failed = 0
        for case_id in case_ids:
            rows, issues = verify_case(conn, case_id)
            if issues:
                failed += 1
                print(f"[案件 {case_id}] 失败：")
                for issue in issues:
                    print(f"  - {issue}")
            elif rows:
                print(
                    f"[案件 {case_id}] 通过"
                    f"（{len(rows)} 条记录，最新记录哈希 {_short(rows[-1]['record_hash'])}）"
                )
            else:
                print(f"[案件 {case_id}] 通过（空链：0 条记录）")

        print(f"总计：{len(case_ids) - failed}/{len(case_ids)} 个案件通过")
        return 1 if failed else 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
