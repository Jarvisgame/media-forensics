"""SQLite 案件库 + 哈希链（doc/01 §6）。

表结构：cases / media / analyses / findings / chain（列名与 doc/01 §6 一致）。

链规则（不可变）：
    record_hash = SHA256(prev_hash + canonical_json(payload))
每个案件独立成链：链首记录（case_created）的 prev_hash 为全 0；
created_at 同时写入 payload 与表列（「时间只进留痕 payload」，doc/01 §4）。

事务约定：
- ``append_case`` / ``append_media`` / ``append_analysis`` 自带事务（``with conn``）；
- ``append_chain_record`` 不自行提交，由调用方控制，
  以保证「行写入 + 链追加」在同一事务内原子完成。
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .models import AnalysisResult, MediaRef, canonical_json

__all__ = [
    "DEFAULT_DB_PATH",
    "GENESIS_PREV_HASH",
    "connect",
    "init_schema",
    "utc_now",
    "compute_record_hash",
    "last_record_hash",
    "append_case",
    "append_media",
    "append_analysis",
    "append_chain_record",
    "iter_chain",
]

DEFAULT_DB_PATH = Path("cases") / "forensics.db"
GENESIS_PREV_HASH = "0" * 64  # 链首记录的 prev_hash

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT    NOT NULL,
    note         TEXT    NOT NULL DEFAULT '',
    code_version TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS media (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id  INTEGER NOT NULL REFERENCES cases(id),
    path     TEXT    NOT NULL,
    sha256   TEXT    NOT NULL,
    size     INTEGER NOT NULL,
    mime     TEXT    NOT NULL,
    width    INTEGER NOT NULL,
    height   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    media_id         INTEGER NOT NULL REFERENCES media(id),
    analyzer         TEXT    NOT NULL,
    analyzer_version TEXT    NOT NULL,
    config_json      TEXT    NOT NULL,
    scores_json      TEXT    NOT NULL,
    created_at       TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id   INTEGER NOT NULL REFERENCES analyses(id),
    type          TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    detail_json   TEXT    NOT NULL,
    artifact_path TEXT
);

CREATE TABLE IF NOT EXISTS chain (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      INTEGER NOT NULL REFERENCES cases(id),
    prev_hash    TEXT    NOT NULL,
    record_hash  TEXT    NOT NULL,
    payload_json TEXT    NOT NULL,
    created_at   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_media_case        ON media(case_id);
CREATE INDEX IF NOT EXISTS idx_analyses_media    ON analyses(media_id);
CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id);
CREATE INDEX IF NOT EXISTS idx_chain_case        ON chain(case_id);
"""


def utc_now() -> str:
    """当前 UTC 时间（秒精度，ISO 8601 带 Z 后缀）。仅用于留痕字段。"""

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """打开（必要时创建）案件库，并确保表结构就绪。"""

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """建表（幂等）。"""

    conn.executescript(_SCHEMA)


def compute_record_hash(prev_hash: str, payload: Mapping[str, Any]) -> str:
    """按链规则计算 record_hash = SHA256(prev_hash + canonical_json(payload))。"""

    data = (prev_hash + canonical_json(payload)).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def last_record_hash(conn: sqlite3.Connection, case_id: int) -> str:
    """案件链上最后一条记录的 record_hash；案件尚无记录时返回全 0。"""

    row = conn.execute(
        "SELECT record_hash FROM chain WHERE case_id = ? ORDER BY id DESC LIMIT 1",
        (case_id,),
    ).fetchone()
    return row["record_hash"] if row is not None else GENESIS_PREV_HASH


def append_chain_record(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    payload: Mapping[str, Any],
    created_at: str | None = None,
) -> str:
    """追加一条链记录并返回 record_hash（不自行提交事务）。

    ``created_at`` 会同时写入 payload 与表列（时间只进留痕 payload）。
    """

    ts = created_at or utc_now()
    full_payload = {**payload, "created_at": ts}
    prev_hash = last_record_hash(conn, case_id)
    record_hash = compute_record_hash(prev_hash, full_payload)
    conn.execute(
        "INSERT INTO chain (case_id, prev_hash, record_hash, payload_json, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (case_id, prev_hash, record_hash, canonical_json(full_payload), ts),
    )
    return record_hash


def append_case(
    conn: sqlite3.Connection,
    *,
    note: str = "",
    code_version: str = "",
    created_at: str | None = None,
) -> int:
    """新建案件，并写入链首记录（kind = "case_created"）。返回案件 id。"""

    ts = created_at or utc_now()
    with conn:
        cur = conn.execute(
            "INSERT INTO cases (created_at, note, code_version) VALUES (?, ?, ?)",
            (ts, note, code_version),
        )
        case_id = cur.lastrowid
        append_chain_record(
            conn,
            case_id=case_id,
            payload={
                "kind": "case_created",
                "case_id": case_id,
                "note": note,
                "code_version": code_version,
            },
            created_at=ts,
        )
    return case_id


def append_media(conn: sqlite3.Connection, *, case_id: int, media: MediaRef) -> int:
    """登记被测媒体文件。返回 media id。"""

    with conn:
        cur = conn.execute(
            "INSERT INTO media (case_id, path, sha256, size, mime, width, height) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                case_id,
                media.path,
                media.sha256,
                media.size,
                media.mime,
                media.width,
                media.height,
            ),
        )
    return cur.lastrowid


def append_analysis(
    conn: sqlite3.Connection,
    *,
    media_id: int,
    analyzer: str,
    analyzer_version: str,
    config: Mapping[str, Any] | None,
    result: AnalysisResult,
    created_at: str | None = None,
) -> int:
    """写入一次分析（analyses + findings 行）并追加链记录。返回 analysis id。

    链 payload 自包含该次分析的完整内容（媒体哈希、配置、分数、findings、工件索引），
    与库内行数据相互印证；case_id 由 media_id 反查，避免调用方传错。
    """

    ts = created_at or utc_now()
    config_obj = dict(config) if config else {}
    with conn:
        media_row = conn.execute(
            "SELECT case_id, sha256 FROM media WHERE id = ?", (media_id,)
        ).fetchone()
        if media_row is None:
            raise ValueError(f"media_id={media_id} 不存在，无法写入分析记录")

        cur = conn.execute(
            "INSERT INTO analyses "
            "(media_id, analyzer, analyzer_version, config_json, scores_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                media_id,
                analyzer,
                analyzer_version,
                canonical_json(config_obj),
                canonical_json(result.scores),
                ts,
            ),
        )
        analysis_id = cur.lastrowid
        for finding in result.findings:
            conn.execute(
                "INSERT INTO findings "
                "(analysis_id, type, severity, detail_json, artifact_path) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    analysis_id,
                    finding.type,
                    finding.severity,
                    canonical_json(finding.detail),
                    finding.artifact_path,
                ),
            )
        append_chain_record(
            conn,
            case_id=media_row["case_id"],
            payload={
                "kind": "analysis",
                "case_id": media_row["case_id"],
                "media_id": media_id,
                "media_sha256": media_row["sha256"],
                "analysis_id": analysis_id,
                "analyzer": analyzer,
                "analyzer_version": analyzer_version,
                "config": config_obj,
                "scores": dict(result.scores),
                "findings": [finding.to_dict() for finding in result.findings],
                "artifacts": dict(result.artifacts),
                "meta": dict(result.meta),
            },
            created_at=ts,
        )
    return analysis_id


def iter_chain(conn: sqlite3.Connection, case_id: int) -> list[sqlite3.Row]:
    """按写入顺序（id 升序）返回某案件的全部链记录。"""

    return conn.execute(
        "SELECT id, prev_hash, record_hash, payload_json, created_at "
        "FROM chain WHERE case_id = ? ORDER BY id",
        (case_id,),
    ).fetchall()
