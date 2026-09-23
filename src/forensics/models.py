"""数据模型与规范化序列化（doc/01 §4 / §6）。

仅包含数据结构与无副作用工具函数，不涉及 IO / 存储逻辑。

确定性约定（doc/01 §5）：
- 全项目 JSON 序列化统一走 ``canonical_json``（键排序、紧凑分隔符、UTF-8），
  保证「同一数据 → 同一字节串 → 同一哈希」。
- 「浮点统一格式化（如 6 位小数）」约定待 W2 引入真实分数后在此集中实施。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

__all__ = ["AnalysisResult", "Finding", "MediaRef", "canonical_json"]


@dataclass
class Finding:
    """单条痕迹 / 规则发现。

    ``type`` 建议使用规则 ID（如 ``"metadata.software_tag"``）；
    ``severity`` 约定取值：``info`` / ``low`` / ``medium`` / ``high``。
    """

    type: str
    severity: str
    detail: dict[str, Any] = field(default_factory=dict)
    artifact_path: str | None = None  # 相对案件目录的工件路径（如热图）

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "detail": self.detail,
            "artifact_path": self.artifact_path,
        }


@dataclass
class MediaRef:
    """被测媒体文件的引用信息（对应 media 表；sha256 为文件完整体哈希）。"""

    path: str
    sha256: str
    size: int
    mime: str
    width: int
    height: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "mime": self.mime,
            "width": self.width,
            "height": self.height,
        }


@dataclass
class AnalysisResult:
    """单个分析器的输出（doc/01 §4）。

    - ``scores``：数值化分数（键为分数名，如 ``"ela_mean"``）
    - ``findings``：规则 / 痕迹列表
    - ``artifacts``：工件索引 ``{"ela_heatmap": "artifacts/ela.png"}``（相对案件目录）
    - ``meta``：参数快照、权重哈希等（不含系统时间）
    """

    scores: dict[str, float] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scores": dict(self.scores),
            "findings": [finding.to_dict() for finding in self.findings],
            "artifacts": dict(self.artifacts),
            "meta": dict(self.meta),
        }


def canonical_json(obj: Any) -> str:
    """规范化 JSON 字符串：键排序 + 紧凑分隔符 + 保留非 ASCII。

    - ``allow_nan=False``：拒绝 NaN / Infinity，保证输出是严格 JSON，
      哈希计算不会因非标准浮点而不可复现。
    """

    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
