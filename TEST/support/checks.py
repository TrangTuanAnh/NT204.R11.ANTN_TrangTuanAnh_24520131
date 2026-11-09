"""Đọc, ghi và đối chiếu kết quả của các ca kiểm thử."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

MISSING = "<không có>"  # giá trị thay thế khi đường dẫn trường không tồn tại trong kết quả


def lookup(data: Any, path: str) -> Any:
    """Lấy giá trị theo đường dẫn như "events.0.decoded.uri"; không có thì trả MISSING.

    Số trong đường dẫn là chỉ số khi giá trị đang xét là danh sách.
    """
    value = data
    for part in path.split("."):
        try:
            value = value[int(part)] if isinstance(value, list) else value[part]
        except (KeyError, IndexError, TypeError, ValueError):
            return MISSING
    return value


def same_value(actual: Any, expected: Any) -> bool:
    """So sánh hai giá trị JSON; số thực được coi là bằng nhau nếu lệch dưới một phần triệu."""
    if isinstance(expected, float) and isinstance(actual, (int, float)) and not isinstance(actual, bool):
        return math.isclose(actual, expected, rel_tol=0, abs_tol=1e-6)
    if isinstance(expected, list) and isinstance(actual, list):
        return len(actual) == len(expected) and all(map(same_value, actual, expected))
    if isinstance(expected, dict) and isinstance(actual, dict):
        return actual.keys() == expected.keys() and all(same_value(actual[k], expected[k]) for k in expected)
    return type(actual) is type(expected) and actual == expected


def write_json(path: Path, data: Any) -> None:
    """Ghi JSON dễ đọc (thụt lề, giữ nguyên chữ tiếng Việt)."""
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_lines(path: Path) -> list[Any]:
    """Đọc file JSON Lines; file chưa có thì trả danh sách rỗng."""
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def markdown_value(value: Any) -> str:
    """Viết giá trị JSON vào ô bảng Markdown."""
    text = json.dumps(value, ensure_ascii=False)
    return "`" + text.replace("|", "\\|").replace("`", "'") + "`"
