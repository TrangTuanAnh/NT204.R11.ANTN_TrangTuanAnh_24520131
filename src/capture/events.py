"""Đọc event đã lưu trong file JSON Lines, dùng làm nguồn vào thay cho card mạng hoặc PCAP."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO


def iter_events(path: str | Path, max_line_bytes: int) -> Iterator[dict[str, Any]]:
    """Trả lần lượt từng event trong file, mỗi dòng một event.

    Dòng hỏng (không phải JSON, không phải object, sai UTF-8, dài quá giới hạn)
    không làm dừng việc đọc: dòng đó được đổi thành một event có status
    "malformed" kèm lỗi, để Preprocessor đánh dấu rồi đọc tiếp các dòng sau.
    Dòng trống được bỏ qua.
    """
    with Path(path).open("rb") as stream:
        line_number = 0
        while True:
            line = stream.readline(max_line_bytes + 1)
            if not line:
                break
            line_number += 1
            if len(line) > max_line_bytes and not line.endswith(b"\n"):
                _skip_rest_of_line(stream)
                yield _malformed(line_number, f"dài hơn giới hạn {max_line_bytes} byte")
            elif line.strip():
                yield _read_event(line, line_number)


def _read_event(line: bytes, line_number: int) -> dict[str, Any]:
    """Đổi một dòng thành event; dòng không đọc được thì trả event malformed."""
    try:
        # NaN/Infinity không hợp lệ trong JSON chuẩn: giữ ở dạng chữ để Preprocessor báo sai.
        value = json.loads(line.decode("utf-8-sig"), parse_constant=str)
    except UnicodeDecodeError:
        return _malformed(line_number, "không phải chữ UTF-8 hợp lệ")
    except json.JSONDecodeError as exc:
        return _malformed(line_number, f"không phải JSON hợp lệ ({exc.msg})")
    if not isinstance(value, dict):
        return _malformed(line_number, "không phải JSON object")
    return value


def _skip_rest_of_line(stream: BinaryIO) -> None:
    """Đọc bỏ phần còn lại của một dòng quá dài, từng đoạn nhỏ để không tốn bộ nhớ."""
    while True:
        chunk = stream.readline(65536)
        if not chunk or chunk.endswith(b"\n"):
            return


def _malformed(line_number: int, problem: str) -> dict[str, Any]:
    """Tạo event thay thế cho một dòng hỏng."""
    return {"packet_id": None, "status": "malformed", "errors": [f"Dòng {line_number} {problem}"]}
