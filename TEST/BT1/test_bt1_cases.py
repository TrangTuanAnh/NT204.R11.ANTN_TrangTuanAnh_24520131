"""Kiểm tra 12 ca bắt buộc của Bài tập 1 đã lưu trong TEST/BT1.

Bài tập 1 chỉ có capture và parser, nên mỗi ca chạy với --parse-only. Mỗi ca được kiểm tra hai cách:
giá trị mong đợi trong expected.json phải có trong event, và kết quả chạy lại phải trùng event đã lưu.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import main
from TEST.support.checks import lookup, read_lines, same_value
from TEST.support.paths import BT1_DIR

CASE_FOLDERS = sorted(path.parent for path in BT1_DIR.glob("*/input.pcap"))


def run_parse_only(folder: Path, output: Path) -> int:
    """Chạy main.py ở chế độ của Bài tập 1 trên PCAP của ca và ghi event vào file output."""
    return main.main(["--pcap", str(folder / "input.pcap"), "--output", str(output), "--parse-only"])


def observed(event: dict[str, Any], path: str) -> Any:
    """Giá trị của một trường trong event; "errors_nonempty" nghĩa là danh sách lỗi không rỗng."""
    if path == "errors_nonempty":
        return bool(event["errors"])
    return lookup(event, path)


def test_twelve_required_cases_are_saved() -> None:
    """Đủ 12 ca bắt buộc của đề có thư mục kết quả đã lưu."""
    assert len(CASE_FOLDERS) == 12


@pytest.mark.parametrize("folder", CASE_FOLDERS, ids=lambda folder: folder.name)
def test_expected_values_are_observed(folder: Path, tmp_path: Path) -> None:
    """Mỗi event phải có đúng các giá trị ghi trong expected.json (một mục cho mỗi event, theo thứ tự)."""
    expected = json.loads((folder / "expected.json").read_text(encoding="utf-8"))
    assert run_parse_only(folder, tmp_path / "events.jsonl") == 0
    events = read_lines(tmp_path / "events.jsonl")
    assert len(events) == len(expected)
    wrong = [(index, path, value, observed(event, path))
             for index, (event, wanted) in enumerate(zip(events, expected))
             for path, value in wanted.items() if not same_value(observed(event, path), value)]
    assert not wrong, json.dumps(wrong, ensure_ascii=False, indent=2)


@pytest.mark.parametrize("folder", CASE_FOLDERS, ids=lambda folder: folder.name)
def test_saved_events_still_reproduce(folder: Path, tmp_path: Path) -> None:
    """Chạy lại đầu vào đã lưu và so với events.jsonl đã nộp: đổi code mà làm lệch kết quả cũ thì báo lỗi."""
    assert run_parse_only(folder, tmp_path / "events.jsonl") == 0
    assert read_lines(tmp_path / "events.jsonl") == read_lines(folder / "events.jsonl")
