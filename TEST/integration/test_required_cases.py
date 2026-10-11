"""Kiểm tra tự động các ca bắt buộc và tính tái hiện của kết quả đã lưu trong required_cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import main
from TEST.integration.cases import Case, required_cases
from TEST.integration.run_required_cases import (CASES_DIR, active_flows_trace, cli_arguments, evaluate,
                                                 read_outputs, write_inputs)

SAVED_CASE_FOLDERS = sorted(path.parent for path in CASES_DIR.glob("*/input.*"))


@pytest.mark.parametrize("case", required_cases(), ids=lambda case: case.case_id)
def test_required_case_passes(case: Case, tmp_path: Path) -> None:
    """Chạy ca T01–T14 qua hàm main của chương trình rồi đối chiếu mọi giá trị mong đợi."""
    write_inputs(case, tmp_path)
    exit_code = main.main(cli_arguments(case, tmp_path))
    events, flows = read_outputs(tmp_path)
    checks = evaluate(case, exit_code, events, flows, active_flows_trace(case, tmp_path))
    failed = [check for check in checks if not check["passed"]]
    assert not failed, json.dumps(failed, ensure_ascii=False, indent=2)


@pytest.mark.parametrize("folder", SAVED_CASE_FOLDERS, ids=lambda folder: folder.name)
def test_saved_outputs_still_reproduce(folder: Path, tmp_path: Path) -> None:
    """Chạy lại đầu vào đã lưu của từng ca và so với file kết quả đã lưu.

    Ca có config.json là ca của Bài tập 2, chạy đủ pipeline. Ca không có
    config.json là ca của Bài tập 1, chạy với --parse-only như lúc tạo kết quả.
    """
    input_path = next(folder.glob("input.*"))
    events_path, flows_path = tmp_path / "events.jsonl", tmp_path / "flows.jsonl"
    source = "--pcap" if input_path.suffix == ".pcap" else "--events"
    arguments = [source, str(input_path), "--output", str(events_path), "--flow-output", str(flows_path)]
    config_path = folder / "config.json"
    arguments += ["--config", str(config_path)] if config_path.exists() else ["--parse-only"]
    assert main.main(arguments) == 0
    assert _rows(events_path) == _rows(folder / "events.jsonl")
    if config_path.exists():
        assert _rows(flows_path) == _rows(folder / "flows.jsonl")


def _rows(path: Path) -> list[Any]:
    """Đọc file JSON Lines thành danh sách để so sánh, không phụ thuộc kiểu xuống dòng."""
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
