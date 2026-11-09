"""Kiểm tra tự động các ca của Bài tập 3 (14 ca bắt buộc và các ca bổ sung) và tính tái hiện của kết quả đã lưu."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import main
from TEST.BT3.cases import DetectionCase, all_detection_cases, required_detection_cases
from TEST.BT3.run_cases import (candidates_trace, case_folder, cli_arguments, evaluate, read_outputs,
                                write_inputs)

ALL_CASES = all_detection_cases()


@pytest.mark.parametrize("case", ALL_CASES, ids=lambda case: case.number)
def test_case_passes(case: DetectionCase, tmp_path: Path) -> None:
    """Chạy từng ca qua hàm main của chương trình rồi đối chiếu mọi giá trị mong đợi."""
    write_inputs(case, tmp_path)
    exit_code = main.main(cli_arguments(case, tmp_path))
    outputs = read_outputs(tmp_path)
    checks = evaluate(case, exit_code, outputs, candidates_trace(case, tmp_path, outputs["events"]))
    failed = [check for check in checks if not check["passed"]]
    assert not failed, json.dumps(failed, ensure_ascii=False, indent=2)


def test_every_case_has_a_saved_result() -> None:
    """Mỗi ca có thư mục kết quả đã lưu đúng chỗ: ca bắt buộc trong TEST/BT3, ca bổ sung trong TEST/extra."""
    assert len(required_detection_cases()) == 14
    assert all((case_folder(case) / "result.json").is_file() for case in ALL_CASES)


@pytest.mark.parametrize("case", ALL_CASES, ids=lambda case: case.name)
def test_saved_outputs_still_reproduce(case: DetectionCase, tmp_path: Path) -> None:
    """Chạy lại đầu vào đã lưu của từng ca và so với các file kết quả đã lưu."""
    folder = case_folder(case)
    arguments = cli_arguments(case, folder)
    for name, value in (("--output", "events.jsonl"), ("--flow-output", "flows.jsonl"),
                        ("--detection-output", "detections.jsonl"), ("--rule-report", "rule_report.json")):
        arguments[arguments.index(name) + 1] = str(tmp_path / value)
    assert main.main(arguments) == 0
    fresh, saved = read_outputs(tmp_path), read_outputs(folder)
    assert fresh["events"] == saved["events"] and fresh["flows"] == saved["flows"]
    assert _without_paths(fresh["detections"]) == _without_paths(saved["detections"])
    assert fresh["report"]["summary"] == saved["report"]["summary"]
    assert fresh["report"]["engine"] == saved["report"]["engine"]


def _without_paths(detections: list[Any]) -> list[Any]:
    """Bỏ đường dẫn file rule, vì đường dẫn phụ thuộc thư mục đang chạy."""
    return [{name: value for name, value in row.items() if name != "rule_file"} for row in detections]
