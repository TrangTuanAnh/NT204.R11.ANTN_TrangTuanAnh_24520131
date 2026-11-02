"""Kiểm tra tự động các ca bắt buộc của Core Engine và tính tái hiện của kết quả đã lưu trong TEST/BT3."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import main
from TEST.integration.detection_cases import DetectionCase, required_detection_cases
from TEST.integration.run_detection_cases import (CASES_DIR, candidates_trace, cli_arguments, evaluate, read_outputs,
                                                  write_inputs)

CASES_BY_NAME = {case.name: case for case in required_detection_cases()}
SAVED_CASE_FOLDERS = sorted(path.parent for path in CASES_DIR.glob("*/result.json"))


@pytest.mark.parametrize("case", required_detection_cases(), ids=lambda case: case.number)
def test_required_case_passes(case: DetectionCase, tmp_path: Path) -> None:
    """Chạy từng ca qua hàm main của chương trình rồi đối chiếu mọi giá trị mong đợi."""
    write_inputs(case, tmp_path)
    exit_code = main.main(cli_arguments(case, tmp_path))
    outputs = read_outputs(tmp_path)
    checks = evaluate(case, exit_code, outputs, candidates_trace(case, tmp_path, outputs["events"]))
    failed = [check for check in checks if not check["passed"]]
    assert not failed, json.dumps(failed, ensure_ascii=False, indent=2)


@pytest.mark.parametrize("folder", SAVED_CASE_FOLDERS, ids=lambda folder: folder.name)
def test_saved_outputs_still_reproduce(folder: Path, tmp_path: Path) -> None:
    """Chạy lại đầu vào đã lưu của từng ca và so với các file kết quả đã lưu."""
    case = CASES_BY_NAME[folder.name]
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
