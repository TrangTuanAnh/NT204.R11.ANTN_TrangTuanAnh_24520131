"""Kiểm tra tự động các ca bắt buộc T01–T14 của Bài tập 2 và tính tái hiện của kết quả đã lưu trong TEST/BT2."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import main
from TEST.BT2.cases import Case, required_cases
from TEST.BT2.run_cases import (CASES_DIR, active_flows_trace, cli_arguments, evaluate, read_outputs,
                                write_inputs)
from TEST.support.checks import read_lines

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


def test_every_required_case_has_a_saved_result() -> None:
    """Mỗi ca trong cases.py có một thư mục kết quả đã lưu, và không có thư mục nào thừa."""
    assert {folder.name for folder in SAVED_CASE_FOLDERS} == {case.name for case in required_cases()}


@pytest.mark.parametrize("folder", SAVED_CASE_FOLDERS, ids=lambda folder: folder.name)
def test_saved_outputs_still_reproduce(folder: Path, tmp_path: Path) -> None:
    """Chạy lại đầu vào đã lưu của từng ca và so với file kết quả đã lưu."""
    input_path = next(folder.glob("input.*"))
    events_path, flows_path = tmp_path / "events.jsonl", tmp_path / "flows.jsonl"
    source = "--pcap" if input_path.suffix == ".pcap" else "--events"
    assert main.main([source, str(input_path), "--config", str(folder / "config.json"),
                      "--output", str(events_path), "--flow-output", str(flows_path)]) == 0
    assert read_lines(events_path) == read_lines(folder / "events.jsonl")
    assert read_lines(flows_path) == read_lines(folder / "flows.jsonl")
