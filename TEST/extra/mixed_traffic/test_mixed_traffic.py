"""Kiểm tra tự động các bộ traffic lớn.

Hai việc chính: kết quả của chương trình phải khớp kết quả mong đợi được tính độc lập từ các gói Scapy,
và kết quả đã lưu trong repo phải còn tái hiện được. Ngoài ra kiểm tra bản thân bộ traffic còn đủ lớn,
đủ đa dạng và sinh ra lặp lại được.
"""

from __future__ import annotations

import functools
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import main
from TEST.extra.mixed_traffic.run_scenarios import (CASES_DIR, cli_arguments, compare_flows, detections_by_packet,
                                                    evaluate, read_outputs, write_inputs)
from TEST.extra.mixed_traffic.scenarios import SCENARIOS, Scenario
from TEST.support.checks import read_lines

NAMES = sorted(SCENARIOS)


def fingerprint(scenario: Scenario) -> str:
    """Mã băm của mọi gói (nội dung và thời điểm) theo đúng thứ tự, để biết hai lần sinh có giống nhau không."""
    digest = hashlib.sha256()
    for packet in scenario.packets:
        digest.update(bytes(packet) + repr(round(float(packet.time), 6)).encode())
    return digest.hexdigest()


@functools.lru_cache(maxsize=None)
def built(name: str) -> tuple[Scenario, dict[str, Any], str]:
    """Bộ traffic, kết quả mong đợi và mã băm của nó; dựng một lần rồi dùng chung cho mọi test vì dựng khá lâu."""
    scenario = SCENARIOS[name]()
    return scenario, scenario.expected(), fingerprint(scenario)


@pytest.mark.parametrize("name", NAMES)
def test_program_output_matches_independent_expectation(name: str, tmp_path: Path) -> None:
    """Chạy bộ traffic qua hàm main và đối chiếu từng flow, từng Detection Event với kết quả mong đợi."""
    scenario, expected, _ = built(name)
    write_inputs(scenario, expected, tmp_path)
    exit_code = main.main(cli_arguments(tmp_path, tmp_path / "events.jsonl"))
    checks, problems = evaluate(expected, exit_code, read_outputs(tmp_path, tmp_path / "events.jsonl"))
    failed = [check for check in checks if not check["passed"]]
    assert not failed, json.dumps({"checks": failed, "flows": problems[:5]}, ensure_ascii=False, indent=2)


@pytest.mark.parametrize("name", NAMES)
def test_traffic_is_large_and_varied(name: str) -> None:
    """Mỗi bộ có khoảng 2.000 gói, nhiều flow, nhiều loại phiên và có cả gói chương trình chưa hỗ trợ hoặc tấn công."""
    scenario, expected, _ = built(name)
    assert 1800 <= len(scenario.packets) <= 2300
    assert len(expected["flows"]) >= 200
    assert len({flow["kind"] for flow in expected["flows"]}) >= 5
    assert expected["detections"]["total"] >= 50
    assert set(expected["detections"]["by_sid"]) == {str(rule.sid) for rule in scenario.rules}  # rule nào cũng khớp


@pytest.mark.parametrize("name", NAMES)
def test_traffic_exercises_every_way_a_flow_can_end(name: str) -> None:
    """Có đủ flow đóng bằng FIN, bị RST, hết hạn và còn mở lúc hết dữ liệu.

    Riêng flow TCP không tự đóng phải có cả hai kiểu hết hạn và còn mở, nếu không bộ traffic
    không phân biệt được thời gian chờ TCP đặt sai.
    """
    _, expected, _ = built(name)
    reasons = {flow["end_reason"] for flow in expected["flows"]}
    assert {"tcp_closed", "tcp_reset", "idle_timeout", "end_of_input"} <= reasons
    open_tcp = {flow["end_reason"] for flow in expected["flows"]
                if flow["protocol"] == "TCP" and flow["end_reason"] in ("idle_timeout", "end_of_input")}
    assert open_tcp == {"idle_timeout", "end_of_input"}


@pytest.mark.parametrize("name", NAMES)
def test_generation_is_repeatable(name: str) -> None:
    """Dựng lại một lần nữa phải ra đúng cùng một dãy gói và cùng kết quả mong đợi."""
    _, expected, digest = built(name)
    again = SCENARIOS[name]()
    assert fingerprint(again) == digest
    assert again.expected() == expected


@pytest.mark.parametrize("name", NAMES)
def test_saved_results_agree_with_saved_expectation(name: str) -> None:
    """Kết quả đã lưu (flows.jsonl, detections.jsonl) phải khớp expected.json đã lưu, không cần sinh lại traffic."""
    folder = CASES_DIR / name
    expected = json.loads((folder / "expected.json").read_text(encoding="utf-8"))
    assert compare_flows(expected["flows"], read_lines(folder / "flows.jsonl")) == []
    assert detections_by_packet(read_lines(folder / "detections.jsonl")) == expected["detections"]["by_packet"]
    assert json.loads((folder / "result.json").read_text(encoding="utf-8"))["passed"] is True


@pytest.mark.parametrize("name", NAMES)
def test_saved_input_still_reproduces(name: str, tmp_path: Path) -> None:
    """Chạy lại PCAP và rule đã lưu và so với kết quả đã lưu: đổi code làm lệch kết quả cũ thì báo lỗi."""
    folder = CASES_DIR / name
    arguments = cli_arguments(folder, tmp_path / "events.jsonl")
    for option, value in (("--flow-output", "flows.jsonl"), ("--detection-output", "detections.jsonl"),
                          ("--rule-report", "rule_report.json")):
        arguments[arguments.index(option) + 1] = str(tmp_path / value)
    assert main.main(arguments) == 0
    assert read_lines(tmp_path / "flows.jsonl") == read_lines(folder / "flows.jsonl")
    assert _without_paths(read_lines(tmp_path / "detections.jsonl")) == _without_paths(
        read_lines(folder / "detections.jsonl"))
    fresh = json.loads((tmp_path / "rule_report.json").read_text(encoding="utf-8"))
    saved = json.loads((folder / "rule_report.json").read_text(encoding="utf-8"))
    assert fresh["summary"] == saved["summary"] and fresh["engine"] == saved["engine"]


def _without_paths(detections: list[Any]) -> list[Any]:
    """Bỏ đường dẫn file rule, vì đường dẫn phụ thuộc thư mục đang chạy."""
    return [{name: value for name, value in row.items() if name != "rule_file"} for row in detections]
