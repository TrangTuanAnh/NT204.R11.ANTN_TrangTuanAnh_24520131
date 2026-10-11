"""Tạo đầu vào, chạy main.py và lưu kết quả đối chiếu của các ca kiểm thử T01–T14.

Chạy tại thư mục gốc repo:
    python TEST/integration/run_required_cases.py              # chạy cả 14 ca
    python TEST/integration/run_required_cases.py --case T07   # chỉ chạy một ca
Thư mục kết quả đã có thì không bị ghi đè, trừ khi thêm --overwrite.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))  # để import được src và TEST khi chạy file này trực tiếp

import scapy  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from src.capture.events import iter_events  # noqa: E402
from src.capture.pcap import iter_pcap  # noqa: E402
from src.config import Config  # noqa: E402
from src.pipeline import Pipeline  # noqa: E402
from TEST.integration.cases import Case, required_cases  # noqa: E402

CASES_DIR = REPO_ROOT / "TEST" / "integration" / "required_cases"
MISSING = "<không có>"  # giá trị thay thế khi đường dẫn trường không tồn tại trong kết quả


def write_inputs(case: Case, folder: Path) -> None:
    """Ghi file đầu vào, cấu hình và các giá trị mong đợi của ca vào thư mục."""
    folder.mkdir(parents=True, exist_ok=True)
    if case.packets:
        wrpcap(str(folder / "input.pcap"), case.packets)
    else:
        (folder / "input.jsonl").write_text("\n".join(case.event_lines) + "\n", encoding="utf-8")
    _write_json(folder / "config.json", asdict(Config(**case.config)))
    _write_json(folder / "expected.json", {
        "id": case.case_id, "case": case.name, "requirement": case.requirement,
        "checks": case.checks, "same_flow": case.same_flow, "different_flow": case.different_flow,
    })


def cli_arguments(case: Case, folder: Path) -> list[str]:
    """Tham số dòng lệnh của main.py để chạy ca với các file trong thư mục cho trước."""
    source = "--pcap" if case.packets else "--events"
    return [source, str(folder / case.input_name), "--config", str(folder / "config.json"),
            "--output", str(folder / "events.jsonl"), "--flow-output", str(folder / "flows.jsonl")]


def read_outputs(folder: Path) -> tuple[list[Any], list[Any]]:
    """Đọc event và tổng kết flow mà main.py đã ghi ra."""
    return _read_lines(folder / "events.jsonl"), _read_lines(folder / "flows.jsonl")


def active_flows_trace(case: Case, folder: Path) -> list[int]:
    """Chạy lại pipeline ngay trong chương trình để đếm số flow trong bảng sau từng đầu vào.

    Số này không có trong file đầu ra nên phải hỏi trực tiếp Flow Tracker.
    """
    config = Config(**case.config)
    pipeline = Pipeline(config)
    trace = []
    if case.packets:
        for packet_id, (packet, timestamp) in enumerate(iter_pcap(folder / "input.pcap"), start=1):
            pipeline.process_packet(packet, packet_id, timestamp, "pcap")
            trace.append(pipeline.tracker.active_count)
    else:
        for event in iter_events(folder / "input.jsonl", config.max_event_bytes):
            pipeline.process_event(event)
            trace.append(pipeline.tracker.active_count)
    return trace


def evaluate(case: Case, exit_code: int, events: list[Any], flows: list[Any],
             trace: list[int]) -> list[dict[str, Any]]:
    """So từng giá trị mong đợi với kết quả thực tế; trả danh sách các phép so sánh."""
    data = {"exit_code": exit_code, "event_count": len(events), "flow_count": len(flows),
            "events": events, "flows": flows, "active_flows_trace": trace}
    checks = []
    for path, expected in case.checks.items():
        actual = lookup(data, path)
        checks.append({"field": path, "expected": expected, "actual": actual,
                       "passed": same_value(actual, expected)})
    for group in case.same_flow:
        ids = [lookup(data, f"events.{index}.flow_id") for index in group]
        checks.append({"field": f"same_flow {group}", "expected": "cùng một flow_id",
                       "actual": ids, "passed": _all_known(ids) and len(set(ids)) == 1})
    for group in case.different_flow:
        ids = [lookup(data, f"events.{index}.flow_id") for index in group]
        checks.append({"field": f"different_flow {group}", "expected": "các flow_id khác nhau",
                       "actual": ids, "passed": _all_known(ids) and len(set(ids)) == len(ids)})
    return checks


def lookup(data: dict[str, Any], path: str) -> Any:
    """Lấy giá trị theo đường dẫn như "events.0.decoded.uri" hoặc "flow_of_event.2.state"."""
    parts = path.split(".")
    value: Any = data
    if parts[0] == "flow_of_event":
        flow_id = lookup(data, f"events.{parts[1]}.flow_id")
        matches = [flow for flow in data["flows"] if flow_id not in (None, MISSING) and flow["flow_id"] == flow_id]
        if not matches:
            return MISSING
        value, parts = matches[0], parts[2:]
    for part in parts:
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


def run_case(case: Case, folder: Path) -> dict[str, Any]:
    """Chạy trọn một ca qua main.py bằng một tiến trình riêng và lưu kết quả."""
    write_inputs(case, folder)
    process = subprocess.run([sys.executable, "main.py", *cli_arguments(case, folder)], cwd=REPO_ROOT,
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    events, flows = read_outputs(folder)
    checks = evaluate(case, process.returncode, events, flows, active_flows_trace(case, folder))
    passed = sum(check["passed"] for check in checks)
    result = {
        "id": case.case_id,
        "case": case.name,
        "requirement": case.requirement,
        "run_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "scapy": scapy.__version__,
        "input_sha256": hashlib.sha256((folder / case.input_name).read_bytes()).hexdigest(),
        "command": _display_command(case, folder),
        "exit_code": process.returncode,
        "passed": passed == len(checks),
        "passed_checks": passed,
        "total_checks": len(checks),
        "event_count": len(events),
        "flow_count": len(flows),
        "checks": checks,
    }
    _write_json(folder / "result.json", result)
    (folder / "README.md").write_text(_readme(case, folder, result), encoding="utf-8")
    return result


def main() -> int:
    """Chọn ca cần chạy, chạy lần lượt và in kết quả tóm tắt."""
    parser = argparse.ArgumentParser(description="Chay cac ca kiem thu T01-T14 va luu ket qua")
    parser.add_argument("--case", help="Ma ca (vi du T07) hoac ten thu muc cua ca")
    parser.add_argument("--output-root", type=Path, default=CASES_DIR, help="Thu muc chua ket qua cac ca")
    parser.add_argument("--overwrite", action="store_true", help="Xoa ket qua cu cua ca truoc khi chay lai")
    args = parser.parse_args()
    cases = [case for case in required_cases() if args.case in (None, case.case_id, case.name)]
    if not cases:
        parser.error("Khong tim thay ca kiem thu")
    root = args.output_root.resolve()
    if not root.is_relative_to(REPO_ROOT):
        parser.error("Thu muc ket qua phai nam trong repo de lenh chay lai dung duong dan tuong doi")
    for case in cases:
        folder = root / case.name
        if folder.exists() and not args.overwrite:
            parser.error(f"Da co ket qua cua {case.case_id}; them --overwrite de chay lai")
    results = []
    for case in cases:
        folder = root / case.name
        if folder.exists():
            shutil.rmtree(folder)  # main.py ghi nối tiếp nên phải xóa kết quả cũ trước
        results.append(run_case(case, folder))
    for result in results:
        verdict = "PASS" if result["passed"] else "FAIL"
        print(f"{result['id']} {result['case']} {verdict} ({result['passed_checks']}/{result['total_checks']})")
    print(f"Passed {sum(r['passed'] for r in results)}/{len(results)}")
    return 0 if all(result["passed"] for result in results) else 1


def _all_known(values: list[Any]) -> bool:
    """Mọi giá trị đều có thật (không null, không thiếu)."""
    return all(value not in (None, MISSING) for value in values)


def _write_json(path: Path, data: Any) -> None:
    """Ghi JSON dễ đọc (thụt lề, giữ nguyên chữ tiếng Việt)."""
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _read_lines(path: Path) -> list[Any]:
    """Đọc file JSON Lines; file chưa có thì trả danh sách rỗng."""
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _display_command(case: Case, folder: Path) -> str:
    """Lệnh chạy lại ca, dùng đường dẫn tương đối từ gốc repo và tên output mới."""
    relative = folder.relative_to(REPO_ROOT).as_posix()
    source = "--pcap" if case.packets else "--events"
    prefix = case.name.split("_")[0]
    return (f"python main.py {source} {relative}/{case.input_name} --config {relative}/config.json "
            f"--output output/{prefix}_events.jsonl --flow-output output/{prefix}_flows.jsonl")


def _markdown_value(value: Any) -> str:
    """Viết giá trị JSON vào ô bảng Markdown."""
    text = json.dumps(value, ensure_ascii=False)
    return "`" + text.replace("|", "\\|").replace("`", "'") + "`"


def _readme(case: Case, folder: Path, result: dict[str, Any]) -> str:
    """Soạn README của ca: yêu cầu, đầu vào, cách chạy lại và bảng đối chiếu."""
    changed = ", ".join(f"`{name}` = {value}" for name, value in case.config.items())
    config_note = f"Cấu hình khác mặc định: {changed} (đầy đủ trong `config.json`)." if changed \
        else "Cấu hình mặc định (ghi đầy đủ trong `config.json`)."
    verdict = "ĐẠT" if result["passed"] else "CHƯA ĐẠT"
    rows = [f"| `{check['field']}` | {_markdown_value(check['expected'])} | {_markdown_value(check['actual'])} "
            f"| {'ĐẠT' if check['passed'] else 'SAI'} |" for check in result["checks"]]
    input_note = "gói tin tổng hợp dựng bằng Scapy" if case.packets else "event JSON, mỗi dòng một event"
    return "\n".join([
        f"# {case.case_id} - {case.title}",
        "",
        f"**Kết quả mong đợi theo đề:** {case.requirement}.",
        "",
        "## Dữ liệu đầu vào",
        "",
        f"{case.scenario} File `{case.input_name}` chứa {input_note}, được đọc offline.",
        "",
        config_note,
        "",
        "## Cách chạy lại",
        "",
        "Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:",
        "",
        "```powershell",
        result["command"],
        "```",
        "",
        "Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:",
        "",
        "```powershell",
        f"python TEST/integration/run_required_cases.py --case {case.case_id} --overwrite",
        "```",
        "",
        "## Kết quả đã chạy",
        "",
        f"- Kết luận: **{verdict}** ({result['passed_checks']}/{result['total_checks']} phép đối chiếu).",
        f"- Mã thoát CLI: `{result['exit_code']}`; số event: `{result['event_count']}`; "
        f"số flow ghi ra: `{result['flow_count']}`.",
        f"- Ý nghĩa: {case.explanation}",
        "",
        "| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |",
        "| --- | --- | --- | --- |",
        *rows,
        "",
        "## Artifact",
        "",
        f"- `{case.input_name}`: dữ liệu đầu vào.",
        "- `config.json`: cấu hình đã dùng.",
        "- `expected.json`: các giá trị phải quan sát được.",
        "- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.",
        "- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.",
        "- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.",
        "",
        "[Về bảng tổng hợp](../README.md)",
        "",
    ])


if __name__ == "__main__":
    raise SystemExit(main())
