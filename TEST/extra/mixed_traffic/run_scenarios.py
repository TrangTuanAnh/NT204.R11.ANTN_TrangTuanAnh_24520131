"""Tạo đầu vào, chạy main.py và lưu kết quả đối chiếu của các bộ traffic lớn trong TEST/extra/mixed_traffic.

Chạy tại thư mục gốc repo:
    python TEST/extra/mixed_traffic/run_scenarios.py                       # chạy cả hai bộ
    python TEST/extra/mixed_traffic/run_scenarios.py --scenario office_day  # chỉ chạy một bộ
Thư mục kết quả đã có thì không bị ghi đè, trừ khi thêm --overwrite.

File event (events.jsonl) rất lớn nên chỉ được ghi vào thư mục tạm để đối chiếu, không lưu trong repo.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

_REPO = str(Path(__file__).resolve().parents[3])
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)  # để import được src và TEST khi chạy file này trực tiếp

import scapy  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from TEST.extra.mixed_traffic.scenarios import SCENARIOS, Scenario, flow_order  # noqa: E402
from TEST.support.checks import markdown_value, read_lines, same_value, write_json  # noqa: E402
from TEST.support.paths import EXTRA_DIR, REPO_ROOT  # noqa: E402

CASES_DIR = EXTRA_DIR / "mixed_traffic"

# Các trường của flow phải khớp đúng từng giá trị; hai trường thời gian cho phép lệch dưới 10 micro giây.
EXACT_FLOW_FIELDS = ("protocol", "application_protocol", "endpoint_a", "endpoint_b", "packet_count", "byte_count",
                     "forward_packet_count", "forward_byte_count", "backward_packet_count", "backward_byte_count",
                     "SYN_count", "ACK_count", "FIN_count", "RST_count", "state", "handshake_observed", "end_reason")
TIME_FLOW_FIELDS = ("start_time", "last_seen")
TIME_TOLERANCE = 1e-5
SHOWN_DIFFERENCES = 5


def write_inputs(scenario: Scenario, expected: dict[str, Any], folder: Path) -> None:
    """Ghi PCAP, file rule, cấu hình và kết quả mong đợi của bộ traffic vào thư mục."""
    folder.mkdir(parents=True, exist_ok=True)
    wrpcap(str(folder / "input.pcap"), scenario.packets)
    (folder / "input.rules").write_bytes(scenario.rule_text().encode("utf-8"))
    write_json(folder / "config.json", scenario.config)
    write_json(folder / "expected.json", {
        "scenario": scenario.name, "seed": scenario.seed, "composition": scenario.composition(), **expected})


def cli_arguments(folder: Path, events_path: Path) -> list[str]:
    """Tham số dòng lệnh của main.py để chạy bộ traffic có các file trong thư mục folder."""
    return ["--pcap", (folder / "input.pcap").as_posix(), "--rules", (folder / "input.rules").as_posix(),
            "--config", (folder / "config.json").as_posix(), "--output", events_path.as_posix(),
            "--flow-output", (folder / "flows.jsonl").as_posix(),
            "--detection-output", (folder / "detections.jsonl").as_posix(),
            "--rule-report", (folder / "rule_report.json").as_posix()]


def read_outputs(folder: Path, events_path: Path) -> dict[str, Any]:
    """Đọc mọi kết quả main.py đã ghi ra."""
    report_path = folder / "rule_report.json"
    return {
        "events": read_lines(events_path),
        "flows": read_lines(folder / "flows.jsonl"),
        "detections": read_lines(folder / "detections.jsonl"),
        "report": json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {},
    }


def group_by_tuple(flows: list[dict[str, Any]]) -> dict[tuple, list[dict[str, Any]]]:
    """Gom flow theo 5-tuple (đã có thứ tự endpoint) rồi xếp theo thời điểm bắt đầu."""
    groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for flow in sorted(flows, key=flow_order):
        a, b = flow["endpoint_a"], flow["endpoint_b"]
        groups[(flow["protocol"], a["ip"], a["port"], b["ip"], b["port"])].append(flow)
    return groups


def compare_flows(expected: list[dict[str, Any]], actual: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ghép từng flow mong đợi với flow thật cùng 5-tuple (theo thứ tự thời gian); liệt kê mọi chỗ khác nhau."""
    wanted, found = group_by_tuple(expected), group_by_tuple(actual)
    problems: list[dict[str, Any]] = []
    for key in sorted(set(wanted) | set(found)):
        label = "%s %s:%s -> %s:%s" % key
        if len(wanted.get(key, [])) != len(found.get(key, [])):
            problems.append({"flow": label, "problem": "số flow khác nhau",
                             "expected": len(wanted.get(key, [])), "actual": len(found.get(key, []))})
            continue
        for want, got in zip(wanted[key], found[key]):
            differences = {name: {"expected": want[name], "actual": got.get(name)}
                           for name in EXACT_FLOW_FIELDS if want[name] != got.get(name)}
            for name in TIME_FLOW_FIELDS:
                if abs(want[name] - got[name]) > TIME_TOLERANCE:
                    differences[name] = {"expected": want[name], "actual": got[name]}
            if differences:
                problems.append({"flow": label, "differences": differences})
    return problems


def detections_by_packet(detections: list[dict[str, Any]]) -> dict[str, list[int]]:
    """Gom các sid của Detection Event theo số thứ tự gói."""
    table: dict[str, list[int]] = defaultdict(list)
    for detection in detections:
        table[str(detection["packet_id"])].append(detection["sid"])
    return {packet: sorted(sids) for packet, sids in table.items()}


def evaluate(expected: dict[str, Any], exit_code: int, outputs: dict[str, Any]) -> tuple[list[dict[str, Any]], list]:
    """So kết quả thực tế với kết quả mong đợi; trả danh sách phép đối chiếu và các flow bị lệch."""
    events, flows, detections = outputs["events"], outputs["flows"], outputs["detections"]
    engine = outputs["report"].get("engine", {})
    flow_ids = {flow["flow_id"] for flow in flows}
    tracked = [event for event in events if event.get("flow_id") is not None]
    problems = compare_flows(expected["flows"], flows)
    wanted_packets = expected["detections"]["by_packet"]
    found_packets = detections_by_packet(detections)
    packets_different = [number for number in set(wanted_packets) | set(found_packets)
                         if wanted_packets.get(number) != found_packets.get(number)]
    checks: list[dict[str, Any]] = []

    def check(field: str, want: Any, got: Any) -> None:
        """Ghi một phép so sánh giá trị mong đợi với giá trị thực tế."""
        checks.append({"field": field, "expected": want, "actual": got, "passed": same_value(got, want)})

    check("exit_code", 0, exit_code)
    check("event_count", expected["packets"], len(events))
    check("skipped_events", expected["skipped"], sum(e.get("processing_action") == "skip" for e in events))
    check("invalid_events", 0, sum(e.get("preprocess_status") == "invalid" for e in events))
    check("unexpected_errors", 0, sum(any(str(text).startswith("Lỗi khi") for text in
                                          e.get("reason", []) + e.get("decode_errors", [])) for e in events))
    check("events_with_flow", expected["packets"] - expected["skipped"], len(tracked))
    check("events_with_unknown_flow", 0, sum(e["flow_id"] not in flow_ids for e in tracked))
    check("packets_counted_in_flows", len(tracked), sum(flow["packet_count"] for flow in flows))
    check("flow_count", len(expected["flows"]), len(flows))
    check("flows_different_from_expected", 0, len(problems))
    check("detection_count", expected["detections"]["total"], len(detections))
    check("detections_by_sid", expected["detections"]["by_sid"],
          {str(sid): sum(d["sid"] == sid for d in detections) for sid in sorted({d["sid"] for d in detections})})
    check("packets_with_different_detections", 0, len(packets_different))
    check("engine.rules_in_repository", expected["rules"], engine.get("rules_in_repository"))
    check("engine.events_seen", expected["packets"], engine.get("events_seen"))
    check("engine.matches", expected["detections"]["total"], engine.get("matches"))
    check("engine.errors", 0, engine.get("errors"))
    check("index_skips_rules", True, engine.get("candidate_rules", 0) < engine.get("events_evaluated", 0) *
          engine.get("rules_in_repository", 0))
    return checks, problems


def run_scenario(scenario: Scenario, folder: Path) -> dict[str, Any]:
    """Chạy trọn một bộ traffic qua main.py bằng một tiến trình riêng và lưu kết quả."""
    expected = scenario.expected()
    write_inputs(scenario, expected, folder)
    relative = folder.relative_to(REPO_ROOT)
    with tempfile.TemporaryDirectory() as scratch:
        events_path = Path(scratch) / "events.jsonl"
        process = subprocess.run([sys.executable, "main.py", *cli_arguments(relative, events_path)], cwd=REPO_ROOT,
                                 capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
        outputs = read_outputs(folder, events_path)
    checks, problems = evaluate(expected, process.returncode, outputs)
    passed = sum(check["passed"] for check in checks)
    pcap = folder / "input.pcap"
    result = {
        "scenario": scenario.name,
        "seed": scenario.seed,
        "run_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "scapy": scapy.__version__,
        "input_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
        "pcap_bytes": pcap.stat().st_size,
        "command": display_command(scenario, relative),
        "exit_code": process.returncode,
        "passed": passed == len(checks),
        "passed_checks": passed,
        "total_checks": len(checks),
        "packet_count": expected["packets"],
        "flow_count": len(outputs["flows"]),
        "detection_count": len(outputs["detections"]),
        "flow_differences": problems[:SHOWN_DIFFERENCES],
        "checks": checks,
    }
    write_json(folder / "result.json", result)
    (folder / "README.md").write_text(readme(scenario, expected, result), encoding="utf-8")
    return result


def main() -> int:
    """Chọn bộ traffic cần chạy, chạy lần lượt và in kết quả tóm tắt."""
    parser = argparse.ArgumentParser(description="Chay cac bo traffic lon va luu ket qua")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), help="Chi chay mot bo traffic")
    parser.add_argument("--overwrite", action="store_true", help="Xoa ket qua cu cua bo traffic truoc khi chay lai")
    args = parser.parse_args()
    names = [args.scenario] if args.scenario else sorted(SCENARIOS)
    for name in names:
        if (CASES_DIR / name).exists() and not args.overwrite:
            parser.error(f"Da co ket qua cua {name}; them --overwrite de chay lai")
    results = []
    for name in names:
        folder = CASES_DIR / name
        if folder.exists():
            shutil.rmtree(folder)  # main.py ghi nối tiếp nên phải xóa kết quả cũ trước
        results.append(run_scenario(SCENARIOS[name](), folder))
    for result in results:
        verdict = "PASS" if result["passed"] else "FAIL"
        print(f"{result['scenario']} {verdict} ({result['passed_checks']}/{result['total_checks']}) "
              f"- {result['packet_count']} goi, {result['flow_count']} flow, {result['detection_count']} detection")
        for difference in result["flow_differences"]:
            print("  lech:", difference)
    return 0 if all(result["passed"] for result in results) else 1


def display_command(scenario: Scenario, relative: Path) -> str:
    """Lệnh chạy lại bộ traffic, dùng đường dẫn tương đối từ gốc repo và tên output mới."""
    base, name = relative.as_posix(), scenario.name
    return (f"python main.py --pcap {base}/input.pcap --rules {base}/input.rules --config {base}/config.json "
            f"--output output/{name}_events.jsonl --flow-output output/{name}_flows.jsonl "
            f"--detection-output output/{name}_detections.jsonl --rule-report output/{name}_rule_report.json")


def readme(scenario: Scenario, expected: dict[str, Any], result: dict[str, Any]) -> str:
    """Soạn README của bộ traffic: mô tả, thành phần, cách chạy lại và bảng đối chiếu."""
    rows = [f"| {kind} | {row['sessions'] or '-'} | {row['packets']} |"
            for kind, row in scenario.composition().items()]
    rules = [f"| {rule.sid} | `{rule.text}` | {expected['detections']['by_sid'].get(str(rule.sid), 0)} |"
             for rule in scenario.rules]
    changed = ", ".join(f"`{name}` = {value}" for name, value in scenario.config.items())
    config_note = f"Cấu hình khác mặc định: {changed}." if changed else "Cấu hình mặc định."
    verdict = "ĐẠT" if result["passed"] else "CHƯA ĐẠT"
    checks = [f"| `{check['field']}` | {markdown_value(check['expected'])} | {markdown_value(check['actual'])} "
              f"| {'ĐẠT' if check['passed'] else 'SAI'} |" for check in result["checks"]]
    duration = expected["last_time"] - min(float(flow["start_time"]) for flow in expected["flows"])
    return "\n".join([
        f"# {scenario.title}",
        "",
        scenario.description,
        "",
        f"`input.pcap` có **{expected['packets']} gói** ({result['pcap_bytes'] // 1024} KB), kéo dài khoảng "
        f"{duration:.0f} giây, tạo **{len(expected['flows'])} flow**. Dữ liệu là traffic tổng hợp dựng bằng Scapy từ "
        f"seed `{scenario.seed}` (địa chỉ thuộc dải dành cho tài liệu và mạng riêng), được đọc offline, không gửi ra mạng.",
        "",
        "## Thành phần",
        "",
        "| Loại | Số phiên (mỗi phiên là một flow) | Số gói |",
        "| --- | --- | --- |",
        *rows,
        "",
        "## Rule",
        "",
        "| sid | Rule | Số lần khớp mong đợi |",
        "| --- | --- | --- |",
        *rules,
        "",
        config_note,
        "",
        "## Cách đối chiếu",
        "",
        "`expected.json` **không lấy từ kết quả của chương trình**. Nó được tính từ chính các gói Scapy vừa dựng: số gói, "
        "số byte, số cờ SYN/ACK/FIN/RST và chiều đi của từng flow đếm thẳng từ các gói; trạng thái cuối và lý do kết thúc "
        "lấy từ cách dựng từng phiên (phiên đóng bằng FIN thì phải `CLOSED`, bị RST thì phải `RESET`, phiên không tự "
        "kết thúc thì hết hạn nếu thời điểm cuối của cả bộ vượt `last_seen` cộng thời gian chờ). Gói nào phải khớp "
        "rule nào được viết lại độc lập bằng Python, không dùng code của engine. Mỗi flow mong đợi được ghép với flow "
        "thật cùng 5-tuple và so từng trường; mỗi gói được so tập sid đã khớp.",
        "",
        "## Cách chạy lại",
        "",
        "Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp. File event rất lớn nên không được "
        "lưu trong repo; chạy lệnh dưới đây sẽ tạo nó trong `output/`:",
        "",
        "```powershell",
        result["command"],
        "```",
        "",
        "Tạo lại toàn bộ đầu vào, chạy và đối chiếu bằng script:",
        "",
        "```powershell",
        f"python TEST/extra/mixed_traffic/run_scenarios.py --scenario {scenario.name} --overwrite",
        "```",
        "",
        "## Kết quả đã chạy",
        "",
        f"- Kết luận: **{verdict}** ({result['passed_checks']}/{result['total_checks']} phép đối chiếu).",
        f"- Mã thoát CLI: `{result['exit_code']}`; số gói: `{result['packet_count']}`; số flow ghi ra: "
        f"`{result['flow_count']}`; số Detection Event: `{result['detection_count']}`.",
        "",
        "| Phép đối chiếu | Mong đợi | Thực tế | Kết quả |",
        "| --- | --- | --- | --- |",
        *checks,
        "",
        "## Artifact",
        "",
        "- `input.pcap`: traffic đầu vào.",
        "- `input.rules`: các rule đã nạp.",
        "- `config.json`: các tùy chọn cấu hình khác mặc định.",
        "- `expected.json`: thành phần của bộ traffic, flow và Detection Event mong đợi.",
        "- `flows.jsonl`: tổng kết từng flow do chương trình ghi ra.",
        "- `detections.jsonl`: các Detection Event, mỗi dòng một lần rule khớp.",
        "- `rule_report.json`: kết quả nạp rule và số liệu đánh giá của engine.",
        "- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.",
        "",
        "[Về README của các bộ traffic](../README.md)",
        "",
    ])


if __name__ == "__main__":
    raise SystemExit(main())
