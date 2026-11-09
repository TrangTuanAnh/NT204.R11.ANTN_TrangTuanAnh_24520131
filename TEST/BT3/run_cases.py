"""Tạo đầu vào, chạy main.py và lưu kết quả đối chiếu của các ca kiểm thử Core Engine.

Kết quả 14 ca bắt buộc nằm trong TEST/BT3, kết quả các ca bổ sung nằm trong TEST/extra.

Chạy tại thư mục gốc repo:
    python TEST/BT3/run_cases.py              # chạy tất cả các ca
    python TEST/BT3/run_cases.py --case 07    # chỉ chạy một ca
    python TEST/BT3/run_cases.py --case B1    # chỉ chạy ca bổ sung B1
Thư mục kết quả đã có thì không bị ghi đè, trừ khi thêm --overwrite.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

_REPO = str(Path(__file__).resolve().parents[2])
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)  # để import được src và TEST khi chạy file này trực tiếp

import scapy  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from src.config import Config  # noqa: E402
from src.detection.matcher import PacketView  # noqa: E402
from src.rules.rule_set import load_rule_set  # noqa: E402
from TEST.BT3.cases import DetectionCase, all_detection_cases  # noqa: E402
from TEST.support.checks import lookup, markdown_value, read_lines, same_value, write_json  # noqa: E402
from TEST.support.paths import BT3_DIR, EXTRA_DIR, REPO_ROOT  # noqa: E402


def case_folder(case: DetectionCase) -> Path:
    """Thư mục lưu kết quả của ca: ca bắt buộc trong TEST/BT3, ca bổ sung trong TEST/extra."""
    return (EXTRA_DIR if case.extra else BT3_DIR) / case.name


def write_inputs(case: DetectionCase, folder: Path) -> None:
    """Ghi gói tin, file rule, cấu hình và các giá trị mong đợi của ca vào thư mục."""
    folder.mkdir(parents=True, exist_ok=True)
    wrpcap(str(folder / "input.pcap"), case.packets)
    for name, content in case.rules.items():
        (folder / name).write_bytes(content.encode("utf-8"))
    write_json(folder / "config.json", case.config)
    write_json(folder / "expected.json", {
        "case": case.name, "requirement": case.requirement, "checks": case.checks,
        "equal_paths": case.equal_paths,
    })


def rule_paths(case: DetectionCase, folder: Path, repo_root: Path) -> list[str]:
    """Đường dẫn các file rule của ca: file riêng của ca rồi tới file có sẵn trong repo."""
    return [(folder / name).as_posix() for name in case.rules] + [(repo_root / path).as_posix() for path in case.repo_rules]


def cli_arguments(case: DetectionCase, folder: Path, repo_root: Path = REPO_ROOT) -> list[str]:
    """Tham số dòng lệnh của main.py để chạy ca với các file trong thư mục cho trước."""
    return ["--pcap", (folder / "input.pcap").as_posix(), "--rules", *rule_paths(case, folder, repo_root),
            "--config", (folder / "config.json").as_posix(), "--output", (folder / "events.jsonl").as_posix(),
            "--flow-output", (folder / "flows.jsonl").as_posix(),
            "--detection-output", (folder / "detections.jsonl").as_posix(),
            "--rule-report", (folder / "rule_report.json").as_posix()]


def read_outputs(folder: Path) -> dict[str, Any]:
    """Đọc mọi kết quả main.py đã ghi ra."""
    report_path = folder / "rule_report.json"
    return {
        "events": read_lines(folder / "events.jsonl"),
        "flows": read_lines(folder / "flows.jsonl"),
        "detections": read_lines(folder / "detections.jsonl"),
        "report": json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {},
    }


def candidates_trace(case: DetectionCase, folder: Path, events: list[Any], repo_root: Path = REPO_ROOT) -> list[list[int]]:
    """Hỏi trực tiếp Repository xem mỗi event được chọn những rule nào.

    Số này không có trong file đầu ra nên phải tra lại trên event đã chuẩn hóa.
    """
    config = Config(**{**case.config, "rule_files": rule_paths(case, folder, repo_root)})
    repository = load_rule_set(config).repository
    trace = []
    for event in events:
        packet = PacketView(event)
        found = repository.candidates(packet.protocol, packet.source_port, packet.destination_port)
        trace.append([rule.sid for rule in found])
    return trace


def evaluate(case: DetectionCase, exit_code: int, outputs: dict[str, Any],
             candidates: list[list[int]]) -> list[dict[str, Any]]:
    """So từng giá trị mong đợi với kết quả thực tế; trả danh sách các phép so sánh."""
    by_packet: dict[str, list[int]] = {str(event["packet_id"]): [] for event in outputs["events"]}
    for detection in outputs["detections"]:
        by_packet[str(detection["packet_id"])].append(detection["sid"])
    data = {**outputs, "exit_code": exit_code, "event_count": len(outputs["events"]),
            "flow_count": len(outputs["flows"]), "detection_count": len(outputs["detections"]),
            "by_packet": by_packet, "candidates": candidates}
    checks = []
    for path, expected in case.checks.items():
        actual = lookup(data, path)
        checks.append({"field": path, "expected": expected, "actual": actual,
                       "passed": same_value(actual, expected)})
    for first, second in case.equal_paths:
        values = [lookup(data, first), lookup(data, second)]
        checks.append({"field": f"{first} = {second}", "expected": "hai giá trị bằng nhau", "actual": values,
                       "passed": values[0] is not None and values[0] == values[1]})
    return checks


def run_case(case: DetectionCase, folder: Path) -> dict[str, Any]:
    """Chạy trọn một ca qua main.py bằng một tiến trình riêng và lưu kết quả."""
    write_inputs(case, folder)
    relative = folder.relative_to(REPO_ROOT)
    process = subprocess.run([sys.executable, "main.py", *cli_arguments(case, relative, Path("."))], cwd=REPO_ROOT,
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    outputs = read_outputs(folder)
    checks = evaluate(case, process.returncode, outputs, candidates_trace(case, folder, outputs["events"]))
    passed = sum(check["passed"] for check in checks)
    result = {
        "case": case.name,
        "requirement": case.requirement,
        "run_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "scapy": scapy.__version__,
        "input_sha256": hashlib.sha256((folder / "input.pcap").read_bytes()).hexdigest(),
        "command": _display_command(case, relative),
        "exit_code": process.returncode,
        "passed": passed == len(checks),
        "passed_checks": passed,
        "total_checks": len(checks),
        "event_count": len(outputs["events"]),
        "flow_count": len(outputs["flows"]),
        "detection_count": len(outputs["detections"]),
        "checks": checks,
    }
    write_json(folder / "result.json", result)
    (folder / "README.md").write_text(_readme(case, result), encoding="utf-8")
    return result


def main() -> int:
    """Chọn ca cần chạy, chạy lần lượt và in kết quả tóm tắt."""
    parser = argparse.ArgumentParser(description="Chay cac ca kiem thu Core Engine va luu ket qua")
    parser.add_argument("--case", help="So thu tu ca (vi du 07, B1) hoac ten thu muc cua ca")
    parser.add_argument("--overwrite", action="store_true", help="Xoa ket qua cu cua ca truoc khi chay lai")
    args = parser.parse_args()
    cases = [case for case in all_detection_cases() if args.case in (None, case.number, case.name)]
    if not cases:
        parser.error("Khong tim thay ca kiem thu")
    for case in cases:
        if case_folder(case).exists() and not args.overwrite:
            parser.error(f"Da co ket qua cua ca {case.number}; them --overwrite de chay lai")
    results = []
    for case in cases:
        folder = case_folder(case)
        if folder.exists():
            shutil.rmtree(folder)  # main.py ghi nối tiếp nên phải xóa kết quả cũ trước
        results.append(run_case(case, folder))
    for result in results:
        verdict = "PASS" if result["passed"] else "FAIL"
        print(f"{result['case']} {verdict} ({result['passed_checks']}/{result['total_checks']})")
    print(f"Passed {sum(r['passed'] for r in results)}/{len(results)}")
    return 0 if all(result["passed"] for result in results) else 1


def _display_command(case: DetectionCase, relative: Path) -> str:
    """Lệnh chạy lại ca, dùng đường dẫn tương đối từ gốc repo và tên output mới."""
    rules = " ".join(rule_paths(case, relative, Path(".")))
    prefix = case.name if case.extra else f"case{case.number}"
    return (f"python main.py --pcap {relative.as_posix()}/input.pcap --rules {rules} "
            f"--config {relative.as_posix()}/config.json --output output/{prefix}_events.jsonl "
            f"--flow-output output/{prefix}_flows.jsonl --detection-output output/{prefix}_detections.jsonl "
            f"--rule-report output/{prefix}_rule_report.json")


def _readme(case: DetectionCase, result: dict[str, Any]) -> str:
    """Soạn README của ca: yêu cầu, đầu vào, cách chạy lại và bảng đối chiếu."""
    changed = ", ".join(f"`{name}` = {json.dumps(value, ensure_ascii=False)}" for name, value in case.config.items())
    config_note = f"Cấu hình khác mặc định: {changed}." if changed else "Cấu hình mặc định."
    verdict = "ĐẠT" if result["passed"] else "CHƯA ĐẠT"
    rows = [f"| `{check['field']}` | {markdown_value(check['expected'])} | {markdown_value(check['actual'])} "
            f"| {'ĐẠT' if check['passed'] else 'SAI'} |" for check in result["checks"]]
    rule_files = [f"- `{name}`: file rule của ca." for name in case.rules]
    rule_files += [f"- `{path}`: file rule có sẵn trong repo." for path in case.repo_rules]
    return "\n".join([
        f"# Ca {case.number} - {case.title}",
        "",
        f"**Kết quả mong đợi theo đề:** {case.requirement}",
        "",
        "## Dữ liệu đầu vào",
        "",
        f"{case.scenario} File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.",
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
        f"python TEST/BT3/run_cases.py --case {case.number} --overwrite",
        "```",
        "",
        "## Kết quả đã chạy",
        "",
        f"- Kết luận: **{verdict}** ({result['passed_checks']}/{result['total_checks']} phép đối chiếu).",
        f"- Mã thoát CLI: `{result['exit_code']}`; số event: `{result['event_count']}`; "
        f"số Detection Event: `{result['detection_count']}`.",
        f"- Ý nghĩa: {case.explanation}",
        "",
        "| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |",
        "| --- | --- | --- | --- |",
        *rows,
        "",
        "## Artifact",
        "",
        "- `input.pcap`: dữ liệu đầu vào.",
        *rule_files,
        "- `config.json`: các tùy chọn cấu hình khác mặc định.",
        "- `expected.json`: các giá trị phải quan sát được.",
        "- `events.jsonl`, `flows.jsonl`: event và tổng kết flow của các bước trước.",
        "- `detections.jsonl`: các Detection Event, mỗi dòng một lần rule khớp.",
        "- `rule_report.json`: kết quả nạp từng rule và số liệu đánh giá của engine.",
        "- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.",
        "",
        "[Về bảng tổng hợp](../README.md)",
        "",
    ])


if __name__ == "__main__":
    raise SystemExit(main())
