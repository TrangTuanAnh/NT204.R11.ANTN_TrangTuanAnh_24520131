from __future__ import annotations

import argparse
import json
import sys
import threading
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path

from src.capture.events import iter_events
from src.capture.interfaces import list_interfaces
from src.capture.live import capture_live
from src.capture.pcap import iter_pcap
from src.config import Config, load_config
from src.output.jsonl import JsonLinesWriter
from src.parser.packet import parse_packet
from src.pipeline import Pipeline
from src.rules.rule_set import RuleSet, load_rule_set, load_warnings
from scapy.error import Scapy_Exception


def build_parser() -> argparse.ArgumentParser:
    """Khai báo tham số chọn nguồn dữ liệu, chế độ xử lý, cấu hình và file đầu ra."""
    parser = argparse.ArgumentParser(
        description="IDS: capture, parser, decoder, preprocessor, flow tracker, so khop rule Snort")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--interface", help="Ten network interface can bat packet")
    source.add_argument("--pcap", type=Path, help="Duong dan file PCAP")
    source.add_argument("--events", type=Path, help="File event JSON Lines, moi dong mot event")
    parser.add_argument("--list-interfaces", action="store_true", help="Liet ke interface")
    parser.add_argument("--output", type=Path, default=Path("output/ids.jsonl"), help="File ghi event")
    parser.add_argument("--flow-output", type=Path, default=Path("output/flows.jsonl"),
                        help="File ghi tong ket flow")
    parser.add_argument("--rules", nargs="+", action="extend", metavar="FILE",
                        help="Mot hoac nhieu file .rules; bat buoc phai co rule moi chay buoc so khop")
    parser.add_argument("--detection-output", type=Path, default=Path("output/detections.jsonl"),
                        help="File ghi Detection Event")
    parser.add_argument("--rule-report", type=Path, default=Path("output/rule_report.json"),
                        help="File bao cao nap rule va so lieu danh gia")
    parser.add_argument("--config", type=Path, help="File cau hinh JSON; bo trong thi dung gia tri mac dinh")
    parser.add_argument("--parse-only", action="store_true", help="Chi capture va parse nhu Bai tap 1")
    parser.add_argument("--count", type=int, default=0, help="So packet live toi da; 0 la khong gioi han")
    parser.add_argument("--timeout", type=int, help="So giay bat live toi da")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Điều phối nguồn dữ liệu, các bước xử lý và việc ghi kết quả.

    Trả 0 khi xử lý xong, 2 khi tham số hoặc cấu hình không hợp lệ, 1 khi nguồn
    dữ liệu hoặc việc ghi file có lỗi, 130 khi người dùng dừng bằng Ctrl+C.
    """
    args = build_parser().parse_args(argv)
    if args.count < 0 or (args.timeout is not None and args.timeout <= 0):
        print('count >= 0 va timeout > 0', file=sys.stderr)
        return 2
    if args.list_interfaces:
        for interface in list_interfaces():
            print(interface)
        return 0
    if not (args.interface or args.pcap or args.events):
        print("Can chon --interface, --pcap hoac --events", file=sys.stderr)
        return 2
    try:
        config = load_config(args.config)
        if args.rules:
            config = replace(config, rule_files=list(dict.fromkeys(config.rule_files + args.rules)))
        _check_paths(args, config)
        rule_set = _load_rules(config) if config.rule_files and not args.parse_only else None
    except (OSError, ValueError) as exc:
        print(f"Tham so hoac cau hinh khong hop le: {exc}", file=sys.stderr)
        return 2
    try:
        if args.parse_only:
            _run_parse_only(args)
        else:
            _run_pipeline(args, config, rule_set)
    except KeyboardInterrupt:
        print("Da dung bat packet.", file=sys.stderr)
        return 130
    except (OSError, PermissionError, ValueError, RuntimeError, Scapy_Exception) as exc:
        print(f"Khong the xu ly nguon du lieu: {exc}", file=sys.stderr)
        return 1
    return 0


def _load_rules(config: Config) -> RuleSet:
    """Nạp các file rule và in cảnh báo về những rule không dùng được, rồi chạy tiếp."""
    rule_set = load_rule_set(config)
    for line in load_warnings(rule_set.report):
        print(line, file=sys.stderr)
    return rule_set


def _check_paths(args: argparse.Namespace, config: Config) -> None:
    """Không cho file kết quả trùng file đầu vào hoặc trùng nhau.

    Kết quả được ghi nối tiếp, nên trùng file sẽ làm hỏng dữ liệu vào hoặc
    trộn lẫn event với tổng kết flow.
    """
    if args.parse_only and args.events:
        raise ValueError("--parse-only chi dung voi --pcap hoac --interface")
    if args.parse_only and args.rules:
        raise ValueError("--rules can du pipeline, khong dung voi --parse-only")
    outputs = [args.output] if args.parse_only else [args.output, args.flow_output]
    inputs = [path for path in (args.pcap, args.events, args.config) if path is not None]
    if config.rule_files and not args.parse_only:
        outputs += [args.detection_output, args.rule_report]
        inputs += [Path(path) for path in config.rule_files]
    for index, output in enumerate(outputs):
        for other in outputs[:index] + inputs:
            if _same_file(output, other):
                raise ValueError(f"file ket qua {output} trung voi file {other}")


def _same_file(first: Path, second: Path) -> bool:
    """Hai đường dẫn có trỏ tới cùng một file không (kể cả viết khác nhau)."""
    if first.resolve() == second.resolve():
        return True
    return first.exists() and second.exists() and first.samefile(second)


def _run_parse_only(args: argparse.Namespace) -> None:
    """Chế độ của Bài tập 1: chỉ capture và parse rồi ghi event, không giải mã hay theo dõi flow."""
    source = "pcap" if args.pcap else "live"
    with JsonLinesWriter(args.output) as writer:
        packet_id = 0

        def process_packet(packet, timestamp):
            """Đánh số gói từ nguồn đã chọn rồi ghi ngay event đã phân tích."""
            nonlocal packet_id
            packet_id += 1
            writer.write(parse_packet(packet, packet_id, timestamp, source))

        if args.pcap:
            for packet, timestamp in iter_pcap(args.pcap):
                process_packet(packet, timestamp)
        else:
            capture_live(args.interface, process_packet, args.count, args.timeout)


def _run_pipeline(args: argparse.Namespace, config: Config, rule_set: RuleSet | None = None) -> None:
    """Chạy đủ các bước parse → decode → preprocess → flow → so khớp rule; ghi kết quả từng bước.

    Khi nguồn kết thúc (hết file, hết thời gian bắt, lỗi hoặc Ctrl+C), các flow
    còn mở vẫn được ghi ra file kèm lý do kết thúc. Không có rule thì không tạo
    file Detection Event và không chạy bước so khớp.
    """
    pipeline = Pipeline(config)
    if rule_set is not None:
        pipeline.use_rules(rule_set.repository)
    # Khi bắt live, gói được xử lý ở luồng bắt gói còn việc đóng flow hết hạn
    # chạy ở luồng chính; khóa này giữ cho hai việc không chạy chồng lên nhau.
    lock = threading.Lock()
    source = "pcap" if args.pcap else "events" if args.events else "live"
    detection_writer = JsonLinesWriter(args.detection_output) if rule_set is not None else None
    with JsonLinesWriter(args.output) as event_writer, JsonLinesWriter(args.flow_output) as flow_writer, \
            detection_writer or nullcontext():
        packet_id = 0

        def save(event, finished_flows):
            """Ghi event (nếu không bị bỏ theo cấu hình), tổng kết flow và các Detection Event mới."""
            if event is not None:
                event_writer.write(event)
            for flow in finished_flows:
                flow_writer.write(flow)
            for detection in pipeline.take_detections():
                detection_writer.write(detection)

        def process_packet(packet, timestamp):
            """Đánh số gói rồi đưa qua pipeline; dùng chung cho PCAP và live."""
            nonlocal packet_id
            with lock:
                packet_id += 1
                save(*pipeline.process_packet(packet, packet_id, timestamp, source))

        def close_idle_flows():
            """Gọi định kỳ khi bắt live để đóng flow hết hạn dù không có gói mới."""
            with lock:
                save(None, pipeline.expire_idle())

        end_reason = "source_error"  # đổi lại khi nguồn kết thúc bình thường
        try:
            if args.events:
                for event in iter_events(args.events, config.max_event_bytes):
                    save(*pipeline.process_event(event))
            elif args.pcap:
                for packet, timestamp in iter_pcap(args.pcap):
                    process_packet(packet, timestamp)
            else:
                capture_live(args.interface, process_packet, args.count, args.timeout,
                             on_idle=close_idle_flows, idle_interval=config.live_check_interval)
            end_reason = "capture_stopped" if source == "live" else "end_of_input"
        except KeyboardInterrupt:
            end_reason = "interrupted"
            raise
        finally:
            with lock:
                save(None, pipeline.finish(end_reason))
            if rule_set is not None:
                _write_rule_report(args.rule_report, rule_set, pipeline)


def _write_rule_report(path: Path, rule_set: RuleSet, pipeline: Pipeline) -> None:
    """Ghi báo cáo gồm kết quả nạp từng rule và số liệu đánh giá; mỗi lần chạy ghi đè file cũ."""
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {**rule_set.report, "engine": pipeline.detector.stats}
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
