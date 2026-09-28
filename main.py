from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.capture.interfaces import list_interfaces
from src.capture.live import capture_live
from src.capture.pcap import iter_pcap
from src.output.jsonl import JsonLinesWriter
from src.parser.packet import parse_packet
from scapy.error import Scapy_Exception


def build_parser() -> argparse.ArgumentParser:
    """Khai báo tham số chọn nguồn packet, giới hạn bắt live và file đầu ra."""
    parser = argparse.ArgumentParser(description="Packet capture va parser cho IDS")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--interface", help="Ten network interface can bat packet")
    source.add_argument("--pcap", type=Path, help="Duong dan file PCAP")
    parser.add_argument("--list-interfaces", action="store_true", help="Liet ke interface")
    parser.add_argument("--output", type=Path, default=Path("output/ids.jsonl"))
    parser.add_argument("--count", type=int, default=0, help="So packet live toi da; 0 la khong gioi han")
    parser.add_argument("--timeout", type=int, help="So giay bat live toi da")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Điều phối capture/PCAP qua cùng parser và ghi từng event ra JSON Lines.

    Trả 0 khi xử lý xong, 2 khi tham số không hợp lệ, 1 khi nguồn có lỗi,
    hoặc 130 khi người dùng dừng bằng Ctrl+C.
    """
    args = build_parser().parse_args(argv)
    if args.count < 0 or (args.timeout is not None and args.timeout <= 0):
        print('count >= 0 va timeout > 0', file=sys.stderr)
        return 2
    if args.list_interfaces:
        for interface in list_interfaces():
            print(interface)
        return 0
    if not args.interface and not args.pcap:
        print("Can chon --interface hoac --pcap", file=sys.stderr)
        return 2
    try:
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
    except KeyboardInterrupt:
        print("Da dung bat packet.", file=sys.stderr)
        return 130
    except (OSError, PermissionError, ValueError, RuntimeError, Scapy_Exception) as exc:
        print(f"Khong the xu ly nguon packet: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
