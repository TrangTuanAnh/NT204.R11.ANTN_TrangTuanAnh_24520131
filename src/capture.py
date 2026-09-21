from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from scapy.all import get_if_list, sniff
from scapy.utils import PcapReader


def list_interfaces() -> list[str]:
    """Trả về danh sách interface Scapy nhìn thấy."""
    return list(get_if_list())


def iter_pcap(path: str | Path) -> Iterator[tuple[Any, float]]:
    """Đọc PCAP tuần tự để không giữ toàn bộ packet trong bộ nhớ."""
    with PcapReader(str(path)) as reader:
        for packet in reader:
            yield packet, float(packet.time)


def capture_live(interface: str, process_packet: Callable[[Any, float], None],
                 count: int = 0, timeout: int | None = None) -> None:
    """Chuyển ngay từng packet sang hàm xử lý, không tích vào RAM."""
    if interface not in list_interfaces():
        raise ValueError('Interface khong ton tai; dung --list-interfaces')
    sniff(iface=interface, count=count, timeout=timeout, store=False,
          prn=lambda packet: process_packet(packet, float(packet.time)))
