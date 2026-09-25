from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
import os
import struct

from scapy.all import get_if_list, sniff
from scapy.utils import PcapReader


def list_interfaces() -> list[str]:
    """Trả về danh sách interface Scapy nhìn thấy."""
    return list(get_if_list())


def iter_pcap(path: str | Path) -> Iterator[tuple[Any, float]]:
    """Đọc PCAP tuần tự để không giữ toàn bộ packet trong bộ nhớ."""
    with PcapReader(str(path)) as reader:
        if not isinstance(reader, PcapReader):
            raise ValueError('Can file PCAP; PCAPNG chua duoc ho tro')
        while True:
            position = reader.f.tell()
            header = reader.f.read(16)
            if not header:
                break
            if len(header) != 16:
                raise ValueError('PCAP bi cat giua header record')
            _, _, captured, original = struct.unpack(reader.endian + 'IIII', header)
            reader.f.seek(0, os.SEEK_END)
            remaining = reader.f.tell() - position - 16
            if captured > remaining:
                raise ValueError('PCAP bi cat giua du lieu record')
            if captured > original or captured > reader.snaplen:
                raise ValueError('Do dai record PCAP khong hop le')
            reader.f.seek(position)
            packet = reader.read_packet(size=captured)
            yield packet, float(packet.time)


def capture_live(interface: str, process_packet: Callable[[Any, float], None],
                 count: int = 0, timeout: int | None = None) -> None:
    """Chuyển ngay từng packet sang hàm xử lý, không tích vào RAM."""
    if interface not in list_interfaces():
        raise ValueError('Interface khong ton tai; dung --list-interfaces')
    sniff(iface=interface, count=count, timeout=timeout, store=False,
          prn=lambda packet: process_packet(packet, float(packet.time)))
