import os
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from scapy.utils import PcapReader


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
