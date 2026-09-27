from collections.abc import Callable
from typing import Any

from scapy.all import sniff

from .interfaces import list_interfaces


def capture_live(interface: str, process_packet: Callable[[Any, float], None],
                 count: int = 0, timeout: int | None = None) -> None:
    """Bắt packet từ interface và chuyển ngay từng packet sang hàm xử lý."""
    if interface not in list_interfaces():
        raise ValueError('Interface khong ton tai; dung --list-interfaces')
    sniff(iface=interface, count=count, timeout=timeout, store=False,
          prn=lambda packet: process_packet(packet, float(packet.time)))
