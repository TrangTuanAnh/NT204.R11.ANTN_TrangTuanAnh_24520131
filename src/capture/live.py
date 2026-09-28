from collections.abc import Callable
from typing import Any

from scapy.all import conf, sniff

from .interfaces import list_interfaces


def _capture_name(interface: str) -> str | None:
    """Đổi tên thường, GUID hoặc tên Npcap thành tên card mà Scapy dùng."""
    prefix = "\\Device\\NPF_"
    for device in conf.ifaces.values():
        network_name = device.network_name or ""
        aliases = {device.name, network_name}
        if network_name.startswith(prefix):
            aliases.add(network_name[len(prefix):])
        if interface in aliases:
            return device.name
    return None


def capture_live(interface: str, process_packet: Callable[[Any, float], None],
                 count: int = 0, timeout: int | None = None) -> None:
    """Bắt live trên interface và gọi callback với packet cùng timestamp.

    Không lưu danh sách packet trong bộ nhớ; count và timeout giới hạn lần bắt.
    """
    capture_name = _capture_name(interface)
    if capture_name is None and interface not in list_interfaces():
        raise ValueError('Interface khong ton tai; dung --list-interfaces')
    sniff(iface=capture_name or interface, count=count, timeout=timeout, store=False,
          prn=lambda packet: process_packet(packet, float(packet.time)))
