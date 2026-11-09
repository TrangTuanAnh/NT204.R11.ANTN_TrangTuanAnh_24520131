"""Dựng gói tin tổng hợp bằng Scapy cho các ca kiểm thử (không gửi gì ra mạng)."""

from __future__ import annotations

from typing import Any

from scapy.all import Ether, IP, Raw, TCP, UDP

# Mọi gói được gán thời điểm BASE_TIME cộng số giây của riêng gói đó.
BASE_TIME = 1_700_000_000.0


def frame(layers: Any, at: float) -> Any:
    """Thêm lớp Ethernet để lưu được vào PCAP và gán thời điểm BASE_TIME + at giây.

    Địa chỉ MAC được ghi rõ để Scapy không phải gửi ARP ra mạng thật khi dựng gói.
    """
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / layers
    packet.time = BASE_TIME + at
    return packet


def tcp(at: float, src: str, sport: int, dst: str, dport: int, flags: str,
        payload: bytes = b"", seq: int = 0, ack: int = 0) -> Any:
    """Tạo một gói IPv4/TCP với cờ và dữ liệu cho trước."""
    layers = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    return frame(layers / Raw(payload) if payload else layers, at)


def udp(at: float, src: str, sport: int, dst: str, dport: int, payload: Any) -> Any:
    """Tạo một gói IPv4/UDP; payload là byte hoặc một lớp Scapy như DNS."""
    return frame(IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload, at)


def http_message(first_line: str, headers: dict[str, str], body: bytes = b"") -> bytes:
    """Ghép một thông điệp HTTP; có body thì tự thêm Content-Length đúng độ dài."""
    if body:
        headers = {**headers, "Content-Length": str(len(body))}
    head = "\r\n".join([first_line] + [f"{name}: {value}" for name, value in headers.items()])
    return head.encode("ascii") + b"\r\n\r\n" + body
