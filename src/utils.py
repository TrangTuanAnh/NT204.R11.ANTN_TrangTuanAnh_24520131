from typing import Any


def decode_payload(payload: bytes) -> str:
    """Đổi payload thành chuỗi mà không làm hỏng cả packet khi dữ liệu lỗi."""
    return payload.decode("utf-8", errors="replace")


def text_value(value: Any) -> str:
    """Đổi giá trị Scapy thành chuỗi dễ ghi JSON."""
    if isinstance(value, bytes):
        return value.rstrip(b".\x00").decode("utf-8", errors="replace")
    return str(value)

