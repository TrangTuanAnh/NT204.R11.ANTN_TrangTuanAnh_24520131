from typing import Any


def decode_payload(payload: bytes) -> str:
    """Giải mã payload UTF-8; thay byte không hợp lệ bằng ký tự thay thế."""
    return payload.decode("utf-8", errors="replace")


def text_value(value: Any) -> str:
    """Đổi giá trị Scapy thành chuỗi; bỏ dấu chấm/byte 0 cuối tên DNS."""
    if isinstance(value, bytes):
        return value.rstrip(b".\x00").decode("utf-8", errors="replace")
    return str(value)

