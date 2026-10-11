"""Chọn cách giải mã cho từng event theo giao thức ứng dụng mà parser nhận diện được."""

from __future__ import annotations

from typing import Any

from src.config import Config

from .http import decode_http
from .mime import decode_mail
from .text import DecodeReport, decode_text, limit_bytes


def empty_decoded() -> dict[str, Any]:
    """Khung kết quả giải mã; mọi event đều có đủ các khóa này, khóa không dùng để null/[]/{}."""
    return {
        "uri": None,         # HTTP: URI đã giải mã %XX
        "query": [],         # HTTP: các cặp [tên, giá trị] sau dấu ? của URI
        "form": [],          # HTTP: các cặp [tên, giá trị] trong body dạng form
        "body": None,        # HTTP: body dạng chữ; SMTP: phần chữ của thư
        "headers": {},       # SMTP: header của thư đã giải mã
        "mime_parts": [],    # SMTP: từng phần của thư và trạng thái giải mã của phần đó
        "text": None,        # gói khác: toàn bộ payload đọc thành chữ
    }


def decode_event(event: dict[str, Any], payload: bytes | None, config: Config) -> None:
    """Giải mã dữ liệu ứng dụng của event và ghi kết quả vào chính event đó.

    Thêm ba trường:
    - decoded: dữ liệu sau khi giải mã (xem empty_decoded).
    - decode_status: ok / partial / error / not_applicable.
    - decode_errors: danh sách lỗi gặp phải.

    Các trường parser đã tạo được giữ nguyên, nên luôn so được dữ liệu gốc với
    dữ liệu đã giải mã. payload là byte gốc của gói; event đọc từ file không
    có byte gốc (payload là None) thì dùng các trường chữ mà parser để lại.
    Hàm không bao giờ ném lỗi ra ngoài.
    """
    report = DecodeReport()
    decoded = empty_decoded()
    try:
        application = event.get("application")
        if not isinstance(application, dict):
            application = {}
        protocol = str(application.get("protocol") or "").strip().upper()
        message_type = str(application.get("message_type") or "").strip().lower()
        if payload is not None:
            payload = limit_bytes(payload, config.max_payload_bytes, report, "Payload")
        if protocol == "HTTP":
            decoded.update(decode_http(application, payload, config.max_payload_bytes, report))
        elif protocol == "SMTP" and message_type == "data":
            decoded.update(decode_mail(application, payload, config.max_payload_bytes,
                                       config.max_mime_parts, report))
        elif protocol != "DNS" and payload:
            # Gói chưa rõ giao thức hoặc lệnh SMTP: đọc cả payload thành chữ để kiểm tra bảng mã.
            decoded["text"] = decode_text(payload, "utf-8", report, "Payload")
            report.add_result()
    except Exception as exc:
        # Lưới an toàn: lỗi không lường trước chỉ đánh dấu event này, chương trình vẫn chạy tiếp.
        report.add_error(f"Lỗi khi giải mã: {exc}")
    event["decoded"] = decoded
    event["decode_status"] = report.status()
    event["decode_errors"] = report.errors
