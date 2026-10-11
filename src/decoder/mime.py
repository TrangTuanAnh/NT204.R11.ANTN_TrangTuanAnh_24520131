"""Giải mã thư gửi qua SMTP theo chuẩn MIME: Base64, Quoted-Printable và header dạng =?utf-8?...?=."""

from __future__ import annotations

import base64
import binascii
import html
import quopri
import re
from email.header import decode_header
from email.message import Message
from email.parser import BytesParser
from typing import Any

from .text import DecodeReport, decode_text, limit_bytes

# Trong Quoted-Printable, dấu "=" phải đi với hai chữ số hex (ví dụ "=3D") hoặc đứng cuối dòng.
_BAD_QP_ESCAPE = re.compile(rb"=(?![0-9A-Fa-f]{2}|\r?\n|$)")
# Phần nội dung chỉ chứa byte gốc, không có lớp mã hóa truyền tải.
_PLAIN_ENCODINGS = ("7bit", "8bit", "binary")


def decode_mail(application: dict[str, Any], payload: bytes | None, limit: int, max_parts: int,
                report: DecodeReport) -> dict[str, Any]:
    """Giải mã một thư: header, từng phần MIME và phần chữ của thư.

    Cách giải mã từng phần lấy theo header Content-Transfer-Encoding của phần
    đó, không tự đoán từ nội dung. Phần chữ của các phần text được nối lại
    thành body của thư.
    """
    data = payload if payload is not None else _rebuild_message(application, limit, report)
    message = BytesParser().parsebytes(_remove_smtp_marks(data))
    parts = []
    for part in message.walk():
        if part.is_multipart():
            continue  # phần bao ngoài chỉ chứa các phần con, không có nội dung riêng
        if len(parts) >= max_parts:
            report.add_error(f"Thư có hơn {max_parts} phần, các phần sau không được giải mã")
            break
        parts.append(_decode_part(part, len(parts) + 1, report))
    defects = sorted({type(defect).__name__ for part in message.walk() for defect in part.defects})
    if defects:
        report.add_error("Cấu trúc MIME chưa đầy đủ hoặc sai: " + ", ".join(defects))
    texts = [part["body"] for part in parts if part["body"] is not None]
    return {
        "headers": _decode_headers(message, report),
        "mime_parts": parts,
        "body": "\n".join(texts) if texts else None,
    }


def _remove_smtp_marks(data: bytes) -> bytes:
    """Bỏ những thứ SMTP thêm vào khi truyền thư để lấy lại đúng nội dung thư.

    - Lệnh "DATA" nếu nằm chung gói với nội dung thư.
    - Dòng chỉ có một dấu "." báo hết thư.
    - Dấu chấm SMTP chèn thêm vào đầu những dòng vốn bắt đầu bằng dấu chấm.
    """
    if data[:6].upper() == b"DATA\r\n":
        data = data[6:]
    if data.endswith(b"\r\n.\r\n"):
        data = data[:-3]
    data = data.replace(b"\r\n..", b"\r\n.")
    return data[1:] if data.startswith(b"..") else data


def _rebuild_message(application: dict[str, Any], limit: int, report: DecodeReport) -> bytes:
    """Dựng lại thư từ header và body của event khi không có byte gốc (event đọc từ file)."""
    headers = application.get("headers")
    lines = [f"{name}: {value}" for name, value in headers.items()] if isinstance(headers, dict) else []
    body = application.get("body")
    text = "\r\n".join(lines) + "\r\n\r\n" + (body if isinstance(body, str) else "")
    return limit_bytes(text.encode("utf-8"), limit, report, "Thư SMTP")


def _decode_part(part: Message, index: int, report: DecodeReport) -> dict[str, Any]:
    """Giải mã một phần của thư.

    Phần dạng chữ được đổi ra chữ (text/html còn được đổi thực thể HTML); phần
    khác như file đính kèm chỉ ghi kích thước sau khi giải mã.
    """
    label = f"Phần MIME {index}"
    record: dict[str, Any] = {
        "content_type": part.get_content_type(),
        "charset": part.get_content_charset(),
        "transfer_encoding": str(part.get("Content-Transfer-Encoding") or "7bit").strip().lower(),
        "filename": part.get_filename(),
        "size": None,
        "body": None,
        "status": "error",
    }
    errors_before = len(report.errors)
    try:
        data = _transfer_decode(part, record["transfer_encoding"], label, report)
    except ValueError as exc:
        report.add_error(f"{label}: {exc}")
        return record
    record["size"] = len(data)
    if part.get_content_maintype() == "text":
        text = decode_text(data, record["charset"], report, label)
        record["body"] = html.unescape(text) if record["content_type"] == "text/html" else text
    report.add_result()
    record["status"] = "partial" if len(report.errors) > errors_before else "ok"
    return record


def _transfer_decode(part: Message, encoding: str, label: str, report: DecodeReport) -> bytes:
    """Bỏ lớp mã hóa truyền tải (Base64, Quoted-Printable) để lấy lại byte gốc của phần thư."""
    if encoding in _PLAIN_ENCODINGS:
        return part.get_payload(decode=True) or b""
    raw = part.get_payload(decode=False)
    if not isinstance(raw, str):
        raise ValueError("không đọc được nội dung")
    data = raw.encode("utf-8", errors="surrogateescape")
    if encoding == "base64":
        return _decode_base64(data)
    if encoding == "quoted-printable":
        if _BAD_QP_ESCAPE.search(data):
            report.add_error(f"{label}: Quoted-Printable có dấu '=' không đúng dạng, giữ nguyên")
        return quopri.decodestring(data)
    raise ValueError(f"chưa hỗ trợ kiểu mã hóa '{encoding}'")


def _decode_base64(data: bytes) -> bytes:
    """Giải mã Base64: bỏ khoảng trắng, xuống dòng và tự thêm dấu "=" ở cuối nếu bị thiếu."""
    compact = re.sub(rb"\s+", b"", data)
    if len(compact) % 4 == 1:
        raise ValueError("Base64 không hợp lệ (độ dài sai)")
    compact += b"=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact, validate=True)
    except binascii.Error as exc:
        raise ValueError("Base64 không hợp lệ") from exc


def _decode_headers(message: Message, report: DecodeReport) -> dict[str, str]:
    """Đọc header của thư (tên viết thường); header trùng tên được nối bằng dấu phẩy."""
    headers: dict[str, str] = {}
    for name, value in message.items():
        text = _decode_header_value(str(value), name, report)
        key = name.strip().lower()
        headers[key] = f"{headers[key]}, {text}" if key in headers else text
    return headers


def _decode_header_value(value: str, name: str, report: DecodeReport) -> str:
    """Giải mã các đoạn dạng =?utf-8?b?...?= trong giá trị header, ví dụ Subject có dấu tiếng Việt."""
    value = re.sub(r"\r?\n(?=[ \t])", "", value)  # nối header viết tràn nhiều dòng
    try:
        pieces = decode_header(value)
    except Exception:
        report.add_error(f"Header {name}: không giải mã được, giữ nguyên")
        return value
    texts = []
    for content, charset in pieces:
        if isinstance(content, bytes):
            texts.append(decode_text(content, charset, report, f"Header {name}"))
        else:
            texts.append(content)
    return "".join(texts)
