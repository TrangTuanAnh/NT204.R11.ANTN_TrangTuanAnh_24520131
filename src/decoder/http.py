"""Giải mã dữ liệu HTTP: chuỗi %XX trong URI và form, bảng mã và thực thể HTML trong body."""

from __future__ import annotations

import html
import re
from typing import Any
from urllib.parse import unquote_to_bytes

from .text import DecodeReport, decode_text, limit_bytes

# Dấu % không đi kèm đúng hai chữ số hex (ví dụ "%ZZ", "%4") là chuỗi mã hóa sai.
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
FORM_TYPE = "application/x-www-form-urlencoded"
# Ngoài các loại text/..., hai loại này cũng là chữ có thể chứa thực thể HTML (&lt; &gt;...).
_HTML_TEXT_TYPES = {"application/xhtml+xml", "application/xml"}


def decode_http(application: dict[str, Any], payload: bytes | None, limit: int,
                report: DecodeReport) -> dict[str, Any]:
    """Giải mã URI, tham số trên URI, form và body của một thông điệp HTTP.

    Mỗi phép giải mã chỉ làm một lượt ("%2527" thành "%27" chứ không thành
    dấu nháy) để không đổi ý nghĩa dữ liệu. URI gốc trong application giữ nguyên.
    """
    result: dict[str, Any] = {"uri": None, "query": [], "form": [], "body": None}
    uri = application.get("uri")
    if isinstance(uri, str):
        result["uri"] = decode_percent(uri, report, "URI")
        result["query"] = decode_form(_query_string(uri), report, "Tham số URI")
    body = _body_bytes(application, payload, limit, report)
    if body is not None:
        headers = _lower_headers(application.get("headers"))
        result["body"], result["form"] = _decode_body(body, headers, report)
    return result


def decode_percent(text: str, report: DecodeReport, label: str) -> str:
    """Giải mã một lượt các chuỗi %XX, ví dụ "%27%20OR%201%3D1" thành "' OR 1=1".

    Chuỗi % sai dạng được giữ nguyên và ghi lỗi. Byte giải mã ra được đọc theo UTF-8.
    """
    if _BAD_PERCENT.search(text):
        report.add_error(f"{label}: có dấu % không đúng dạng %XX, giữ nguyên")
    decoded = decode_text(unquote_to_bytes(text), "utf-8", report, label)
    report.add_result()
    return decoded


def decode_form(text: str, report: DecodeReport, label: str) -> list[list[str]]:
    """Tách chuỗi dạng "a=1&b=2" thành danh sách [tên, giá trị] đã giải mã.

    Giữ đúng thứ tự, tên lặp lại và giá trị rỗng. Theo quy ước của form HTML,
    dấu "+" là khoảng trắng; dấu cộng thật được gửi dưới dạng "%2B".
    """
    pairs = []
    for item in text.split("&") if text else []:
        if not item:
            continue
        name, _, value = item.partition("=")
        pairs.append([
            decode_percent(name.replace("+", " "), report, label),
            decode_percent(value.replace("+", " "), report, label),
        ])
    return pairs


def parse_content_type(value: str | None) -> tuple[str | None, str | None]:
    """Tách Content-Type thành loại nội dung (viết thường) và bảng mã.

    Ví dụ "text/html; charset=UTF-8" cho ra ("text/html", "UTF-8").
    """
    if not value:
        return None, None
    media_type, *params = value.split(";")
    charset = None
    for param in params:
        name, _, param_value = param.partition("=")
        if name.strip().lower() == "charset":
            charset = param_value.strip().strip('"') or None
    return media_type.strip().lower() or None, charset


def _query_string(uri: str) -> str:
    """Lấy phần tham số sau dấu "?" của URI, bỏ phần "#..." nếu có."""
    return uri.partition("#")[0].partition("?")[2]


def _lower_headers(headers: Any) -> dict[str, str]:
    """Đổi tên header về chữ thường để tra cứu không phân biệt hoa thường."""
    if not isinstance(headers, dict):
        return {}
    return {str(name).strip().lower(): str(value) for name, value in headers.items()}


def _body_bytes(application: dict[str, Any], payload: bytes | None, limit: int,
                report: DecodeReport) -> bytes | None:
    """Lấy body dạng byte.

    Ưu tiên byte gốc của gói (phần sau dòng trống ngăn header và body). Event
    đọc từ file không có byte gốc thì dùng trường body dạng chữ của parser.
    """
    if payload is not None:
        for separator in (b"\r\n\r\n", b"\n\n"):
            _, found, body = payload.partition(separator)
            if found:
                return body
        return None  # chưa thấy hết phần header nên chưa có body
    body = application.get("body")
    if isinstance(body, str):
        return limit_bytes(body.encode("utf-8"), limit, report, "Body HTTP")
    return None


def _decode_body(body: bytes, headers: dict[str, str],
                 report: DecodeReport) -> tuple[str | None, list[list[str]]]:
    """Đọc body thành chữ theo bảng mã trong Content-Type rồi giải mã thêm theo loại nội dung.

    - Form (application/x-www-form-urlencoded): tách thành các cặp tên/giá trị.
    - Nội dung dạng chữ (text/..., XML hoặc không ghi loại): đổi thực thể HTML
      như "&lt;script&gt;" thành "<script>".
    """
    encoding = headers.get("content-encoding", "").strip().lower()
    if encoding and encoding != "identity":
        report.add_error(f"Body HTTP được nén bằng '{encoding}', chưa hỗ trợ giải nén")
        return None, []
    media_type, charset = parse_content_type(headers.get("content-type"))
    text = decode_text(body, charset, report, "Body HTTP")
    report.add_result()
    if "chunked" in headers.get("transfer-encoding", "").lower():
        report.add_error("Body HTTP gửi theo từng khúc (chunked), chưa ghép các khúc lại")
    if media_type == FORM_TYPE:
        return text, decode_form(text, report, "Form")
    if media_type is None or media_type.startswith("text/") or media_type in _HTML_TEXT_TYPES:
        text = html.unescape(text)
    return text, []
