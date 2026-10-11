"""Các phép chuẩn hóa giữ nguyên ý nghĩa dữ liệu: chữ hoa/thường, cách viết IP, tên miền, URI, thời gian."""

from __future__ import annotations

import ipaddress
import math
import re
from copy import deepcopy
from datetime import datetime
from typing import Any

# Mốc thời gian lớn nhất được nhận (cuối năm 9999), tránh số quá lớn làm lỗi các bước sau.
MAX_TIMESTAMP = 253402300799.0

# Khung trường của từng giao thức ứng dụng sau khi chuẩn hóa. Event thiếu trường nào
# thì điền giá trị mặc định ở đây, để mọi event cùng giao thức có cùng một dạng.
APPLICATION_FIELDS: dict[str, dict[str, Any]] = {
    "HTTP": {
        "message_type": None, "method": None, "uri": None, "uri_normalized": None,
        "version": None, "status_code": None, "reason": None, "headers": {}, "body": None,
    },
    "DNS": {
        "transaction_id": None, "is_response": None, "response_code": None,
        "questions": [], "answers": [],
    },
    "SMTP": {
        "message_type": None, "command": None, "argument": None, "status_code": None,
        "message": None, "headers": {}, "body": None,
    },
}

# Loại bản ghi DNS mà phần dữ liệu là tên miền (NS, CNAME, PTR) hoặc địa chỉ IP (A, AAAA).
_DNS_NAME_TYPES = {2, 5, 12}
_DNS_ADDRESS_TYPES = {1, 28}

# Ký tự không cần mã hóa trong URI (theo RFC 3986): viết "%41" hay "A" đều như nhau.
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")
_ABSOLUTE_URI = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)$", re.DOTALL)


def normalize_timestamp(value: Any) -> float:
    """Đổi thời gian về số giây tính từ 01/01/1970 (Unix time).

    Nhận số, chuỗi số hoặc chuỗi ISO 8601 có múi giờ như "2026-10-02T07:00:00+07:00".
    Chuỗi ISO thiếu múi giờ bị từ chối vì không biết đó là giờ ở nơi nào.
    """
    if isinstance(value, bool):
        raise ValueError("phải là số giây hoặc chuỗi thời gian")
    if isinstance(value, (int, float)):
        seconds = float(value)
    elif isinstance(value, str):
        text = value.strip()
        try:
            seconds = float(text)
        except ValueError:
            seconds = _iso_seconds(text)
    else:
        raise ValueError("phải là số giây hoặc chuỗi thời gian")
    if not math.isfinite(seconds) or not 0 <= seconds <= MAX_TIMESTAMP:
        raise ValueError("ngoài khoảng cho phép")
    return seconds


def _iso_seconds(text: str) -> float:
    """Đổi chuỗi thời gian ISO 8601 có múi giờ (chữ Z nghĩa là giờ UTC) thành số giây Unix."""
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("không đọc được dạng thời gian") from None
    if moment.tzinfo is None:
        raise ValueError("thiếu múi giờ")
    return moment.timestamp()


def normalize_ip(value: Any) -> str:
    """Đổi địa chỉ IP về cách viết chuẩn; báo ValueError nếu không phải địa chỉ IP."""
    if not isinstance(value, str):
        raise ValueError("địa chỉ IP phải là chuỗi")
    return str(ipaddress.ip_address(value.strip()))


def normalize_domain(value: str) -> str:
    """Tên miền viết thường và bỏ dấu chấm cuối: "WWW.Example.TEST." → "www.example.test"."""
    return value.strip().rstrip(".").lower()


def normalize_host(value: str) -> str:
    """Chuẩn hóa giá trị header Host nhưng giữ nguyên port.

    Ví dụ "WWW.Example.TEST.:8080" → "www.example.test:8080";
    "[2001:DB8::1]:80" → "[2001:db8::1]:80".
    """
    value = value.strip()
    if value.startswith("["):  # địa chỉ IPv6 nằm trong ngoặc vuông
        return value.lower()
    host, separator, port = value.partition(":")
    return normalize_domain(host) + separator + port


def normalize_uri(uri: str) -> str:
    """Chuẩn hóa URI ở mức an toàn, không làm đổi ý nghĩa của URI.

    - Viết hoa hai chữ số hex sau dấu %: "%2f" → "%2F".
    - Giải mã các ký tự vốn không cần mã hóa: "%41" → "A", "%7E" → "~".
    - Bỏ các đoạn "." và ".." trong đường dẫn: "/a/./b/../c" → "/a/c".
    - Viết thường phần giao thức và tên máy nếu URI có dạng đầy đủ "http://Host/...".
    Ký tự đặc biệt như "%2F" (dấu /) hay "%3F" (dấu ?) giữ nguyên vì giải mã sẽ đổi ý nghĩa.
    """
    uri = _PERCENT.sub(_normalize_escape, uri)
    if uri.startswith("/"):
        return _normalize_path_part(uri)
    match = _ABSOLUTE_URI.match(uri)
    if match is None:
        return uri  # dạng "*" hoặc "host:port" không có đường dẫn để chuẩn hóa
    scheme, authority, rest = match.groups()
    user, at, host = authority.rpartition("@")
    return f"{scheme.lower()}://{user}{at}{host.lower()}{_normalize_path_part(rest)}"


def normalize_application(application: dict[str, Any]) -> list[str]:
    """Chuẩn hóa phần ứng dụng của event ngay trên dictionary đó.

    application["protocol"] phải đã được viết hoa từ trước. Trường thiếu được
    điền theo APPLICATION_FIELDS; tên header viết thường; tên miền viết thường;
    HTTP có thêm uri_normalized. Trả danh sách vấn đề gặp phải (dữ liệu sai cấu
    trúc được thay bằng giá trị mặc định).
    """
    problems: list[str] = []
    protocol = application.get("protocol")
    fields = APPLICATION_FIELDS.get(protocol, {})
    for name, default in fields.items():
        if name not in application:
            application[name] = deepcopy(default)
    put_in_order(application, ("protocol", *fields))
    if "headers" in fields:
        application["headers"] = _normalize_headers(application["headers"], problems)
    if protocol == "HTTP":
        host = application["headers"].get("host")
        if host:
            application["headers"]["host"] = normalize_host(host)
        uri = application.get("uri")
        application["uri_normalized"] = normalize_uri(uri) if isinstance(uri, str) else None
    elif protocol == "DNS":
        for section in ("questions", "answers"):
            application[section] = _normalize_dns_records(application[section], section, problems)
    return problems


def put_in_order(section: dict[str, Any], names: tuple[str, ...]) -> None:
    """Xếp các khóa của dictionary theo thứ tự cho trước; khóa lạ (nếu có) giữ lại ở cuối.

    Nhờ vậy mọi event có cùng thứ tự trường, kể cả event vừa được điền thêm trường thiếu.
    """
    ordered = {name: section[name] for name in names if name in section}
    ordered.update((name, value) for name, value in section.items() if name not in ordered)
    section.clear()
    section.update(ordered)


def _normalize_escape(match: re.Match[str]) -> str:
    """Giải mã một chuỗi %XX nếu đó là ký tự không cần mã hóa, ngược lại chỉ viết hoa phần hex."""
    character = chr(int(match.group(1), 16))
    return character if character in _UNRESERVED else "%" + match.group(1).upper()


def _normalize_path_part(text: str) -> str:
    """Bỏ "." và ".." trong phần đường dẫn; phần tham số sau "?" hoặc "#" giữ nguyên."""
    ends = [index for index in (text.find("?"), text.find("#")) if index != -1]
    path_end = min(ends) if ends else len(text)
    return _remove_dot_segments(text[:path_end]) + text[path_end:]


def _remove_dot_segments(path: str) -> str:
    """Bỏ các đoạn "." (thư mục hiện tại) và ".." (lùi một cấp) trong đường dẫn.

    Không lùi quá thư mục gốc: "/../a" → "/a". Giữ dấu "/" cuối nếu đoạn cuối là "." hoặc "..".
    """
    if not path:
        return path
    segments = path.split("/")
    result: list[str] = []
    for segment in segments:
        if segment == ".":
            continue
        if segment == "..":
            # result[0] == "" là phần trước dấu "/" đầu tiên, tức thư mục gốc: không bỏ.
            if len(result) > 1 or (result and result[0] != ""):
                result.pop()
            continue
        result.append(segment)
    if segments[-1] in (".", ".."):
        result.append("")
    return "/".join(result)


def _normalize_headers(headers: Any, problems: list[str]) -> dict[str, str]:
    """Viết thường tên header và bỏ khoảng trắng thừa ở giá trị.

    Header trùng tên sau khi viết thường (ví dụ "Host" và "HOST") được nối bằng dấu phẩy.
    """
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        problems.append("application.headers không phải object, đã thay bằng {}")
        return {}
    result: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            problems.append(f"Bỏ header không hợp lệ: {name!r}")
            continue
        key, value = name.strip().lower(), value.strip()
        result[key] = f"{result[key]}, {value}" if key in result else value
    return result


def _normalize_dns_records(records: Any, section: str, problems: list[str]) -> list[Any]:
    """Viết thường tên miền trong câu hỏi/câu trả lời DNS và đổi địa chỉ IP về cách viết chuẩn."""
    if records is None:
        return []
    if not isinstance(records, list):
        problems.append(f"application.{section} không phải danh sách, đã thay bằng []")
        return []
    result = []
    for record in records:
        if not isinstance(record, dict):
            problems.append(f"Bỏ bản ghi DNS không hợp lệ trong {section}")
            continue
        if isinstance(record.get("name"), str):
            record["name"] = normalize_domain(record["name"])
        data, record_type = record.get("data"), record.get("type")
        if isinstance(data, str) and isinstance(record_type, int):
            if record_type in _DNS_NAME_TYPES:
                record["data"] = normalize_domain(data)
            elif record_type in _DNS_ADDRESS_TYPES:
                try:
                    record["data"] = normalize_ip(data)
                except ValueError:
                    problems.append(f"Địa chỉ IP trong bản ghi DNS không hợp lệ: {data!r}")
        result.append(record)
    return result
