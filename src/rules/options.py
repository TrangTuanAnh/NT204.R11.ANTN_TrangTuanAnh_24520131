"""Phân tích phần tùy chọn của rule, tức phần nằm trong dấu ngoặc đơn."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from .model import ContentOption, DsizeOption, FlagsOption, FlowOption, RuleProblems

# Các keyword trong phạm vi đề bài; keyword khác làm cả rule bị đánh dấu unsupported và không được dùng.
SINGLE_USE_KEYWORDS = {"msg", "sid", "rev", "classtype", "priority", "flags", "dsize", "flow"}
CONTENT_MODIFIERS = {"nocase", "offset", "depth", "distance", "within"}
SUPPORTED_KEYWORDS = SINGLE_USE_KEYWORDS | CONTENT_MODIFIERS | {"content"}

# Giá trị đúng của Snort cho flow nhưng ngoài phạm vi đề bài.
_OTHER_FLOW_VALUES = {"from_client", "from_server", "stateless", "no_stream", "only_stream", "no_frag", "only_frag"}
_FLOW_DIRECTIONS = {"to_server", "to_client"}
_FLOW_STATES = {"established", "not_established"}

_KEYWORD = re.compile(r"^[a-z0-9_]+$")
_CLASSTYPE = re.compile(r"^[A-Za-z0-9_.-]+$")
_FLAGS = re.compile(r"^([!*+]?)([A-Za-z0-9]+)([!*+]?)(?:,([A-Za-z0-9]+))?$")
_DSIZE = re.compile(r"^(?:(\d+)\s*<>\s*(\d+)|([<>]?)\s*(\d+))$")
_FLAG_LETTERS = "FSRPAUCE"
_OLD_FLAG_NAMES = {"1": "C", "2": "E"}  # hai tên cũ của cờ CWR và ECE, Snort vẫn chấp nhận
_LARGEST_POSITION = 65535


def parse_options(text: str, problems: RuleProblems) -> dict[str, Any] | None:
    """Đọc các tùy chọn, trả các trường để tạo Rule; mọi vấn đề được ghi vào problems.

    Trả None nếu không tách được các tùy chọn, vì khi đó không còn biết rule có những gì.
    """
    fields: dict[str, Any] = {}
    contents: list[ContentOption] = []
    try:
        options = split_options(text)
    except ValueError as exc:
        problems.invalid.append(f"Phần tùy chọn sai cú pháp: {exc}")
        return None
    for name, value in options:
        if not _KEYWORD.match(name):
            problems.invalid.append(f"Tùy chọn sai dạng: {name!r}")
        elif name not in SUPPORTED_KEYWORDS:
            problems.unsupported.append(f"Keyword {name} ngoài phạm vi hỗ trợ")
            problems.unsupported_keywords.append(name)
        elif name in SINGLE_USE_KEYWORDS and name in fields:
            problems.invalid.append(f"Keyword {name} xuất hiện nhiều lần")
        else:
            _read_option(name, value, fields, contents, problems)
    fields["contents"] = tuple(contents)
    return fields


def split_options(text: str) -> list[tuple[str, str | None]]:
    """Tách chuỗi tùy chọn thành các cặp (tên keyword, giá trị).

    Các tùy chọn ngăn cách bằng dấu ";". Dấu ";" nằm trong cặp dấu nháy kép hoặc
    có dấu "\\" đứng trước không phải là dấu ngăn cách. Tùy chọn cuối có thể
    không có dấu ";" như các ví dụ trong bài giảng.
    """
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    index = 0
    while index < len(text):
        character = text[index]
        if character == "\\":
            current.append(text[index:index + 2])
            index += 2
            continue
        if character == '"':
            in_quotes = not in_quotes
        if character == ";" and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
        index += 1
    if in_quotes:
        raise ValueError('thiếu dấu " đóng')
    parts.append("".join(current))
    options = []
    for part in parts:
        if part.strip():
            name, separator, value = part.partition(":")
            options.append((name.strip().lower(), value.strip() if separator else None))
    return options


def _read_option(name: str, value: str | None, fields: dict[str, Any], contents: list[ContentOption],
                 problems: RuleProblems) -> None:
    """Đọc một keyword trong phạm vi; giá trị sai được ghi là invalid thay vì làm dừng chương trình."""
    try:
        if name == "content":
            contents.append(_read_content(value))
        elif name in CONTENT_MODIFIERS:
            # Keyword ngoài phạm vi đứng trước có thể là thứ mà keyword này phụ thuộc vào (ví dụ
            # within:len dùng biến của byte_extract). Rule đó đã bị bỏ nên không cần xét tiếp.
            if not problems.unsupported:
                if not contents:
                    raise ValueError("phải đứng sau một content")
                contents[-1] = _apply_modifier(contents[-1], name, value)
        elif name == "msg":
            fields["msg"] = _read_quoted_text(value)
        elif name == "classtype":
            if value is None or not _CLASSTYPE.match(value):
                raise ValueError("phải là một tên phân loại")
            fields["classtype"] = value
        elif name == "sid":
            fields["sid"] = _read_integer(value, 1)
        elif name == "rev":
            fields["rev"] = _read_integer(value, 0)
        elif name == "priority":
            fields["priority"] = _read_integer(value, 0)
        elif name == "flags":
            fields["flags"] = _read_flags(value)
        elif name == "dsize":
            fields["dsize"] = _read_dsize(value)
        elif name == "flow":
            fields["flow"] = _read_flow(value, problems)
    except ValueError as exc:
        problems.invalid.append(f"Keyword {name} không hợp lệ ({value}): {exc}")
        if name in SINGLE_USE_KEYWORDS:
            fields[name] = None  # đã báo sai rồi, không báo thêm là thiếu keyword này


def _read_integer(value: str | None, smallest: int, largest: int | None = None) -> int:
    """Đọc một số nguyên và kiểm tra khoảng cho phép."""
    if value is None or not re.fullmatch(r"-?\d+", value):
        raise ValueError("phải là số nguyên")
    number = int(value)
    if number < smallest or (largest is not None and number > largest):
        raise ValueError(f"phải từ {smallest} trở lên" if largest is None else f"phải từ {smallest} đến {largest}")
    return number


def _inside_quotes(value: str | None) -> str:
    """Lấy phần nằm trong cặp dấu nháy kép; không được có dấu nháy trơ ở giữa."""
    if value is None or len(value) < 2 or not value.startswith('"') or not value.endswith('"'):
        raise ValueError('phải đặt trong cặp dấu nháy kép')
    body = value[1:-1]
    if re.search(r'(?<!\\)(?:\\\\)*"', body) or re.search(r'(?<!\\)(?:\\\\)*\\$', body):
        raise ValueError('có dấu nháy kép hoặc dấu \\ chưa được viết đúng')
    return body


def _read_quoted_text(value: str | None) -> str:
    """Đọc chuỗi của msg và bỏ dấu "\\" đứng trước các ký tự đặc biệt."""
    return re.sub(r"\\(.)", r"\1", _inside_quotes(value))


def _read_content(value: str | None) -> ContentOption:
    """Đọc content:[!]"chuỗi"; chuỗi có thể trộn chữ và byte viết dạng hex giữa hai dấu "|"."""
    text = (value or "").strip()
    negated = text.startswith("!")
    if negated:
        text = text[1:].strip()
    body = _inside_quotes(text)
    return ContentOption(text=body, pattern=_content_bytes(body), negated=negated)


def _content_bytes(body: str) -> bytes:
    """Đổi chuỗi content thành byte cần tìm, ví dụ "ab|00 FF|c" thành b"ab\\x00\\xffc"."""
    result = bytearray()
    index = 0
    while index < len(body):
        character = body[index]
        if character == "|":
            end = body.find("|", index + 1)
            if end == -1:
                raise ValueError('thiếu dấu "|" đóng phần hex')
            try:
                result += bytes.fromhex(body[index + 1:end])
            except ValueError:
                raise ValueError("phần hex phải gồm từng cặp chữ số hex") from None
            index = end + 1
        elif character == "\\":
            escaped = body[index + 1:index + 2]
            if escaped not in ('"', ";", "\\", ":", "|"):
                raise ValueError(f"không được viết \\{escaped}")
            result += escaped.encode("ascii")
            index += 2
        elif character == ";":
            raise ValueError("ký tự ; phải viết thành \\;")
        else:
            result += character.encode("utf-8")
            index += 1
    if not result:
        raise ValueError("chuỗi cần tìm đang rỗng")
    return bytes(result)


def _apply_modifier(content: ContentOption, name: str, value: str | None) -> ContentOption:
    """Áp một keyword bổ sung vào content đứng ngay trước nó và kiểm tra giá trị.

    offset/depth tính từ đầu dữ liệu còn distance/within tính từ chuỗi vừa tìm
    thấy, nên bài làm không cho dùng chung hai nhóm này trên một content.
    """
    if name == "nocase":
        if value is not None:
            raise ValueError("không nhận giá trị")
        return replace(content, nocase=True)
    if getattr(content, name) is not None:
        raise ValueError("đã có trên content này")
    other_group = ("distance", "within") if name in ("offset", "depth") else ("offset", "depth")
    if any(getattr(content, other) is not None for other in other_group):
        raise ValueError(f"không dùng chung với {' hoặc '.join(other_group)}")
    if name in ("offset", "distance"):
        number = _read_integer(value, -_LARGEST_POSITION, _LARGEST_POSITION)
    else:
        number = _read_integer(value, max(1, len(content.pattern)), _LARGEST_POSITION)
    return replace(content, **{name: number})


def _read_flags(value: str | None) -> FlagsOption:
    """Đọc flags:[!|*|+]<cờ>[,<cờ bỏ qua>]; số 0 nghĩa là gói không có cờ nào."""
    match = _FLAGS.match((value or "").replace(" ", ""))
    if match is None or (match.group(1) and match.group(3)):
        raise ValueError("phải có dạng [!|*|+]<cờ>[,<cờ bỏ qua>]")
    modifier = match.group(1) or match.group(3)
    flags = "" if match.group(2) == "0" else _flag_letters(match.group(2))
    return FlagsOption(modifier, flags, _flag_letters(match.group(4)) if match.group(4) else "")


def _flag_letters(text: str) -> str:
    """Đổi các tên cờ về chữ hoa theo một thứ tự cố định, báo lỗi nếu có tên lạ."""
    letters = {_OLD_FLAG_NAMES.get(letter, letter) for letter in text.upper()}
    unknown = letters - set(_FLAG_LETTERS)
    if unknown:
        raise ValueError(f"cờ lạ: {''.join(sorted(unknown))}")
    return "".join(letter for letter in _FLAG_LETTERS if letter in letters)


def _read_dsize(value: str | None) -> DsizeOption:
    """Đọc dsize: n (đúng n byte), >n, <n, hoặc min<>max (tính cả hai đầu)."""
    match = _DSIZE.match(value or "")
    if match is None:
        raise ValueError("phải có dạng n, >n, <n hoặc min<>max")
    if match.group(1) is not None:
        low, high = int(match.group(1)), int(match.group(2))
        if low > high:
            raise ValueError("đầu khoảng lớn hơn cuối khoảng")
        return DsizeOption("<>", low, high)
    return DsizeOption(match.group(3) or "=", int(match.group(4)))


def _read_flow(value: str | None, problems: RuleProblems) -> FlowOption:
    """Đọc flow:<giá trị>,<giá trị>; giá trị đúng của Snort nhưng ngoài phạm vi thì unsupported."""
    values = [item.strip().lower() for item in (value or "").split(",")]
    direction, state = None, None
    for item in values:
        if item in _OTHER_FLOW_VALUES:
            problems.unsupported.append(f"Giá trị flow {item} ngoài phạm vi hỗ trợ")
            problems.unsupported_keywords.append(f"flow:{item}")
        elif item in _FLOW_DIRECTIONS:
            if direction is not None:
                raise ValueError("chỉ được chọn một chiều")
            direction = item
        elif item in _FLOW_STATES:
            if state is not None:
                raise ValueError("chỉ được chọn một trạng thái")
            state = item
        else:
            raise ValueError(f"giá trị lạ: {item!r}")
    return FlowOption(direction, state)
