"""Phân tích phần header của rule: hành động, giao thức, địa chỉ IP, port và chiều."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Any

from .model import BIDIRECTIONAL, AddressSet, PortSet, RuleProblems

SUPPORTED_ACTIONS = {"alert"}
OTHER_ACTIONS = {"log", "pass", "drop", "reject", "sdrop", "activate", "dynamic"}
SUPPORTED_PROTOCOLS = {"tcp", "udp", "ip"}
OTHER_PROTOCOLS = {"icmp"}
DIRECTIONS = {"->", BIDIRECTIONAL}

_PORT_RANGE = re.compile(r"^(\d*):(\d*)$")
_LARGEST_PORT = 65535
_MAX_NESTING = 16  # giới hạn số lớp lồng nhau, để biến tự trỏ về chính nó không làm chương trình treo


def parse_header(text: str, variables: dict[str, str], problems: RuleProblems) -> dict[str, Any] | None:
    """Đọc header gồm 7 phần: hành động, giao thức, IP nguồn, port nguồn, chiều, IP đích, port đích.

    Trả các trường để tạo Rule; trả None nếu có phần sai. Mọi vấn đề được ghi vào problems.
    """
    parts = text.split()
    if len(parts) != 7:
        problems.invalid.append(f"Header phải có đủ 7 phần, đang có {len(parts)}: {text.strip()!r}")
        return None
    action, protocol, source, source_port, direction, destination, destination_port = parts
    action, protocol = action.lower(), protocol.lower()
    _check_choice(action, SUPPORTED_ACTIONS, OTHER_ACTIONS, "Hành động", problems)
    _check_choice(protocol, SUPPORTED_PROTOCOLS, OTHER_PROTOCOLS, "Giao thức", problems)
    if direction not in DIRECTIONS:
        problems.invalid.append(f"Chiều phải là -> hoặc <>, đang là {direction!r}")
    fields: dict[str, Any] = {"action": action, "protocol": protocol, "direction": direction}
    for name, value, parse, label in (
        ("source", source, parse_addresses, "IP nguồn"),
        ("source_ports", source_port, parse_ports, "Port nguồn"),
        ("destination", destination, parse_addresses, "IP đích"),
        ("destination_ports", destination_port, parse_ports, "Port đích"),
    ):
        try:
            fields[name] = parse(value, variables)
        except ValueError as exc:
            problems.invalid.append(f"{label} không hợp lệ ({value}): {exc}")
    return fields if len(fields) == 7 else None


def parse_addresses(text: str, variables: dict[str, str]) -> AddressSet:
    """Đọc phần địa chỉ: any, IPv4, CIDR, biến $TEN, danh sách [a,b] và phủ định !a."""
    include, exclude = _parse_group(text, variables, _read_network)
    return AddressSet(include, exclude)


def parse_ports(text: str, variables: dict[str, str]) -> PortSet:
    """Đọc phần port: any, port đơn, khoảng a:b, :b, a:, biến $TEN, danh sách [a,b] và phủ định !a."""
    include, exclude = _parse_group(text, variables, _read_port_range)
    return PortSet(include, exclude)


def _check_choice(value: str, supported: set[str], others: set[str], label: str, problems: RuleProblems) -> None:
    """Giá trị đúng của Snort nhưng ngoài phạm vi thì unsupported; giá trị lạ thì invalid."""
    if value in others:
        problems.unsupported.append(f"{label} {value} ngoài phạm vi hỗ trợ")
    elif value not in supported:
        problems.invalid.append(f"{label} không hợp lệ: {value!r}")


def _parse_group(text: str, variables: dict[str, str], read_item: Callable[[str], Any],
                 nesting: int = 0) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Đọc một biểu thức và trả (các phần được nhận, các phần bị loại)."""
    text = text.strip()
    if not text:
        raise ValueError("thiếu giá trị")
    if nesting > _MAX_NESTING:
        raise ValueError("biến hoặc danh sách lồng nhau quá sâu")
    if text.startswith("!"):
        return _negate(_parse_group(text[1:], variables, read_item, nesting + 1))
    if text.startswith("$"):
        name = text[1:]
        if name not in variables:
            raise ValueError(f"biến ${name} chưa được khai báo")
        return _parse_group(variables[name], variables, read_item, nesting + 1)
    if text.startswith("["):
        if not text.endswith("]"):
            raise ValueError("danh sách thiếu dấu ]")
        groups = [_parse_group(item, variables, read_item, nesting + 1) for item in _split_list(text[1:-1])]
        return _merge(groups)
    if text == "any":
        return (), ()
    return (read_item(text),), ()


def _negate(group: tuple[tuple[Any, ...], tuple[Any, ...]]) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Đảo một biểu thức: phần được nhận thành phần bị loại và ngược lại."""
    include, exclude = group
    if not include and not exclude:
        raise ValueError("không thể phủ định any")
    if include and exclude:
        raise ValueError("chưa hỗ trợ phủ định danh sách có cả phần nhận và phần loại")
    return exclude, include


def _merge(groups: list[tuple[tuple[Any, ...], tuple[Any, ...]]]) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Gộp các phần tử của một danh sách; có phần tử any thì phần nhận là mọi giá trị."""
    has_any = any(not include and not exclude for include, exclude in groups)
    include = () if has_any else tuple(item for group in groups for item in group[0])
    return include, tuple(item for group in groups for item in group[1])


def _split_list(text: str) -> list[str]:
    """Tách danh sách theo dấu phẩy, không tách trong danh sách con."""
    items, current, nesting = [], "", 0
    for character in text:
        if character == "," and nesting == 0:
            items.append(current)
            current = ""
            continue
        nesting += (character == "[") - (character == "]")
        if nesting < 0:
            raise ValueError("danh sách thừa dấu ]")
        current += character
    if nesting != 0:
        raise ValueError("danh sách thiếu dấu ]")
    items.append(current)
    return items


def _read_network(text: str) -> Any:
    """Đọc một địa chỉ IP hoặc dải CIDR; dải có phần máy khác 0 được đưa về đầu dải như Snort."""
    return ipaddress.ip_network(text, strict=False)


def _read_port_range(text: str) -> tuple[int, int]:
    """Đọc port đơn hoặc khoảng; ":1023" là từ 0 tới 1023, "1024:" là từ 1024 tới 65535."""
    if text.isdigit():
        low = high = int(text)
    else:
        match = _PORT_RANGE.match(text)
        if match is None or text == ":":
            raise ValueError("phải là số hoặc khoảng a:b")
        low = int(match.group(1)) if match.group(1) else 0
        high = int(match.group(2)) if match.group(2) else _LARGEST_PORT
    if high > _LARGEST_PORT or low > _LARGEST_PORT:
        raise ValueError("port phải từ 0 đến 65535")
    if low > high:
        raise ValueError("đầu khoảng lớn hơn cuối khoảng")
    return low, high
