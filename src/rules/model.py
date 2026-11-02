"""Internal Rule Object: cách biểu diễn thống nhất của một rule sau khi phân tích xong."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

BIDIRECTIONAL = "<>"

# Ba kết luận khi phân tích một rule. Hai kết luận sau là rule không được dùng để so khớp.
VALID = "valid"
INVALID = "invalid"
UNSUPPORTED = "unsupported"


class RuleProblems:
    """Sổ ghi các vấn đề tìm thấy khi phân tích một rule.

    - invalid: rule viết sai cú pháp, sai kiểu dữ liệu hoặc thiếu trường bắt buộc.
    - unsupported: rule viết đúng nhưng dùng thành phần ngoài phạm vi hỗ trợ.
    """

    def __init__(self) -> None:
        """Bắt đầu với sổ trống."""
        self.invalid: list[str] = []
        self.unsupported: list[str] = []
        self.unsupported_keywords: list[str] = []  # tên các keyword ngoài phạm vi, dùng để thống kê

    def status(self) -> str:
        """Kết luận về rule; lỗi cú pháp được ưu tiên báo trước."""
        if self.invalid:
            return INVALID
        return UNSUPPORTED if self.unsupported else VALID

    def reasons(self) -> list[str]:
        """Danh sách lý do, mỗi lý do một lần; rule hợp lệ thì danh sách rỗng."""
        return list(dict.fromkeys(self.invalid + self.unsupported))


@dataclass(frozen=True)
class AddressSet:
    """Tập địa chỉ IP của một đầu trong header rule.

    Địa chỉ thuộc tập nếu nằm trong include (include rỗng nghĩa là mọi địa chỉ)
    và không nằm trong exclude. Hai danh sách đều rỗng chính là "any".
    """

    include: tuple[Any, ...] = ()
    exclude: tuple[Any, ...] = ()

    @property
    def is_any(self) -> bool:
        """Tập này có nhận mọi địa chỉ không."""
        return not self.include and not self.exclude

    def contains(self, address: str | None) -> bool:
        """Địa chỉ có thuộc tập không; gói không có địa chỉ chỉ thuộc tập "any"."""
        if self.is_any:
            return True
        if address is None:
            return False
        value = ipaddress.ip_address(address)
        if self.include and not any(value in network for network in self.include):
            return False
        return not any(value in network for network in self.exclude)

    def describe(self) -> dict[str, Any]:
        """Dạng dữ liệu JSON để ghi vào báo cáo."""
        return {"any": self.is_any, "include": [str(item) for item in self.include],
                "exclude": [str(item) for item in self.exclude]}


@dataclass(frozen=True)
class PortSet:
    """Tập port của một đầu trong header rule; mỗi phần tử là một khoảng (nhỏ nhất, lớn nhất)."""

    include: tuple[tuple[int, int], ...] = ()
    exclude: tuple[tuple[int, int], ...] = ()

    @property
    def is_any(self) -> bool:
        """Tập này có nhận mọi port không."""
        return not self.include and not self.exclude

    def contains(self, port: int | None) -> bool:
        """Port có thuộc tập không; gói không có port (ví dụ ICMP) chỉ thuộc tập "any"."""
        if self.is_any:
            return True
        if port is None:
            return False
        if self.include and not any(low <= port <= high for low, high in self.include):
            return False
        return not any(low <= port <= high for low, high in self.exclude)

    def single_ports(self) -> list[int] | None:
        """Danh sách port nếu tập chỉ gồm các port đơn lẻ; có khoảng hoặc phần loại trừ thì trả None."""
        if not self.include or self.exclude or any(low != high for low, high in self.include):
            return None
        return [low for low, _ in self.include]

    def describe(self) -> dict[str, Any]:
        """Dạng dữ liệu JSON để ghi vào báo cáo."""
        return {"any": self.is_any, "include": [list(item) for item in self.include],
                "exclude": [list(item) for item in self.exclude]}


@dataclass(frozen=True)
class ContentOption:
    """Một chuỗi cần tìm (content) cùng các giới hạn vị trí đi kèm."""

    text: str                    # chuỗi đúng như viết trong rule, ví dụ "|00 01|abc"
    pattern: bytes               # các byte thật cần tìm
    negated: bool = False        # content:!"..." nghĩa là gói không được chứa chuỗi này
    nocase: bool = False
    offset: int | None = None    # bắt đầu tìm từ byte thứ mấy tính từ đầu dữ liệu
    depth: int | None = None     # chỉ tìm trong bấy nhiêu byte tính từ điểm bắt đầu
    distance: int | None = None  # bỏ qua bấy nhiêu byte tính từ cuối chuỗi vừa tìm thấy
    within: int | None = None    # chuỗi phải nằm trọn trong bấy nhiêu byte tính từ điểm bắt đầu

    @property
    def is_relative(self) -> bool:
        """Vị trí tìm có tính theo chuỗi tìm thấy trước đó không."""
        return self.distance is not None or self.within is not None

    def describe(self) -> dict[str, Any]:
        """Dạng dữ liệu JSON để ghi vào báo cáo."""
        return {"content": self.text, "hex": self.pattern.hex(), "negated": self.negated, "nocase": self.nocase,
                "offset": self.offset, "depth": self.depth, "distance": self.distance, "within": self.within}


@dataclass(frozen=True)
class FlagsOption:
    """Điều kiện về cờ TCP.

    modifier: "" (đúng các cờ này, không thừa không thiếu), "+" (có đủ các cờ này,
    được có thêm cờ khác), "*" (có ít nhất một cờ), "!" (không có cờ nào trong số này).
    ignored là các cờ được bỏ qua khi so sánh.
    """

    modifier: str
    flags: str
    ignored: str = ""


@dataclass(frozen=True)
class DsizeOption:
    """Điều kiện về số byte dữ liệu của gói; operator là "=", ">", "<" hoặc "<>" (tính cả hai đầu)."""

    operator: str
    low: int
    high: int | None = None


@dataclass(frozen=True)
class FlowOption:
    """Điều kiện về flow: chiều gói (to_server/to_client) và trạng thái kết nối."""

    direction: str | None = None
    state: str | None = None


@dataclass(frozen=True)
class Rule:
    """Một rule đã phân tích và kiểm tra xong; mọi module phía sau chỉ làm việc với đối tượng này."""

    action: str
    protocol: str
    source: AddressSet
    source_ports: PortSet
    direction: str
    destination: AddressSet
    destination_ports: PortSet
    sid: int
    msg: str
    rev: int | None = None
    classtype: str | None = None
    priority: int | None = None
    contents: tuple[ContentOption, ...] = ()
    flags: FlagsOption | None = None
    dsize: DsizeOption | None = None
    flow: FlowOption | None = None
    file: str = ""
    line: int = 0

    def ports_fit(self, source_port: int | None, destination_port: int | None) -> bool:
        """Cặp port của gói có khớp header không, xét cả chiều ngược nếu rule dùng "<>"."""
        if self.source_ports.contains(source_port) and self.destination_ports.contains(destination_port):
            return True
        return (self.direction == BIDIRECTIONAL and self.source_ports.contains(destination_port)
                and self.destination_ports.contains(source_port))

    def describe(self) -> dict[str, Any]:
        """Dạng dữ liệu JSON của toàn bộ rule, dùng để ghi báo cáo và kiểm thử."""
        return {
            "action": self.action,
            "protocol": self.protocol,
            "source": self.source.describe(),
            "source_ports": self.source_ports.describe(),
            "direction": self.direction,
            "destination": self.destination.describe(),
            "destination_ports": self.destination_ports.describe(),
            "sid": self.sid,
            "rev": self.rev,
            "msg": self.msg,
            "classtype": self.classtype,
            "priority": self.priority,
            "contents": [content.describe() for content in self.contents],
            "flags": vars(self.flags) if self.flags else None,
            "dsize": vars(self.dsize) if self.dsize else None,
            "flow": vars(self.flow) if self.flow else None,
        }
