"""Rule Repository / Indexer: lưu các rule hợp lệ và chọn nhanh các rule cần xét cho một gói."""

from __future__ import annotations

from collections import defaultdict

from .model import Rule

# Gói TCP/UDP cần xét rule của chính giao thức đó và rule "ip"; gói khác chỉ cần xét rule "ip".
_RULE_GROUPS = {"TCP": ("tcp", "ip"), "UDP": ("udp", "ip")}


class RuleRepository:
    """Kho rule có chỉ mục theo giao thức và port.

    Mỗi rule được xếp vào một nhóm theo giao thức, rồi trong nhóm đó:
    - theo các port đơn lẻ của phía đích; phía đích không có port đơn lẻ thì
      dùng phía nguồn. Rule "<>" không cần xử lý riêng vì khi tra cứu đã xét cả
      port nguồn lẫn port đích của gói.
    - rule không chọn được port đơn lẻ nào (any, khoảng, phủ định) nằm ở danh
      sách chung của nhóm, được kiểm tra port lúc tra cứu.
    Nhờ vậy không phải duyệt toàn bộ rule cho mỗi gói.
    """

    def __init__(self) -> None:
        """Tạo kho rỗng."""
        self._rules: dict[int, Rule] = {}     # sid → rule, giữ thứ tự lúc nạp
        self._position: dict[int, int] = {}   # sid → thứ tự lúc nạp, để kết quả luôn theo một thứ tự
        self._by_port: defaultdict[str, defaultdict[int, list[Rule]]] = defaultdict(lambda: defaultdict(list))
        self._without_port: defaultdict[str, list[Rule]] = defaultdict(list)

    def __len__(self) -> int:
        """Số rule đang có trong kho."""
        return len(self._rules)

    def add(self, rule: Rule) -> bool:
        """Thêm một rule đã kiểm tra; trả False nếu sid đã có trong kho."""
        if rule.sid in self._rules:
            return False
        self._position[rule.sid] = len(self._rules)
        self._rules[rule.sid] = rule
        ports = rule.destination_ports.single_ports() or rule.source_ports.single_ports()
        if ports is None:
            self._without_port[rule.protocol].append(rule)
        else:
            for port in ports:
                self._by_port[rule.protocol][port].append(rule)
        return True

    def get(self, sid: int) -> Rule | None:
        """Lấy một rule theo sid."""
        return self._rules.get(sid)

    def candidates(self, protocol: str | None, source_port: int | None, destination_port: int | None) -> list[Rule]:
        """Trả các rule có giao thức và port khớp với gói, theo thứ tự lúc nạp.

        protocol là "TCP", "UDP" hoặc giá trị khác; gói không có port (ICMP...)
        thì truyền None và chỉ các rule không ràng buộc port được chọn.
        """
        found: dict[int, Rule] = {}
        for group in _RULE_GROUPS.get(protocol, ("ip",)):
            for rule in self._without_port.get(group, ()):
                found[rule.sid] = rule
            ports_of_group = self._by_port.get(group, {})
            for port in (source_port, destination_port):
                for rule in ports_of_group.get(port, ()):
                    found[rule.sid] = rule
        fitting = [rule for rule in found.values() if rule.ports_fit(source_port, destination_port)]
        return sorted(fitting, key=lambda rule: self._position[rule.sid])
