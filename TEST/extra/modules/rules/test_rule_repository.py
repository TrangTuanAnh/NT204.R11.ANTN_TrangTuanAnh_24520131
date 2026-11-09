"""Kiểm thử Rule Repository / Indexer: chọn đúng các rule cần xét theo giao thức và port."""

from __future__ import annotations

import pytest

from src.config import DEFAULT_RULE_VARIABLES
from src.rules.model import Rule
from src.rules.parser import parse_rule
from src.rules.repository import RuleRepository

HEADERS = {
    1: "alert ip any any -> any any",
    2: "alert tcp any any -> any any",
    3: "alert tcp any any -> any 80",
    4: "alert tcp any 80 -> any any",
    5: "alert tcp any any -> any 8000:8100",
    6: "alert tcp any any -> any !22",
    7: "alert tcp any any <> any 25",
    8: "alert tcp any 1000 -> any 2000",
    9: "alert tcp 10.0.0.5 any -> any 443",
    10: "alert udp any any -> any any",
    11: "alert udp any any -> any 53",
    12: "alert ip any any -> any 80",
}


def make_rule(sid: int, header: str):
    """Tạo một rule hợp lệ từ header."""
    parsed = parse_rule(f'{header} (msg:"x"; sid:{sid};)', DEFAULT_RULE_VARIABLES)
    assert parsed.rule is not None, parsed.reasons
    return parsed.rule


@pytest.fixture
def repository() -> RuleRepository:
    """Kho có đủ các loại rule trong HEADERS."""
    store = RuleRepository()
    for sid, header in HEADERS.items():
        assert store.add(make_rule(sid, header))
    return store


@pytest.mark.parametrize("protocol,source_port,destination_port,expected", [
    ("TCP", 40000, 80, [1, 2, 3, 6, 12]),
    ("TCP", 80, 40000, [1, 2, 4, 6]),
    ("TCP", 40000, 8080, [1, 2, 5, 6]),
    ("TCP", 40000, 22, [1, 2]),
    ("TCP", 40000, 25, [1, 2, 6, 7]),       # chiều xuôi của rule "<>"
    ("TCP", 25, 40000, [1, 2, 6, 7]),       # chiều ngược của rule "<>"
    ("TCP", 1000, 2000, [1, 2, 6, 8]),
    ("TCP", 2000, 1000, [1, 2, 6]),         # rule "->" không nhận chiều ngược
    ("TCP", 40000, 443, [1, 2, 6, 9]),      # lọc theo port, IP do bước so khớp kiểm tra
    ("UDP", 40000, 53, [1, 10, 11]),
    ("UDP", 40000, 123, [1, 10]),
    ("UDP", 40000, 80, [1, 10, 12]),
    (None, None, None, [1]),                # gói không có TCP/UDP như ICMP
    ("SCTP", None, None, [1]),
])
def test_candidates_by_protocol_and_port(repository, protocol, source_port, destination_port, expected):
    found = repository.candidates(protocol, source_port, destination_port)
    assert [rule.sid for rule in found] == expected


def test_rule_with_several_ports_is_returned_once():
    store = RuleRepository()
    store.add(make_rule(1, "alert tcp any any <> any [80,8080]"))
    assert [rule.sid for rule in store.candidates("TCP", 80, 8080)] == [1]


def test_duplicate_sid_is_refused():
    store = RuleRepository()
    assert store.add(make_rule(1, "alert tcp any any -> any 80"))
    assert not store.add(make_rule(1, "alert tcp any any -> any 81"))
    assert len(store) == 1 and store.get(1).destination_ports.single_ports() == [80]
    assert store.get(2) is None


def test_lookup_does_not_go_through_every_rule(monkeypatch):
    store = RuleRepository()
    for port in range(1, 1001):
        store.add(make_rule(port, f"alert tcp any any -> any {port}"))
    checked = []
    original = Rule.ports_fit

    def counting(rule, source_port, destination_port):
        """Ghi lại rule nào được đem ra kiểm tra port."""
        checked.append(rule.sid)
        return original(rule, source_port, destination_port)

    monkeypatch.setattr(Rule, "ports_fit", counting)
    assert [rule.sid for rule in store.candidates("TCP", 40000, 7)] == [7]
    assert checked == [7]
