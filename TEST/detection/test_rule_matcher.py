"""Kiểm thử Rule Matching Engine: header, flow, cờ TCP, kích thước và content."""

from __future__ import annotations

import pytest

from src.config import DEFAULT_RULE_VARIABLES
from src.detection.matcher import (CONTENT, FLOW, HEADER, MATCH, NO_MATCH, PACKET, PacketView, find_contents,
                                   match_rule)
from src.rules.parser import parse_rule

ANY_HEADER = "alert tcp any any -> any any"
ESTABLISHED_REQUEST = {"to_server": True, "established": True, "direction": "forward", "state": "ESTABLISHED"}


def make_rule(options: str, header: str = ANY_HEADER):
    """Tạo một rule hợp lệ từ header và tùy chọn."""
    parsed = parse_rule(f'{header} (msg:"x"; {options} sid:1;)', DEFAULT_RULE_VARIABLES)
    assert parsed.rule is not None, parsed.reasons
    return parsed.rule


def verdict(rule, event, flow=None, payload=None) -> str:
    """So khớp rồi chỉ trả MATCH hoặc NO_MATCH."""
    return match_rule(rule, PacketView(event, flow, payload)).verdict


def contents_fit(options: str, payload: bytes) -> bool:
    """Rule có các content cho trước có khớp với dữ liệu này không."""
    rule = make_rule(options)
    return find_contents(rule.contents, payload, payload.lower()) is not None


# ------------------------------------------------------------------ header

@pytest.mark.parametrize("header,expected", [
    ("alert tcp any any -> any any", MATCH),
    ("alert ip any any -> any any", MATCH),
    ("alert udp any any -> any any", NO_MATCH),
    ("alert tcp 192.0.2.1 any -> any any", MATCH),
    ("alert tcp 192.0.2.0/24 any -> 192.0.2.2 any", MATCH),
    ("alert tcp 192.0.3.0/24 any -> any any", NO_MATCH),
    ("alert tcp any any -> 192.0.2.3 any", NO_MATCH),
    ("alert tcp !192.0.2.1 any -> any any", NO_MATCH),
    ("alert tcp any 40000 -> any 80", MATCH),
    ("alert tcp any 39000:41000 -> any :100", MATCH),
    ("alert tcp any any -> any 81", NO_MATCH),
    ("alert tcp any 80 -> any 40000", NO_MATCH),
])
def test_header(make_event, header, expected):
    assert verdict(make_rule("", header), make_event()) == expected


def test_one_way_rule_does_not_match_the_opposite_direction(make_event):
    rule = make_rule("", "alert tcp 192.0.2.1 any -> 192.0.2.2 80")
    assert verdict(rule, make_event()) == MATCH
    assert verdict(rule, make_event(reverse=True)) == NO_MATCH


def test_two_way_rule_matches_both_directions_and_says_which(make_event):
    rule = make_rule("", "alert tcp 192.0.2.1 any <> 192.0.2.2 80")
    same = match_rule(rule, PacketView(make_event()))
    opposite = match_rule(rule, PacketView(make_event(reverse=True)))
    assert (same.verdict, same.matched["reversed_direction"]) == (MATCH, False)
    assert (opposite.verdict, opposite.matched["reversed_direction"]) == (MATCH, True)


def test_two_way_rule_still_needs_both_ends_to_fit(make_event):
    rule = make_rule("", "alert tcp 192.0.2.1 any <> 192.0.2.9 80")
    assert verdict(rule, make_event()) == NO_MATCH and verdict(rule, make_event(reverse=True)) == NO_MATCH


def test_ip_rule_matches_packet_without_ports(make_event):
    event = make_event(transport=None)
    assert verdict(make_rule("", "alert ip any any -> any any"), event) == MATCH
    assert verdict(make_rule("", "alert ip any any -> any 80"), event) == NO_MATCH
    assert verdict(make_rule("", "alert tcp any any -> any any"), event) == NO_MATCH


def test_header_is_checked_before_content(make_event):
    rule = make_rule('content:"GET";', "alert tcp 10.9.9.9 any -> any any")
    result = match_rule(rule, PacketView(make_event(), None, b"GET /"))
    assert (result.verdict, result.failed_at, result.reached_content) == (NO_MATCH, HEADER, False)


# ------------------------------------------------------------------ flow

@pytest.mark.parametrize("option,flow,expected", [
    ("to_server,established", ESTABLISHED_REQUEST, MATCH),
    ("to_server", ESTABLISHED_REQUEST, MATCH),
    ("established", ESTABLISHED_REQUEST, MATCH),
    ("to_client", ESTABLISHED_REQUEST, NO_MATCH),
    ("not_established", ESTABLISHED_REQUEST, NO_MATCH),
    ("to_client,established", {**ESTABLISHED_REQUEST, "to_server": False}, MATCH),
    ("to_server,established", {**ESTABLISHED_REQUEST, "established": False}, NO_MATCH),
    ("not_established", {**ESTABLISHED_REQUEST, "established": False}, MATCH),
    ("established", None, NO_MATCH),
    ("not_established", None, NO_MATCH),
])
def test_flow(make_event, option, flow, expected):
    result = match_rule(make_rule(f"flow:{option};"), PacketView(make_event(), flow))
    assert result.verdict == expected
    assert result.failed_at == (None if expected == MATCH else FLOW)


# ------------------------------------------------------------------ cờ TCP và kích thước

@pytest.mark.parametrize("option,flags,expected", [
    ("S", "S", MATCH),
    ("S", "SA", NO_MATCH),
    ("SA", "SA", MATCH),
    ("AS", "SA", MATCH),
    ("+S", "SA", MATCH),
    ("+SF", "SA", NO_MATCH),
    ("*SF", "SA", MATCH),
    ("*FR", "SA", NO_MATCH),
    ("!R", "SA", MATCH),
    ("!A", "SA", NO_MATCH),
    ("0", "", MATCH),
    ("0", "A", NO_MATCH),
    ("S,CE", "SEC", MATCH),
    ("S", "SEC", NO_MATCH),
    ("S", "SN", MATCH),
])
def test_flags(make_event, option, flags, expected):
    assert verdict(make_rule(f"flags:{option};"), make_event(flags=flags)) == expected


def test_flags_do_not_match_packet_without_tcp_flags(make_event):
    rule = make_rule("flags:!R;", "alert ip any any -> any any")
    assert verdict(rule, make_event(protocol="UDP")) == NO_MATCH
    assert verdict(rule, make_event(flags=None)) == NO_MATCH


@pytest.mark.parametrize("option,size,expected", [
    ("5", 5, MATCH), ("5", 6, NO_MATCH),
    (">5", 6, MATCH), (">5", 5, NO_MATCH),
    ("<5", 4, MATCH), ("<5", 5, NO_MATCH),
    ("3<>5", 3, MATCH), ("3<>5", 5, MATCH), ("3<>5", 2, NO_MATCH), ("3<>5", 6, NO_MATCH),
])
def test_dsize(make_event, option, size, expected):
    event = make_event()
    event["transport"]["payload_length"] = size
    result = match_rule(make_rule(f"dsize:{option};"), PacketView(event))
    assert result.verdict == expected
    assert result.failed_at == (None if expected == MATCH else PACKET)


def test_dsize_uses_payload_when_length_field_is_missing(make_event):
    event = make_event()
    event["transport"]["payload_length"] = None
    assert verdict(make_rule("dsize:3;"), event, payload=b"abc") == MATCH
    assert verdict(make_rule("dsize:3;"), event) == NO_MATCH


# ------------------------------------------------------------------ content

@pytest.mark.parametrize("options,payload,expected", [
    ('content:"GET";', b"xxGETxx", True),
    ('content:"GET";', b"xxgetxx", False),
    ('content:"get"; nocase;', b"xxGETxx", True),
    ('content:"GeT"; nocase;', b"xxgEtxx", True),
    ('content:"|00 01|";', b"a\x00\x01b", True),
    ('content:"|00 01|";', b"a\x00\x02b", False),
    ('content:"|41|";nocase;', b"a", True),
    ('content:!"GET";', b"POST /", True),
    ('content:!"GET";', b"GET /", False),
    # offset và depth
    ('content:"GET"; depth:3;', b"GET /", True),
    ('content:"GET"; depth:3;', b" GET /", False),
    ('content:"GET"; offset:1;', b"GET /", False),
    ('content:"GET"; offset:1;', b" GET /", True),
    ('content:"abc"; offset:2; depth:3;', b"xxabc", True),
    ('content:"abc"; offset:2; depth:3;', b"xxxabc", False),
    ('content:"abc"; offset:-5;', b"abc", True),
    ('content:!"abc"; depth:3;', b"xxxabc", True),
    # distance và within
    ('content:"ABC"; content:"DEF"; distance:1;', b"ABCxDEF", True),
    ('content:"ABC"; content:"DEF"; distance:1;', b"ABCDEF", False),
    ('content:"ABC"; content:"DEF"; within:3;', b"ABCDEF", True),
    ('content:"ABC"; content:"DEF"; within:3;', b"ABCxDEF", False),
    ('content:"ABC"; content:"DEF"; within:10;', b"DEFABC", False),
    ('content:"ABC"; content:"DEF"; distance:1; within:4;', b"ABCxDEF", True),
    ('content:"ABC"; content:"DEF"; distance:1; within:3;', b"ABCxxDEF", False),
    ('content:"ABC"; content:"BC"; distance:-2; within:2;', b"ABC", True),
    # content thường sau content khác được tìm từ đầu dữ liệu, không phụ thuộc vị trí trước
    ('content:"DEF"; content:"ABC";', b"ABCDEF", True),
    # phải quay lại thử chỗ xuất hiện tiếp theo của content trước
    ('content:"ABC"; content:"DEF"; within:3;', b"ABCxxABCDEF", True),
    # phủ định tính từ vị trí của content trước
    ('content:"ABC"; content:!"DEF"; within:3;', b"ABCxxxDEF", True),
    ('content:"ABC"; content:!"DEF"; within:3;', b"ABCDEF", False),
])
def test_contents(options, payload, expected):
    assert contents_fit(options, payload) is expected


def test_position_of_each_content_is_reported():
    rule = make_rule('content:"ABC"; content:"DEF"; distance:1;')
    assert find_contents(rule.contents, b"xABCyDEF", b"xabcydef") == [
        {"content": "ABC", "position": 1, "nocase": False, "negated": False},
        {"content": "DEF", "position": 5, "nocase": False, "negated": False},
    ]


def test_repeated_data_cannot_make_the_search_run_forever():
    rule = make_rule(" ".join(['content:"a";'] * 12) + ' content:"b"; distance:0;')
    assert find_contents(rule.contents, b"a" * 3000, b"a" * 3000) is None


def test_rule_with_content_does_not_match_packet_without_data(make_event):
    result = match_rule(make_rule('content:"GET";'), PacketView(make_event(), None, b""))
    assert (result.verdict, result.failed_at, result.reached_content) == (NO_MATCH, CONTENT, True)


def test_match_result_carries_sid_and_matched_information(make_event):
    result = match_rule(make_rule('flow:to_server; flags:A; dsize:0; content:"GET";'),
                        PacketView(make_event(), ESTABLISHED_REQUEST, b"GET /"))
    assert result.sid == 1 and result.matched["buffer"] == "payload"
    assert result.matched["flags"] == "A" and result.matched["dsize"] == 0
    assert result.matched["flow"] == {"direction": "forward", "state": "ESTABLISHED", "established": True}
    assert result.matched["contents"][0]["content"] == "GET"


# ------------------------------------------------------------------ dữ liệu ứng dụng đã giải mã

def http_event(make_event, **application) -> dict:
    """Event HTTP với các trường cho trước."""
    return make_event(application={"protocol": "HTTP", "message_type": "request", "method": "GET",
                                   "version": "HTTP/1.1", "headers": {"host": "a.test"}, **application})


def test_encoded_traversal_is_found_in_decoded_uri(make_event):
    event = http_event(make_event, uri="/a/..%2f..%2fetc")
    event["decoded"] = {"uri": "/a/../../etc", "body": None}
    result = match_rule(make_rule('content:"../";'), PacketView(event, None, b"GET /a/..%2f..%2fetc HTTP/1.1\r\n\r\n"))
    assert result.verdict == MATCH and result.matched["buffer"] == "application"


def test_raw_payload_is_searched_first(make_event):
    event = http_event(make_event, uri="/a/../b")
    event["decoded"] = {"uri": "/a/../b", "body": None}
    result = match_rule(make_rule('content:"../";'), PacketView(event, None, b"GET /a/../b HTTP/1.1\r\n\r\n"))
    assert result.matched["buffer"] == "payload"


def test_contents_must_be_found_together_in_one_buffer(make_event):
    event = http_event(make_event, uri="/%2e%2e/x")
    event["decoded"] = {"uri": "/../x", "body": None}
    rule = make_rule('content:"%2e%2e"; content:"../";')
    assert verdict(rule, event, payload=b"GET /%2e%2e/x HTTP/1.1\r\n\r\n") == NO_MATCH


def test_event_from_file_is_searched_in_application_data(make_event):
    event = http_event(make_event, uri="/login", body="user=admin")
    assert verdict(make_rule('content:"GET /login";'), event) == MATCH
    assert verdict(make_rule('content:"user=admin";'), event) == MATCH
    assert verdict(make_rule('content:"host: a.test";'), event) == MATCH


def test_http_response_fields_are_searched(make_event):
    event = make_event(application={"protocol": "HTTP", "message_type": "response", "version": "HTTP/1.1",
                                    "status_code": 404, "reason": "Not Found", "headers": {}, "body": "x"})
    assert verdict(make_rule('content:"404 Not Found";'), event) == MATCH


def test_decoded_html_body_is_searched(make_event):
    event = http_event(make_event, uri="/", body="&lt;script&gt;")
    event["decoded"] = {"uri": "/", "body": "<script>"}
    assert verdict(make_rule('content:"<script>";'), event) == MATCH


def test_dns_names_are_searched(make_event):
    event = make_event(protocol="UDP", application={
        "protocol": "DNS", "questions": [{"name": "evil.example.test", "type": 1}],
        "answers": [{"name": "evil.example.test", "type": 1, "data": "192.0.2.9"}]})
    rule = make_rule('content:"evil.example.test";', "alert udp any any -> any any")
    assert verdict(rule, event) == MATCH
    assert verdict(make_rule('content:"192.0.2.9";', "alert udp any any -> any any"), event) == MATCH


@pytest.mark.parametrize("application,decoded,text", [
    ({"protocol": "SMTP", "message_type": "command", "command": "MAIL", "argument": "FROM:<a@b>"}, {}, "FROM:<a@b>"),
    ({"protocol": "SMTP", "message_type": "response", "status_code": 550, "message": "denied"}, {}, "550 denied"),
    ({"protocol": "SMTP", "message_type": "data", "headers": {}, "body": "eGluIGNow6Bv"},
     {"headers": {"subject": "bao cao"}, "body": "noi dung da giai ma"}, "noi dung da giai ma"),
    ({"protocol": "SMTP", "message_type": "data", "headers": {}, "body": "x"},
     {"headers": {"subject": "bao cao"}, "body": "y"}, "subject: bao cao"),
    ({"protocol": None}, {"text": "chu thuong"}, "chu thuong"),
])
def test_other_application_data_is_searched(make_event, application, decoded, text):
    event = make_event(application=application, decoded=decoded)
    assert verdict(make_rule(f'content:"{text}";'), event) == MATCH


@pytest.mark.parametrize("application", ["sai kieu", None, {"protocol": "HTTP", "headers": ["x"], "uri": 5},
                                         {"protocol": "DNS", "answers": "x", "questions": [1]}])
def test_strange_application_data_does_not_raise(make_event, application):
    assert verdict(make_rule('content:"khong_co";'), make_event(application=application)) == NO_MATCH
