"""Kiểm thử Rule Parser & Validator: header, tùy chọn và phân loại valid / invalid / unsupported."""

from __future__ import annotations

import ipaddress

import pytest

from src.config import DEFAULT_RULE_VARIABLES
from src.rules.parser import INVALID, UNSUPPORTED, VALID, parse_rule

HEADER = "alert tcp any any -> any 80"


def parse(text: str, variables: dict[str, str] | None = None):
    """Phân tích một rule với các biến mặc định."""
    return parse_rule(text, DEFAULT_RULE_VARIABLES if variables is None else variables, "a.rules", 7)


def valid(options: str, header: str = HEADER):
    """Phân tích rule phải hợp lệ rồi trả đối tượng Rule."""
    parsed = parse(f"{header} ({options})")
    assert parsed.status == VALID, parsed.reasons
    return parsed.rule


# ------------------------------------------------------------------ header

def test_header_with_any_values():
    rule = valid('msg:"x"; sid:1; rev:2;', "alert tcp any any -> any any")
    assert (rule.action, rule.protocol, rule.direction) == ("alert", "tcp", "->")
    assert rule.source.is_any and rule.source_ports.is_any and rule.destination.is_any
    assert rule.destination_ports.is_any
    assert (rule.sid, rule.rev, rule.msg, rule.file, rule.line) == (1, 2, "x", "a.rules", 7)


def test_header_with_single_ip_cidr_port_and_range():
    rule = valid('msg:"x"; sid:1;', "alert udp 10.0.0.5 1024:65535 <> 192.168.1.0/24 53")
    assert rule.protocol == "udp" and rule.direction == "<>"
    assert rule.source.include == (ipaddress.ip_network("10.0.0.5/32"),)
    assert rule.destination.include == (ipaddress.ip_network("192.168.1.0/24"),)
    assert rule.source_ports.include == ((1024, 65535),)
    assert rule.destination_ports.include == ((53, 53),)


@pytest.mark.parametrize("text,inside,outside", [
    (":1023", [0, 1023], [1024]),
    ("1024:", [1024, 65535], [1023]),
    ("80:90", [80, 90], [79, 91]),
    ("!80", [79, 81], [80]),
    ("!6000:6010", [5999, 6011], [6000, 6010]),
    ("[80,443,8000:8010]", [80, 443, 8005], [81, 8011]),
    ("![80,443]", [81], [80, 443]),
    ("$SSH_PORTS", [22], [23]),
    ("$FILE_DATA_PORTS", [80, 110, 143], [1]),
    ("$SHELLCODE_PORTS", [81], [80]),
])
def test_port_forms(text, inside, outside):
    ports = valid('msg:"x"; sid:1;', f"alert tcp any any -> any {text}").destination_ports
    assert all(ports.contains(port) for port in inside)
    assert not any(ports.contains(port) for port in outside)


@pytest.mark.parametrize("text,inside,outside", [
    ("10.0.0.5", ["10.0.0.5"], ["10.0.0.6"]),
    ("10.0.0.5/24", ["10.0.0.200"], ["10.0.1.1"]),
    ("!192.168.1.0/24", ["10.0.0.1"], ["192.168.1.9"]),
    ("[192.168.1.0/24,10.1.1.0/24]", ["10.1.1.1", "192.168.1.1"], ["10.1.2.1"]),
    ("![192.168.1.0/24,10.1.1.0/24]", ["10.1.2.1"], ["10.1.1.1", "192.168.1.1"]),
    ("[10.0.0.0/8,!10.1.0.0/16]", ["10.2.0.1"], ["10.1.0.1", "11.0.0.1"]),
    ("$HOME_NET", ["8.8.8.8"], []),
])
def test_address_forms(text, inside, outside):
    addresses = valid('msg:"x"; sid:1;', f"alert tcp {text} any -> any any").source
    assert all(addresses.contains(address) for address in inside)
    assert not any(addresses.contains(address) for address in outside)


def test_variables_follow_the_configuration():
    parsed = parse('alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"x"; sid:1;)',
                   {"HOME_NET": "10.0.0.0/8", "EXTERNAL_NET": "!$HOME_NET", "HTTP_PORTS": "[80,8080]"})
    rule = parsed.rule
    assert parsed.status == VALID
    assert rule.destination.contains("10.1.1.1") and not rule.destination.contains("8.8.8.8")
    assert rule.source.contains("8.8.8.8") and not rule.source.contains("10.1.1.1")
    assert rule.destination_ports.single_ports() == [80, 8080]


@pytest.mark.parametrize("header", [
    "alert tcp any any any 80",                  # thiếu chiều
    "alert tcp any any => any 80",               # chiều sai
    "alert tcp any any <- any 80",               # Snort không có chiều này
    "alert tcp 999.1.1.1 any -> any 80",         # IP sai
    "alert tcp 10.0.0.0/33 any -> any 80",       # CIDR sai
    "alert tcp any 70000 -> any 80",             # port quá lớn
    "alert tcp any 90:80 -> any 80",             # khoảng ngược
    "alert tcp any abc -> any 80",               # port không phải số
    "alert tcp any : -> any 80",                 # khoảng không có đầu nào
    "alert tcp !any any -> any 80",              # phủ định any
    "alert tcp [10.0.0.1 any -> any 80",         # danh sách thiếu dấu đóng
    "alert tcp $KHONG_CO any -> any 80",         # biến chưa khai báo
    "alert http any any -> any 80",              # giao thức lạ
    "nothing tcp any any -> any 80",             # hành động lạ
])
def test_wrong_header_is_invalid(header):
    parsed = parse(f'{header} (msg:"x"; sid:1;)')
    assert parsed.status == INVALID and parsed.rule is None and parsed.reasons


@pytest.mark.parametrize("header", ["drop tcp any any -> any 80", "log tcp any any -> any 80",
                                    "alert icmp any any -> any any"])
def test_action_or_protocol_out_of_scope_is_unsupported(header):
    parsed = parse(f'{header} (msg:"x"; sid:1;)')
    assert parsed.status == UNSUPPORTED and parsed.rule is None and parsed.sid == 1


def test_variable_pointing_to_itself_does_not_hang():
    parsed = parse('alert tcp $A any -> any any (msg:"x"; sid:1;)', {"A": "$A"})
    assert parsed.status == INVALID


# ------------------------------------------------------------------ cấu trúc rule

@pytest.mark.parametrize("text,reason", [
    ("alert tcp any any -> any 80", 'thiếu dấu "("'),
    ('alert tcp any any -> any 80 (msg:"x"; sid:1;', 'kết thúc bằng dấu ")"'),
    ('alert tcp any any -> any 80 (msg:"x; sid:1;)', 'thiếu dấu " đóng'),
    ('alert tcp any any -> any 80 (sid:1;)', "thiếu keyword bắt buộc msg"),
    ('alert tcp any any -> any 80 (msg:"x";)', "thiếu keyword bắt buộc sid"),
    ('alert tcp any any -> any 80 (msg:"x"; sid:abc;)', "Keyword sid không hợp lệ"),
    ('alert tcp any any -> any 80 (msg:"x"; sid:0;)', "Keyword sid không hợp lệ"),
    ('alert tcp any any -> any 80 (msg:"x"; sid:1; sid:2;)', "xuất hiện nhiều lần"),
    ('alert tcp any any -> any 80 (msg:x; sid:1;)', "Keyword msg không hợp lệ"),
    ('alert tcp any any -> any 80 (msg:"x"; sid:1; rev:a;)', "Keyword rev không hợp lệ"),
    ('alert tcp any any -> any 80 (msg:"x"; sid:1; priority:a;)', "Keyword priority không hợp lệ"),
    ('alert tcp any any -> any 80 (msg:"x"; sid:1; classtype:"a b";)', "Keyword classtype không hợp lệ"),
    ('alert tcp any any -> any 80 (msg:"x"; sid:1; bad-name:1;)', "Tùy chọn sai dạng"),
])
def test_wrong_rule_is_invalid_with_a_reason(text, reason):
    parsed = parse(text)
    assert parsed.status == INVALID and parsed.rule is None
    assert any(reason in item for item in parsed.reasons), parsed.reasons


def test_invalid_value_does_not_also_report_missing_keyword():
    assert parse(f'{HEADER} (msg:x; sid:1;)').reasons == ["Keyword msg không hợp lệ (x): phải đặt trong cặp "
                                                          "dấu nháy kép"]


def test_last_option_may_omit_the_semicolon_like_the_lecture_examples():
    rule = valid('msg: "ICMP detected"; sid: 100005', "alert tcp any any -> 192.168.1.1 any")
    assert (rule.msg, rule.sid) == ("ICMP detected", 100005)


def test_semicolon_and_quote_can_be_escaped_in_msg():
    assert valid(r'msg:"a\;b\"c\\d"; sid:1;').msg == 'a;b"c\\d'


def test_classification_fields():
    rule = valid('msg:"x"; classtype:web-application-attack; priority:1; sid:1; rev:3;')
    assert (rule.classtype, rule.priority, rule.rev) == ("web-application-attack", 1, 3)


# ------------------------------------------------------------------ keyword ngoài phạm vi

@pytest.mark.parametrize("option", ['pcre:"/x/"', "byte_test:1,>,0,0", "byte_jump:1,0", "metadata:service http",
                                    "reference:cve,1", "gid:1", "flowbits:set,x", "tag:session,5,packets",
                                    "khong_co_keyword:1", 'uricontent:"x"'])
def test_keyword_out_of_scope_makes_rule_unsupported(option):
    parsed = parse(f'{HEADER} (msg:"x"; {option}; sid:1;)')
    assert parsed.status == UNSUPPORTED and parsed.rule is None
    assert parsed.unsupported_keywords == [option.partition(":")[0]]
    assert parsed.reasons == [f"Keyword {option.partition(':')[0]} ngoài phạm vi hỗ trợ"]


@pytest.mark.parametrize("modifier", ["http_uri", "fast_pattern", "rawbytes"])
def test_content_modifier_out_of_scope_makes_rule_unsupported(modifier):
    assert parse(f'{HEADER} (msg:"x"; content:"a"; {modifier}; sid:1;)').status == UNSUPPORTED


@pytest.mark.parametrize("value", ["from_client", "from_server", "stateless", "no_stream", "only_frag"])
def test_flow_value_out_of_scope_makes_rule_unsupported(value):
    parsed = parse(f'{HEADER} (msg:"x"; flow:{value},established; sid:1;)')
    assert parsed.status == UNSUPPORTED and parsed.unsupported_keywords == [f"flow:{value}"]


def test_content_modifier_using_variable_of_out_of_scope_keyword_is_still_unsupported():
    parsed = parse(f'{HEADER} (msg:"x"; byte_extract:1,0,len; content:"a"; within:len; sid:1;)')
    assert parsed.status == UNSUPPORTED


def test_modifier_after_out_of_scope_content_keyword_is_unsupported():
    assert parse(f'{HEADER} (msg:"x"; uricontent:"a"; nocase; sid:1;)').status == UNSUPPORTED


def test_syntax_error_is_reported_before_out_of_scope_keyword():
    parsed = parse(f'{HEADER} (msg:"x"; pcre:"/x/"; sid:abc;)')
    assert parsed.status == INVALID


def test_same_out_of_scope_keyword_is_reported_once():
    parsed = parse(f'{HEADER} (msg:"x"; reference:a,1; reference:a,2; sid:1;)')
    assert parsed.reasons == ["Keyword reference ngoài phạm vi hỗ trợ"]


# ------------------------------------------------------------------ content

def test_content_with_text_and_hex():
    content = valid('msg:"x"; content:"ab|00 FF|c"; sid:1;').contents[0]
    assert content.pattern == b"ab\x00\xffc" and content.text == "ab|00 FF|c" and not content.negated


def test_content_escapes_and_negation():
    content = valid(r'msg:"x"; content:!"a\;b\"c\\d\:e"; sid:1;').contents[0]
    assert content.pattern == b'a;b"c\\d:e' and content.negated


def test_several_contents_keep_their_modifiers():
    first, second = valid('msg:"x"; content:"ab"; nocase; offset:1; depth:5; '
                          'content:"cd"; distance:2; within:4; sid:1;').contents
    assert (first.nocase, first.offset, first.depth, first.distance) == (True, 1, 5, None)
    assert (second.nocase, second.distance, second.within, second.offset) == (False, 2, 4, None)
    assert second.is_relative and not first.is_relative


def test_offset_and_distance_may_be_negative_as_in_the_manual():
    first, second = valid('msg:"x"; content:"ab"; offset:-1; content:"cd"; distance:-3; sid:1;').contents
    assert first.offset == -1 and second.distance == -3


@pytest.mark.parametrize("options", [
    'content:"";',                              # chuỗi rỗng
    "content:abc;",                             # thiếu dấu nháy
    "content;",                                 # thiếu giá trị
    'content:"a"b";',                           # dấu nháy trơ ở giữa
    'content:"|0|";',                           # hex lẻ chữ số
    'content:"|GG|";',                          # không phải hex
    'content:"|00";',                           # thiếu dấu | đóng
    r'content:"a\zb";',                         # dấu \ đứng trước ký tự không cần
    'content:"a;b";',                           # dấu ; chưa viết thành \;
    "nocase;",                                  # không có content đứng trước
    "offset:1;",
    "depth:1;",
    "distance:1;",
    "within:1;",
    'content:"a"; nocase:1;',                   # nocase không nhận giá trị
    'content:"abc"; depth:2;',                  # depth nhỏ hơn độ dài chuỗi
    'content:"abc"; within:2;',                 # within nhỏ hơn độ dài chuỗi
    'content:"a"; depth:0;',                    # depth nhỏ nhất là 1
    'content:"a"; depth:65536;',                # vượt giá trị lớn nhất
    'content:"a"; offset:70000;',
    'content:"a"; offset:x;',
    'content:"a"; offset:1; offset:2;',         # lặp trên cùng một content
    'content:"a"; offset:1; within:5;',         # không dùng chung tuyệt đối và tương đối
    'content:"a"; distance:1; depth:5;',
])
def test_wrong_content_options_are_invalid(options):
    parsed = parse(f'{HEADER} (msg:"x"; {options} sid:1;)')
    assert parsed.status == INVALID and parsed.rule is None, parsed.reasons


# ------------------------------------------------------------------ flags, dsize, flow

@pytest.mark.parametrize("value,modifier,flags,ignored", [
    ("S", "", "S", ""), ("AS", "", "SA", ""), ("+A", "+", "A", ""), ("A+", "+", "A", ""), ("*FR", "*", "FR", ""),
    ("!R", "!", "R", ""), ("0", "", "", ""), ("sa", "", "SA", ""), ("S,CE", "", "S", "CE"), ("SF,12", "", "FS", "CE"),
])
def test_flags_forms(value, modifier, flags, ignored):
    option = valid(f'msg:"x"; flags:{value}; sid:1;').flags
    assert (option.modifier, option.flags, option.ignored) == (modifier, flags, ignored)


@pytest.mark.parametrize("value", ["X", "", "+*S", "S,X", "0A", "+A+"])
def test_wrong_flags_are_invalid(value):
    assert parse(f'{HEADER} (msg:"x"; flags:{value}; sid:1;)').status == INVALID


@pytest.mark.parametrize("value,operator,low,high", [
    ("5", "=", 5, None), (">100", ">", 100, None), ("< 3", "<", 3, None), ("300<>400", "<>", 300, 400),
])
def test_dsize_forms(value, operator, low, high):
    option = valid(f'msg:"x"; dsize:{value}; sid:1;').dsize
    assert (option.operator, option.low, option.high) == (operator, low, high)


@pytest.mark.parametrize("value", ["abc", "", "400<>300", ">", "-1", "1<>"])
def test_wrong_dsize_is_invalid(value):
    assert parse(f'{HEADER} (msg:"x"; dsize:{value}; sid:1;)').status == INVALID


@pytest.mark.parametrize("value,direction,state", [
    ("to_server,established", "to_server", "established"),
    ("established,to_client", "to_client", "established"),
    ("not_established", None, "not_established"),
    ("to_server", "to_server", None),
])
def test_flow_forms(value, direction, state):
    option = valid(f'msg:"x"; flow:{value}; sid:1;').flow
    assert (option.direction, option.state) == (direction, state)


@pytest.mark.parametrize("value", ["abc", "", "to_server,to_client", "established,not_established"])
def test_wrong_flow_is_invalid(value):
    assert parse(f'{HEADER} (msg:"x"; flow:{value}; sid:1;)').status == INVALID


def test_describe_gives_plain_json_data():
    data = valid('msg:"x"; content:"a"; flags:S; dsize:>1; flow:to_server; sid:1; rev:1;',
                 "alert tcp 10.0.0.0/8 1:2 -> !10.1.1.1 80").describe()
    assert data["source"] == {"any": False, "include": ["10.0.0.0/8"], "exclude": []}
    assert data["source_ports"] == {"any": False, "include": [[1, 2]], "exclude": []}
    assert data["destination"] == {"any": False, "include": [], "exclude": ["10.1.1.1/32"]}
    assert data["contents"][0]["hex"] == "61"
    assert data["flags"] == {"modifier": "", "flags": "S", "ignored": ""}
    assert data["dsize"] == {"operator": ">", "low": 1, "high": None}
    assert data["flow"] == {"direction": "to_server", "state": None}
