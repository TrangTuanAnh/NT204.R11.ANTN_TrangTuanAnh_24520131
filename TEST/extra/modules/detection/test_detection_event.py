"""Kiểm thử Detection Event Generator: bản ghi có đủ các trường đề bài yêu cầu."""

from __future__ import annotations

import json

from src.config import DEFAULT_RULE_VARIABLES
from src.detection.generator import build_detection_event
from src.detection.matcher import PacketView, match_rule
from src.rules.parser import parse_rule


def make_rule(text: str):
    """Tạo một rule hợp lệ."""
    parsed = parse_rule(text, DEFAULT_RULE_VARIABLES, "a.rules", 3)
    assert parsed.rule is not None, parsed.reasons
    return parsed.rule


def test_detection_event_has_every_required_field(make_event):
    rule = make_rule('alert tcp any any -> any 80 (msg:"Directory traversal detected"; content:"../"; '
                     'classtype:web-application-attack; priority:1; sid:100001; rev:1;)')
    event = make_event(7.5, application={"protocol": "HTTP"}, flow_id="F123")
    result = match_rule(rule, PacketView(event, None, b"GET /../x"))
    detection = build_detection_event(rule, result, event)
    assert detection == {
        "timestamp": 7.5, "packet_id": 1,
        "sid": 100001, "rev": 1, "msg": "Directory traversal detected",
        "priority": 1, "classtype": "web-application-attack",
        "src_ip": "192.0.2.1", "src_port": 40000, "dst_ip": "192.0.2.2", "dst_port": 80,
        "protocol": "TCP", "application_protocol": "HTTP", "flow_id": "F123",
        "match": {"reversed_direction": False, "buffer": "payload",
                  "contents": [{"content": "../", "position": 5, "nocase": False, "negated": False}]},
        "rule_file": "a.rules", "rule_line": 3,
    }
    json.dumps(detection)


def test_fields_that_rule_does_not_set_are_null(make_event):
    rule = make_rule('alert tcp any any -> any any (msg:"a"; sid:1;)')
    event = make_event()
    detection = build_detection_event(rule, match_rule(rule, PacketView(event)), event)
    assert (detection["rev"], detection["priority"], detection["classtype"]) == (None, None, None)
    assert detection["flow_id"] is None and detection["application_protocol"] is None


def test_application_protocol_falls_back_to_the_flow(make_event):
    rule = make_rule('alert tcp any any -> any any (msg:"a"; sid:1;)')
    event = make_event()
    detection = build_detection_event(rule, match_rule(rule, PacketView(event)), event,
                                      {"application_protocol": "HTTP"})
    assert detection["application_protocol"] == "HTTP"


def test_packet_without_ports_has_protocol_ip(make_event):
    rule = make_rule('alert ip any any -> any any (msg:"a"; sid:1;)')
    event = make_event(transport=None)
    detection = build_detection_event(rule, match_rule(rule, PacketView(event)), event)
    assert (detection["protocol"], detection["src_port"], detection["dst_port"]) == ("IP", None, None)
    assert detection["src_ip"] == "192.0.2.1"
