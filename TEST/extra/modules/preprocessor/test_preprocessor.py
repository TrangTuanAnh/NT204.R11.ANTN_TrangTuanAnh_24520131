"""Kiểm thử module Preprocessor: kiểm tra trường, chuẩn hóa, dữ liệu thiếu/chưa hỗ trợ và metadata."""

from __future__ import annotations

import math

import pytest

from src.config import Config
from src.preprocessor import preprocess_event
from src.preprocessor.normalize import normalize_uri


def prepare(event: dict, config: Config | None = None) -> dict:
    """Chạy Preprocessor rồi trả lại chính event để kiểm tra cho gọn."""
    preprocess_event(event, config or Config())
    return event


def test_parser_event_is_valid_and_processed(make_event):
    event = prepare(make_event())
    assert (event["preprocess_status"], event["processing_action"], event["reason"]) == ("valid", "process", [])


def test_names_and_addresses_are_normalized(make_event):
    event = make_event(flags="ap", application={
        "protocol": " http ", "uri": "/", "headers": {"HOST": "WWW.Example.TEST.:8080", "Accept": " */* "}})
    event["transport"]["protocol"] = "tcp"
    event["network"].update(src_ip=" 192.0.2.1 ")
    prepare(event)
    assert event["transport"]["protocol"] == "TCP"
    assert event["transport"]["flags"] == "PA"
    assert event["network"]["src_ip"] == "192.0.2.1"
    assert event["application"]["protocol"] == "HTTP"
    assert event["application"]["headers"] == {"host": "www.example.test:8080", "accept": "*/*"}


def test_dns_names_and_answer_data_are_normalized(make_event):
    event = make_event(protocol="UDP", application={
        "protocol": "dns", "questions": [{"name": "A.Example.TEST.", "type": 1}],
        "answers": [{"name": "A.example.test", "type": 1, "data": "192.0.2.9"},
                    {"name": "a.example.test", "type": 28, "data": "2001:DB8:0::1"},
                    {"name": "a.example.test", "type": 12, "data": "PTR.Example."}]})
    event["network"].update(version=6, src_ip="2001:DB8::A", dst_ip="2001:db8:0:0::b")
    prepare(event)
    assert event["network"]["src_ip"] == "2001:db8::a" and event["network"]["dst_ip"] == "2001:db8::b"
    assert event["application"]["questions"] == [{"name": "a.example.test", "type": 1}]
    assert [answer["data"] for answer in event["application"]["answers"]] == ["192.0.2.9", "2001:db8::1", "ptr.example"]
    assert event["preprocess_status"] == "valid"


@pytest.mark.parametrize("value,seconds", [
    (1700000000, 1700000000.0), (1.5, 1.5), ("1700000000.5", 1700000000.5),
    ("2026-10-02T07:00:00+07:00", 1790899200.0), ("2026-10-02T00:00:00Z", 1790899200.0),
])
def test_valid_timestamps_become_unix_seconds(make_event, value, seconds):
    event = prepare(make_event(timestamp=value))
    assert event["timestamp"] == seconds and event["preprocess_status"] == "valid"


@pytest.mark.parametrize("value", [None, "2026-10-02T07:00:00", "hôm qua", "NaN", -1, True, math.inf, [1]])
def test_bad_timestamps_make_event_invalid(make_event, value):
    event = prepare(make_event(timestamp=value))
    assert event["timestamp"] is None
    assert (event["preprocess_status"], event["processing_action"]) == ("invalid", "skip")
    assert event["reason"]


@pytest.mark.parametrize("section,name", [("network", "src_ip"), ("network", "dst_ip"),
                                          ("transport", "src_port"), ("transport", "dst_port")])
def test_missing_required_field_is_invalid(make_event, section, name):
    event = make_event()
    del event[section][name]
    prepare(event)
    assert (event["preprocess_status"], event["processing_action"]) == ("invalid", "skip")
    assert event["reason"] == [f"Thiếu {section}.{name}"]
    assert event[section][name] is None


@pytest.mark.parametrize("section,name,value", [
    ("network", "ttl", 300), ("network", "version", 5), ("network", "more_fragments", "yes"),
    ("network", "src_ip", "999.0.0.1"), ("transport", "src_port", 65536), ("transport", "dst_port", True),
    ("transport", "sequence", 2**32), ("transport", "flags", "XYZ"), ("transport", "window", -1),
    ("transport", "payload_length", "5"),
])
def test_wrong_values_are_invalid_and_set_to_null(make_event, section, name, value):
    event = make_event()
    event[section][name] = value
    prepare(event)
    assert event["preprocess_status"] == "invalid"
    assert event[section][name] is None
    assert repr(value) in event["reason"][0]


def test_wrong_captured_length_is_invalid(make_event):
    event = prepare(make_event(captured_length=-1))
    assert event["preprocess_status"] == "invalid" and event["captured_length"] is None


def test_missing_optional_fields_are_filled_and_marked(make_event):
    event = make_event()
    del event["captured_length"], event["network"]["ttl"], event["transport"]["window"]
    for name in ("errors", "status", "application", "packet_id", "source"):
        del event[name]
    prepare(event)
    assert event["captured_length"] is None and event["network"]["ttl"] is None
    assert event["transport"]["window"] is None
    assert event["errors"] == [] and event["status"] is None and event["application"] == {"protocol": None}
    assert event["packet_id"] is None and event["source"] is None
    assert (event["preprocess_status"], event["processing_action"]) == ("partial", "process")
    assert event["reason"] == ["Thiếu trường không bắt buộc, đã điền null: captured_length, network.ttl, "
                               "transport.window"]


def test_explicit_null_optional_field_is_not_reported(make_event):
    event = make_event()
    event["network"]["ttl"] = None
    assert prepare(event)["preprocess_status"] == "valid"


@pytest.mark.parametrize("change,reason", [
    ({"network": None}, "Không có lớp IP được hỗ trợ"),
    ({"transport": None}, "Giao thức IP số 6 chưa được hỗ trợ"),
    ({"transport": {"protocol": "SCTP", "src_port": 1, "dst_port": 2}}, "Giao thức vận chuyển SCTP"),
])
def test_unsupported_data_is_kept_but_skipped(make_event, change, reason):
    event = prepare(make_event(**change))
    assert (event["preprocess_status"], event["processing_action"]) == ("partial", "skip")
    assert event["reason"][0].startswith(reason)


def test_ip_fragment_is_skipped(make_event):
    event = make_event()
    event["network"]["more_fragments"] = True
    event = prepare(event)
    assert (event["preprocess_status"], event["processing_action"]) == ("partial", "skip")


@pytest.mark.parametrize("config,change,action", [
    (Config(drop_invalid_events=True), {"timestamp": None}, "drop"),
    (Config(drop_unsupported_events=True), {"transport": None}, "drop"),
    (Config(drop_invalid_events=True), {"transport": None}, "skip"),
    (Config(drop_unsupported_events=True), {"timestamp": None}, "skip"),
])
def test_drop_policies_follow_config(make_event, config, change, action):
    assert prepare(make_event(**change), config)["processing_action"] == action


def test_parser_status_is_carried_over(make_event):
    assert prepare(make_event(status="partial"))["preprocess_status"] == "partial"
    malformed = prepare(make_event(status="malformed"))
    assert (malformed["preprocess_status"], malformed["processing_action"]) == ("partial", "process")
    broken = prepare({"timestamp": 1.0, "network": None, "transport": None, "status": "malformed"})
    assert (broken["preprocess_status"], broken["processing_action"]) == ("invalid", "skip")


def test_application_fields_follow_one_layout_per_protocol(make_event):
    response = prepare(make_event(application={"protocol": "HTTP", "message_type": "response",
                                               "status_code": 200, "headers": {"Server": "x"}, "body": "ok"}))
    assert list(response["application"]) == ["protocol", "message_type", "method", "uri", "uri_normalized",
                                             "version", "status_code", "reason", "headers", "body"]
    assert response["application"]["method"] is None
    dns = prepare(make_event(application={"protocol": "DNS"}))
    assert dns["application"]["questions"] == [] and dns["application"]["answers"] == []
    smtp = prepare(make_event(application={"protocol": "SMTP", "message_type": "command", "command": "EHLO"}))
    assert smtp["application"]["headers"] == {} and smtp["application"]["body"] is None


@pytest.mark.parametrize("application", [
    "not an object", {"protocol": 10}, {"protocol": "HTTP", "headers": ["x"]},
    {"protocol": "HTTP", "headers": {"A": 1}}, {"protocol": "DNS", "answers": {"x": 1}},
    {"protocol": "DNS", "answers": ["x", {"name": "a", "type": [1], "data": "b"}]},
    {"protocol": "DNS", "answers": [{"name": "a", "type": 1, "data": "not-an-ip"}]},
])
def test_bad_application_structure_is_partial_and_still_tracked(make_event, application):
    event = prepare(make_event(application=application))
    assert (event["preprocess_status"], event["processing_action"]) == ("partial", "process")
    assert event["reason"]


def test_unsupported_application_protocol_is_partial(make_event):
    event = prepare(make_event(application={"protocol": "ftp"}))
    assert event["application"] == {"protocol": "FTP"}
    assert event["reason"] == ["Giao thức ứng dụng FTP chưa được hỗ trợ phân tích"]


@pytest.mark.parametrize("change", [{"packet_id": "x"}, {"source": 5}, {"errors": "oops"}, {"status": 3}])
def test_wrong_note_fields_are_reset_without_blocking_tracking(make_event, change):
    event = prepare(make_event(**change))
    assert (event["preprocess_status"], event["processing_action"]) == ("partial", "process")


def test_inconsistent_ip_information_is_invalid(make_event):
    mixed = make_event()
    mixed["network"]["dst_ip"] = "2001:db8::1"
    assert prepare(mixed)["reason"] == ["Phiên bản IP không khớp với địa chỉ nguồn/đích"]
    wrong_number = make_event()
    wrong_number["network"]["protocol"] = 17
    assert prepare(wrong_number)["reason"] == ["network.protocol (17) không khớp với TCP"]


@pytest.mark.parametrize("change", [{"network": "x"}, {"transport": []}, {"transport": {"src_port": 1}}])
def test_wrong_section_types_are_invalid(make_event, change):
    assert prepare(make_event(**change))["preprocess_status"] == "invalid"


@pytest.mark.parametrize("uri,expected", [
    ("/a/./b/../c", "/a/c"),
    ("/a/b/..", "/a/"),
    ("/../a", "/a"),
    ("/a//b", "/a//b"),
    ("/%7euser/%2fetc%2Fpasswd", "/~user/%2Fetc%2Fpasswd"),
    ("/a/%2E%2E/b", "/b"),
    ("/p?x=/../y#/./z", "/p?x=/../y#/./z"),
    ("HTTP://Example.COM:80/a/../b?Q=1", "http://example.com:80/b?Q=1"),
    ("http://User:Pass@Example.com/", "http://User:Pass@example.com/"),
    ("*", "*"),
    ("example.com:443", "example.com:443"),
])
def test_uri_normalization_keeps_meaning(uri, expected):
    assert normalize_uri(uri) == expected


def test_raw_uri_is_kept_next_to_normalized_uri(make_event):
    event = prepare(make_event(application={"protocol": "HTTP", "uri": "/a/./b/%7e"}))
    assert event["application"]["uri"] == "/a/./b/%7e"
    assert event["application"]["uri_normalized"] == "/a/b/~"
