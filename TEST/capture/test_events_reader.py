"""Kiểm thử việc đọc event từ file JSON Lines."""

from __future__ import annotations

from src.capture.events import iter_events


def test_objects_are_read_and_blank_lines_skipped(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"packet_id": 1}\n\n  \n{"packet_id": 2}\n', encoding="utf-8")
    assert list(iter_events(path, 1000)) == [{"packet_id": 1}, {"packet_id": 2}]


def test_bad_lines_become_malformed_events_and_reading_continues(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_bytes(b'{broken\n[1, 2]\n\xff\xfe\n' + b'{"a": "' + b"x" * 50 + b'"}\n{"packet_id": 6}\n')
    events = list(iter_events(path, 40))
    assert [event.get("status") for event in events] == ["malformed"] * 4 + [None]
    assert events[0]["errors"][0].startswith("Dòng 1 không phải JSON hợp lệ")
    assert events[1]["errors"] == ["Dòng 2 không phải JSON object"]
    assert events[2]["errors"] == ["Dòng 3 không phải chữ UTF-8 hợp lệ"]
    assert events[3]["errors"] == ["Dòng 4 dài hơn giới hạn 40 byte"]
    assert events[4] == {"packet_id": 6}


def test_nan_is_kept_as_text_so_it_can_be_reported(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"timestamp": NaN, "ttl": Infinity}\n', encoding="utf-8")
    assert list(iter_events(path, 1000)) == [{"timestamp": "NaN", "ttl": "Infinity"}]


def test_byte_order_mark_is_ignored(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_bytes(b'\xef\xbb\xbf{"packet_id": 1}\n')
    assert list(iter_events(path, 1000)) == [{"packet_id": 1}]
