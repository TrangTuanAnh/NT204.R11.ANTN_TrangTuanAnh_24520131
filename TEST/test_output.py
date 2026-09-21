import json

from src.output import JsonLinesWriter


def test_json_lines_writer_flushes_each_event(tmp_path):
    path = tmp_path / "events.jsonl"

    with JsonLinesWriter(path) as writer:
        writer.write({"packet_id": 1, "status": "ok"})
        assert path.read_text(encoding="utf-8") == '{"packet_id": 1, "status": "ok"}\n'

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "packet_id": 1,
        "status": "ok",
    }
