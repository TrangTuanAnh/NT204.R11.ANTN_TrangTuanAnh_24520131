"""Kiểm thử Rule Evaluation Engine: lấy rule cần xét, nhiều rule cùng khớp và các bộ đếm."""

from __future__ import annotations

from src.config import DEFAULT_RULE_VARIABLES
from src.detection import evaluator as evaluator_module
from src.detection.evaluator import RuleEvaluator
from src.rules.parser import parse_rule
from src.rules.repository import RuleRepository


def make_evaluator(*rules: str) -> RuleEvaluator:
    """Tạo bộ đánh giá với các rule cho trước; sid đánh số từ 1."""
    repository = RuleRepository()
    for sid, text in enumerate(rules, start=1):
        parsed = parse_rule(text.replace("SID", str(sid)), DEFAULT_RULE_VARIABLES)
        assert parsed.rule is not None, parsed.reasons
        repository.add(parsed.rule)
    return RuleEvaluator(repository)


def test_every_matching_rule_is_returned(make_event):
    evaluator = make_evaluator('alert tcp any any -> any 80 (msg:"a"; sid:SID;)',
                               'alert tcp any any -> any any (msg:"b"; content:"GET"; sid:SID;)',
                               'alert ip any any -> any any (msg:"c"; sid:SID;)')
    matches = evaluator.evaluate(make_event(), None, b"GET /")
    assert [rule.sid for rule, _ in matches] == [1, 2, 3]
    assert evaluator.stats["matches"] == 3


def test_counters_show_where_rules_were_dropped(make_event):
    evaluator = make_evaluator('alert tcp 10.9.9.9 any -> any 80 (msg:"sai ip"; content:"GET"; sid:SID;)',
                               'alert tcp any any -> any 81 (msg:"sai port"; content:"GET"; sid:SID;)',
                               'alert udp any any -> any 80 (msg:"sai giao thuc"; sid:SID;)',
                               'alert tcp any any -> any 80 (msg:"sai flow"; flow:established; sid:SID;)',
                               'alert tcp any any -> any 80 (msg:"sai co"; flags:S; sid:SID;)',
                               'alert tcp any any -> any 80 (msg:"khong co chuoi"; content:"POST"; sid:SID;)',
                               'alert tcp any any -> any 80 (msg:"khop"; content:"GET"; sid:SID;)')
    matches = evaluator.evaluate(make_event(), None, b"GET /")
    assert [rule.sid for rule, _ in matches] == [7]
    stats = evaluator.stats
    assert stats["rules_in_repository"] == 7 and stats["events_evaluated"] == 1
    assert stats["candidate_rules"] == 5  # hai rule sai port và sai giao thức bị loại ngay từ chỉ mục
    assert stats["rejected"] == {"header": 1, "flow": 1, "packet": 1, "content": 1}
    assert stats["content_checks"] == 2 and stats["matches"] == 1 and stats["errors"] == 0


def test_invalid_and_unusable_events_are_skipped(make_event):
    evaluator = make_evaluator('alert ip any any -> any any (msg:"a"; sid:SID;)')
    for event in (make_event(preprocess_status="invalid"), make_event(processing_action="drop"),
                  make_event(network=None), make_event(network="sai"),
                  make_event(network={"src_ip": None, "dst_ip": "192.0.2.1"})):
        assert evaluator.evaluate(event) == []
    assert evaluator.stats["events_seen"] == 5 and evaluator.stats["events_skipped"] == 5


def test_packet_without_flow_is_still_evaluated(make_event):
    evaluator = make_evaluator('alert ip any any -> any any (msg:"a"; sid:SID;)',
                               'alert ip any any -> any any (msg:"b"; flow:established; sid:SID;)')
    event = make_event(transport=None, preprocess_status="partial", processing_action="skip")
    assert [rule.sid for rule, _ in evaluator.evaluate(event)] == [1]


def test_error_in_one_rule_does_not_stop_the_others(make_event, monkeypatch):
    evaluator = make_evaluator('alert tcp any any -> any any (msg:"a"; sid:SID;)',
                               'alert tcp any any -> any any (msg:"b"; sid:SID;)')
    original = evaluator_module.match_rule

    def broken_for_first_rule(rule, packet):
        """Giả lập lỗi không lường trước khi xét rule đầu tiên."""
        if rule.sid == 1:
            raise RuntimeError("boom")
        return original(rule, packet)

    monkeypatch.setattr(evaluator_module, "match_rule", broken_for_first_rule)
    assert [rule.sid for rule, _ in evaluator.evaluate(make_event())] == [2]
    assert evaluator.stats["errors"] == 1


def test_strange_event_does_not_stop_the_program(make_event):
    evaluator = make_evaluator('alert ip any any -> any any (msg:"a"; sid:SID;)')
    event = make_event(transport={"protocol": "TCP", "src_port": [1], "dst_port": 80})
    assert evaluator.evaluate(event) == []
    assert evaluator.stats["errors"] == 1


def test_only_candidates_reach_the_matching_step(make_event):
    repository = RuleRepository()
    for port in range(1, 201):
        repository.add(parse_rule(f'alert tcp any any -> any {port} (msg:"a"; sid:{port};)',
                                  DEFAULT_RULE_VARIABLES).rule)
    evaluator = RuleEvaluator(repository)
    assert [rule.sid for rule, _ in evaluator.evaluate(make_event())] == [80]
    assert evaluator.stats["candidate_rules"] == 1
