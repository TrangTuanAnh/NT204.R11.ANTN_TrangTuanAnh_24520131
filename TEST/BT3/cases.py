"""Đầu vào và kết quả mong đợi của 14 ca kiểm thử bắt buộc của Core Engine (Bài tập 3), cùng các ca bổ sung.

Gói tin được dựng bằng Scapy rồi lưu ra PCAP (dữ liệu tổng hợp, không gửi ra
mạng). Các rule được ghi ra file .rules của từng ca, không viết trong mã nguồn engine.

Đường dẫn trong checks:
- "detections.<i>.<trường>": Detection Event thứ i trong file đầu ra.
- "by_packet.<packet_id>": danh sách sid của các rule khớp với gói đó.
- "candidates.<i>": danh sách sid của các rule được chỉ mục chọn cho gói thứ i (tính từ 0).
- "report.<trường>": file báo cáo nạp rule và số liệu đánh giá.
- "events.<i>.<trường>", "flows.<i>.<trường>", "exit_code", "event_count", "flow_count", "detection_count".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scapy.all import ICMP, IP

from TEST.support.builders import BASE_TIME, frame, http_message, tcp, udp

CLIENT = "10.0.0.5"
OTHER_CLIENT = "10.0.0.6"
SERVER = "192.168.1.20"
CLIENT_PORT = 52133


@dataclass
class DetectionCase:
    """Một ca kiểm thử: rule, gói tin đầu vào, cấu hình và các giá trị phải quan sát được."""

    number: str                       # số thứ tự ca trong đề, ví dụ "01"; ca bổ sung ghi "B1", "B2"...
    name: str                         # tên thư mục lưu kết quả
    title: str                        # tên ngắn của ca
    requirement: str                  # kết quả mong đợi ghi trong đề
    scenario: str                     # mô tả dữ liệu đầu vào
    explanation: str                  # giải thích vì sao kết quả mong đợi như vậy
    checks: dict[str, Any]            # đường dẫn trường → giá trị mong đợi
    packets: list[Any]                # gói tin đầu vào
    rules: dict[str, str] = field(default_factory=dict)   # tên file rule → nội dung
    repo_rules: list[str] = field(default_factory=list)   # file rule có sẵn trong repo
    config: dict[str, Any] = field(default_factory=dict)  # tùy chọn cấu hình khác mặc định
    equal_paths: list[tuple[str, str]] = field(default_factory=list)  # các cặp trường phải bằng nhau
    extra: bool = False               # True: ca bổ sung ngoài bảng test bắt buộc, kết quả lưu trong TEST/extra


def handshake() -> list[Any]:
    """Ba gói bắt tay giữa client và web server."""
    return [
        tcp(0.00, CLIENT, CLIENT_PORT, SERVER, 80, "S", seq=1000),
        tcp(0.01, SERVER, 80, CLIENT, CLIENT_PORT, "SA", seq=5000, ack=1001),
        tcp(0.02, CLIENT, CLIENT_PORT, SERVER, 80, "A", seq=1001, ack=5001),
    ]


def get_request(at: float, path: str) -> Any:
    """Gói HTTP GET từ client tới web server."""
    return tcp(at, CLIENT, CLIENT_PORT, SERVER, 80, "PA",
               http_message(f"GET {path} HTTP/1.1", {"Host": "shop.example.test"}), seq=1001, ack=5001)


def required_detection_cases() -> list[DetectionCase]:
    """Danh sách đủ 14 ca theo bảng test bắt buộc của đề."""
    return [
        _case01_loading(), _case02_syntax_errors(), _case03_out_of_scope(), _case04_header_object(),
        _case05_direction(), _case06_indexer(), _case07_header_mismatch(), _case08_flow(), _case09_nocase(),
        _case10_offset_depth(), _case11_distance_within(), _case12_flags_dsize(), _case13_several_rules(),
        _case14_detection_event(),
    ]


def extra_detection_cases() -> list[DetectionCase]:
    """Các ca bổ sung ngoài bảng test bắt buộc, kết quả lưu trong TEST/extra."""
    return [_extra_snort_community_rules()]


def all_detection_cases() -> list[DetectionCase]:
    """Mọi ca của Bài tập 3: các ca bắt buộc rồi tới các ca bổ sung."""
    return required_detection_cases() + extra_detection_cases()


def _case01_loading() -> DetectionCase:
    """Ca 01: file có rule hợp lệ, comment và dòng trống; tắt rule và file bằng cấu hình."""
    return DetectionCase(
        "01", "case01_rule_loading", "Nạp file rule",
        "Chỉ rule hợp lệ được đưa sang parser.",
        "File input.rules có 3 dòng comment (một dòng là rule đã bị comment), 2 dòng trống, một rule viết trên "
        "một dòng, một rule viết trên hai dòng và một rule bị tắt bằng disabled_sids. File disabled.rules bị tắt "
        "cả file bằng disabled_rule_files. Một gói HTTP GET có đủ các chuỗi mà mọi rule tìm.",
        "Chỉ ba rule của input.rules tới bước phân tích; comment và dòng trống bị bỏ, rule đã comment (sid 100102) "
        "không được nạp. Rule tắt bằng sid và cả file bị tắt không sinh cảnh báo. Gói GET chỉ khớp hai rule còn lại.",
        {
            "exit_code": 0, "detection_count": 2,
            "report.summary.files": 2, "report.summary.disabled_files": 1,
            "report.summary.comment_lines": 3, "report.summary.blank_lines": 2,
            "report.summary.rule_lines": 3, "report.summary.valid": 2, "report.summary.invalid": 0,
            "report.summary.disabled": 1,
            "report.files.1.enabled": False,
            "report.rules.0.line": 4, "report.rules.0.sid": 100101, "report.rules.0.status": "valid",
            "report.rules.1.line": 7, "report.rules.1.sid": 100103, "report.rules.1.status": "valid",
            "report.rules.2.line": 9, "report.rules.2.sid": 100104, "report.rules.2.status": "disabled",
            "by_packet.1": [100101, 100103],
        },
        [get_request(0.0, "/index.html")],
        rules={
            "input.rules": (
                "# Ca 01: file có rule hợp lệ, comment và dòng trống\n"
                "\n"
                "   # comment thụt đầu dòng\n"
                'alert tcp any any -> any 80 (msg:"Ca 01 - rule viet tren mot dong"; content:"GET"; sid:100101; rev:1;)\n'
                "\n"
                '# alert tcp any any -> any 80 (msg:"Ca 01 - rule da bi comment"; content:"GET"; sid:100102; rev:1;)\n'
                "alert tcp any any -> any 80 ( \\\n"
                '    msg:"Ca 01 - rule viet tren hai dong"; content:"Host"; sid:100103; rev:1;)\n'
                'alert tcp any any -> any 80 (msg:"Ca 01 - rule bi tat bang sid"; content:"GET"; sid:100104; rev:1;)\n'
            ),
            "disabled.rules": 'alert tcp any any -> any 80 (msg:"Ca 01 - file bi tat"; content:"GET"; sid:100105; rev:1;)\n',
        },
        config={"disabled_rule_files": ["disabled.rules"], "disabled_sids": [100104]},
    )


def _case02_syntax_errors() -> DetectionCase:
    """Ca 02: các rule sai cú pháp xen giữa rule hợp lệ."""
    header = "alert tcp any any -> any 80"
    return DetectionCase(
        "02", "case02_syntax_errors", "Rule sai cú pháp",
        "Đánh dấu invalid, có lý do; engine tiếp tục chạy.",
        "Mười bốn rule: hai rule hợp lệ ở đầu và cuối file, xen giữa là mười hai rule sai: thiếu chiều, chiều sai, "
        "IP sai, port quá lớn, thiếu dấu đóng ngoặc, thiếu dấu nháy đóng, thiếu msg, thiếu sid, sid không phải số, "
        "nocase không có content, content hex lẻ chữ số, sid trùng rule khác.",
        "Mỗi rule sai có status invalid kèm lý do cụ thể và không vào kho rule. Rule hợp lệ đứng sau các rule sai "
        "vẫn được nạp, chương trình thoát với mã 0 và gói GET vẫn khớp hai rule hợp lệ.",
        {
            "exit_code": 0, "detection_count": 2,
            "report.summary.rule_lines": 14, "report.summary.valid": 2, "report.summary.invalid": 12,
            "report.engine.rules_in_repository": 2,
            "report.rules.0.status": "valid",
            "report.rules.1.status": "invalid",
            "report.rules.1.reasons": ['Header phải có đủ 7 phần, đang có 6: \'alert tcp any any any 80\''],
            "report.rules.2.reasons": ["Chiều phải là -> hoặc <>, đang là '=>'"],
            "report.rules.3.reasons": ["IP nguồn không hợp lệ (999.1.1.1): '999.1.1.1' does not appear to be an "
                                       "IPv4 or IPv6 network"],
            "report.rules.4.reasons": ["Port nguồn không hợp lệ (70000): port phải từ 0 đến 65535"],
            "report.rules.5.reasons": ['Rule phải kết thúc bằng dấu ")"'],
            "report.rules.6.reasons": ['Phần tùy chọn sai cú pháp: thiếu dấu " đóng'],
            "report.rules.7.reasons": ["Rule thiếu keyword bắt buộc msg"],
            "report.rules.8.reasons": ["Rule thiếu keyword bắt buộc sid"],
            "report.rules.9.reasons": ["Keyword sid không hợp lệ (abc): phải là số nguyên"],
            "report.rules.10.reasons": ["Keyword nocase không hợp lệ (None): phải đứng sau một content"],
            "report.rules.11.reasons": ["Keyword content không hợp lệ (\"|0|\"): phần hex phải gồm từng cặp chữ số hex"],
            "report.rules.12.reasons": ["sid 100201 đã được dùng cho rule khác"],
            "report.rules.13.status": "valid",
            "by_packet.1": [100201, 100214],
        },
        [get_request(0.0, "/index.html")],
        rules={"input.rules": "\n".join([
            f'{header} (msg:"Ca 02 - rule hop le dau file"; content:"GET"; sid:100201; rev:1;)',
            'alert tcp any any any 80 (msg:"Thieu chieu"; sid:100202; rev:1;)',
            'alert tcp any any => any 80 (msg:"Chieu sai"; sid:100203; rev:1;)',
            'alert tcp 999.1.1.1 any -> any 80 (msg:"IP sai"; sid:100204; rev:1;)',
            'alert tcp any 70000 -> any 80 (msg:"Port qua lon"; sid:100205; rev:1;)',
            f'{header} (msg:"Thieu dau dong ngoac"; sid:100206; rev:1;',
            f'{header} (msg:"Thieu dau nhay dong; sid:100207; rev:1;)',
            f'{header} (content:"GET"; sid:100208; rev:1;)',
            f'{header} (msg:"Thieu sid"; content:"GET"; rev:1;)',
            f'{header} (msg:"Sid khong phai so"; sid:abc; rev:1;)',
            f'{header} (msg:"Nocase khong co content"; nocase; sid:100211; rev:1;)',
            f'{header} (msg:"Hex le chu so"; content:"|0|"; sid:100212; rev:1;)',
            f'{header} (msg:"Trung sid"; content:"GET"; sid:100201; rev:1;)',
            f'{header} (msg:"Ca 02 - rule hop le cuoi file"; content:"GET"; sid:100214; rev:1;)',
        ]) + "\n"},
    )


def _case03_out_of_scope() -> DetectionCase:
    """Ca 03: rule dùng thành phần ngoài phạm vi đề bài."""
    header = "alert tcp any any -> any 80"
    return DetectionCase(
        "03", "case03_out_of_scope_keywords", "Keyword ngoài phạm vi",
        "Đánh dấu unsupported; không crash.",
        "Tám rule đều tìm chuỗi GET có trong gói: một rule trong phạm vi và bảy rule dùng thành phần ngoài phạm vi: "
        "pcre, byte_test, http_uri, metadata, hành động drop, giao thức icmp, flow:from_client.",
        "Bảy rule ngoài phạm vi có status unsupported kèm lý do và bị bỏ hẳn: dù gói có chuỗi GET, chúng không sinh "
        "Detection Event. report.unsupported_keywords thống kê các keyword đã làm rule bị bỏ.",
        {
            "exit_code": 0, "detection_count": 1,
            "report.summary.rule_lines": 8, "report.summary.valid": 1, "report.summary.unsupported": 7,
            "report.summary.invalid": 0,
            "report.engine.rules_in_repository": 1,
            "report.rules.1.status": "unsupported",
            "report.rules.1.reasons": ["Keyword pcre ngoài phạm vi hỗ trợ"],
            "report.rules.2.reasons": ["Keyword byte_test ngoài phạm vi hỗ trợ"],
            "report.rules.3.reasons": ["Keyword http_uri ngoài phạm vi hỗ trợ"],
            "report.rules.4.reasons": ["Keyword metadata ngoài phạm vi hỗ trợ"],
            "report.rules.5.reasons": ["Hành động drop ngoài phạm vi hỗ trợ"],
            "report.rules.6.reasons": ["Giao thức icmp ngoài phạm vi hỗ trợ"],
            "report.rules.7.reasons": ["Giá trị flow from_client ngoài phạm vi hỗ trợ"],
            "report.unsupported_keywords": {"pcre": 1, "byte_test": 1, "http_uri": 1, "metadata": 1,
                                            "flow:from_client": 1},
            "by_packet.1": [100301],
        },
        [get_request(0.0, "/index.html")],
        rules={"input.rules": "\n".join([
            f'{header} (msg:"Ca 03 - rule trong pham vi"; content:"GET"; sid:100301; rev:1;)',
            f'{header} (msg:"Dung pcre"; pcre:"/GET/"; sid:100302; rev:1;)',
            f'{header} (msg:"Dung byte_test"; content:"GET"; byte_test:1,>,0,0; sid:100303; rev:1;)',
            f'{header} (msg:"Dung http_uri"; content:"GET"; http_uri; sid:100304; rev:1;)',
            f'{header} (msg:"Dung metadata"; content:"GET"; metadata:service http; sid:100305; rev:1;)',
            'drop tcp any any -> any 80 (msg:"Hanh dong drop"; content:"GET"; sid:100306; rev:1;)',
            'alert icmp any any -> any any (msg:"Giao thuc icmp"; sid:100307; rev:1;)',
            f'{header} (msg:"Flow from_client"; flow:from_client; content:"GET"; sid:100308; rev:1;)',
        ]) + "\n"},
    )


def _case04_header_object() -> DetectionCase:
    """Ca 04: đổi header rule thành Internal Rule Object."""
    any_address = {"any": True, "include": [], "exclude": []}
    any_port = {"any": True, "include": [], "exclude": []}
    return DetectionCase(
        "04", "case04_header_object", "Parse header",
        "Internal Rule Object đúng.",
        "Bốn rule TCP: any/any; IP đơn và port đơn; dải CIDR với khoảng port hai đầu và khoảng chỉ có đầu cuối; "
        "khoảng chỉ có đầu đầu. Một gói từ 10.0.0.5:52133 tới 192.168.1.20:80 để kiểm tra đối tượng đó hoạt động đúng.",
        "report.rules.<i>.rule là Internal Rule Object của từng rule. IP đơn được lưu dạng /32, :1023 là từ 0 tới 1023, "
        "1024: là từ 1024 tới 65535. Gói có port đích 80 khớp ba rule đầu, không khớp rule cần port đích 8000-8080.",
        {
            "exit_code": 0, "report.summary.valid": 4,
            "report.rules.0.rule.action": "alert", "report.rules.0.rule.protocol": "tcp",
            "report.rules.0.rule.direction": "->",
            "report.rules.0.rule.source": any_address, "report.rules.0.rule.source_ports": any_port,
            "report.rules.0.rule.destination": any_address, "report.rules.0.rule.destination_ports": any_port,
            "report.rules.1.rule.source": {"any": False, "include": ["10.0.0.5/32"], "exclude": []},
            "report.rules.1.rule.source_ports": {"any": False, "include": [[52133, 52133]], "exclude": []},
            "report.rules.1.rule.destination": {"any": False, "include": ["192.168.1.20/32"], "exclude": []},
            "report.rules.1.rule.destination_ports": {"any": False, "include": [[80, 80]], "exclude": []},
            "report.rules.2.rule.source": {"any": False, "include": ["10.0.0.0/8"], "exclude": []},
            "report.rules.2.rule.source_ports": {"any": False, "include": [[1024, 65535]], "exclude": []},
            "report.rules.2.rule.destination": {"any": False, "include": ["192.168.1.0/24"], "exclude": []},
            "report.rules.2.rule.destination_ports": {"any": False, "include": [[0, 1023]], "exclude": []},
            "report.rules.3.rule.source_ports": {"any": False, "include": [[1024, 65535]], "exclude": []},
            "report.rules.3.rule.destination_ports": {"any": False, "include": [[8000, 8080]], "exclude": []},
            "report.rules.1.rule.sid": 100402, "report.rules.1.rule.rev": 1, "report.rules.1.rule.msg": "IP don, port don",
            "by_packet.1": [100401, 100402, 100403],
        },
        [get_request(0.0, "/index.html")],
        rules={"input.rules": "\n".join([
            'alert tcp any any -> any any (msg:"Any va any"; sid:100401; rev:1;)',
            'alert tcp 10.0.0.5 52133 -> 192.168.1.20 80 (msg:"IP don, port don"; sid:100402; rev:1;)',
            'alert tcp 10.0.0.0/8 1024:65535 -> 192.168.1.0/24 :1023 (msg:"CIDR, khoang port"; sid:100403; rev:1;)',
            'alert tcp any 1024: -> 192.168.1.20 8000:8080 (msg:"Khoang mo"; sid:100404; rev:1;)',
        ]) + "\n"},
    )


def _case05_direction() -> DetectionCase:
    """Ca 05: chiều -> và <>."""
    payload = b"hello"
    return DetectionCase(
        "05", "case05_direction", "Direction -> và <>",
        "So khớp đúng chiều/bidirectional.",
        "Ba gói: client 10.0.0.5:52133 → server 192.168.1.20:80; server → client (chiều ngược); và một client khác "
        "10.0.0.6 → server. Hai rule cùng địa chỉ, một rule dùng -> và một rule dùng <>.",
        "Rule -> chỉ khớp gói đi đúng chiều. Rule <> khớp cả hai chiều và ghi reversed_direction là true với gói "
        "ngược; Detection Event vẫn ghi đúng nguồn và đích thật của gói. Gói từ client khác không khớp rule nào.",
        {
            "exit_code": 0, "detection_count": 3,
            "by_packet.1": [100501, 100502], "by_packet.2": [100502], "by_packet.3": [],
            "detections.0.match.reversed_direction": False,
            "detections.1.match.reversed_direction": False,
            "detections.2.match.reversed_direction": True,
            "detections.2.src_ip": SERVER, "detections.2.src_port": 80,
            "detections.2.dst_ip": CLIENT, "detections.2.dst_port": CLIENT_PORT,
        },
        [
            tcp(0.0, CLIENT, CLIENT_PORT, SERVER, 80, "PA", payload),
            tcp(0.1, SERVER, 80, CLIENT, CLIENT_PORT, "PA", payload),
            tcp(0.2, OTHER_CLIENT, CLIENT_PORT, SERVER, 80, "PA", payload),
        ],
        rules={"input.rules": "\n".join([
            'alert tcp 10.0.0.5 any -> 192.168.1.20 80 (msg:"Ca 05 - mot chieu"; sid:100501; rev:1;)',
            'alert tcp 10.0.0.5 any <> 192.168.1.20 80 (msg:"Ca 05 - hai chieu"; sid:100502; rev:1;)',
        ]) + "\n"},
    )


def _case06_indexer() -> DetectionCase:
    """Ca 06: chỉ mục chọn rule với giao thức IP, TCP, UDP và any."""
    return DetectionCase(
        "06", "case06_indexer", "Indexer với IP, TCP, UDP và any",
        "Trả đúng tập candidate rules.",
        "Tám rule: ip; tcp any; tcp đích 80; tcp nguồn 80; tcp đích khoảng 8000-8100; udp any; udp đích 53; tcp đích "
        "443 kèm IP cụ thể. Tám gói: TCP tới 80, TCP từ 80, TCP tới 8080, TCP tới 443, TCP tới 22, UDP tới 53, UDP tới "
        "123 và một gói ICMP.",
        "candidates.<i> là tập rule mà chỉ mục chọn cho gói thứ i, lấy trực tiếp từ Repository: rule ip luôn được "
        "chọn; rule TCP/UDP chỉ được chọn đúng giao thức và port; gói ICMP không có port nên chỉ có rule ip. Tổng cộng "
        "chỉ phải xét 20 lượt rule thay vì 64 lượt nếu duyệt toàn bộ (8 gói × 8 rule).",
        {
            "exit_code": 0, "report.summary.valid": 8,
            "candidates.0": [100601, 100602, 100603],
            "candidates.1": [100601, 100602, 100604],
            "candidates.2": [100601, 100602, 100605],
            "candidates.3": [100601, 100602, 100608],
            "candidates.4": [100601, 100602],
            "candidates.5": [100601, 100606, 100607],
            "candidates.6": [100601, 100606],
            "candidates.7": [100601],
            "report.engine.events_evaluated": 8,
            "report.engine.rules_in_repository": 8,
            "report.engine.candidate_rules": 20,
        },
        [
            tcp(0.0, CLIENT, CLIENT_PORT, SERVER, 80, "S"),
            tcp(0.1, SERVER, 80, CLIENT, CLIENT_PORT, "SA"),
            tcp(0.2, CLIENT, CLIENT_PORT, SERVER, 8080, "S"),
            tcp(0.3, CLIENT, CLIENT_PORT, SERVER, 443, "S"),
            tcp(0.4, CLIENT, CLIENT_PORT, SERVER, 22, "S"),
            udp(0.5, CLIENT, CLIENT_PORT, SERVER, 53, b"query"),
            udp(0.6, CLIENT, CLIENT_PORT, SERVER, 123, b"time"),
            frame(IP(src=CLIENT, dst=SERVER) / ICMP(), 0.7),
        ],
        rules={"input.rules": "\n".join([
            'alert ip any any -> any any (msg:"Ip moi goi"; sid:100601; rev:1;)',
            'alert tcp any any -> any any (msg:"Tcp moi port"; sid:100602; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Tcp dich 80"; sid:100603; rev:1;)',
            'alert tcp any 80 -> any any (msg:"Tcp nguon 80"; sid:100604; rev:1;)',
            'alert tcp any any -> any 8000:8100 (msg:"Tcp khoang port"; sid:100605; rev:1;)',
            'alert udp any any -> any any (msg:"Udp moi port"; sid:100606; rev:1;)',
            'alert udp any any -> any 53 (msg:"Udp dich 53"; sid:100607; rev:1;)',
            'alert tcp 10.0.0.5 any -> any 443 (msg:"Tcp IP cu the dich 443"; sid:100608; rev:1;)',
        ]) + "\n"},
    )


def _case07_header_mismatch() -> DetectionCase:
    """Ca 07: header không khớp thì không tới bước tìm content."""
    return DetectionCase(
        "07", "case07_header_mismatch", "Header không match",
        "Rule bị loại trước content matching.",
        "Năm rule đều tìm chuỗi GET có trong gói: sai IP nguồn, sai IP đích, sai port đích, sai giao thức và một rule "
        "đúng header. Một gói HTTP GET tới port 80.",
        "Rule sai port và sai giao thức bị chỉ mục loại ngay (candidates chỉ còn 3 rule). Hai rule sai IP bị loại ở "
        "bước header (rejected.header là 2). Chỉ rule đúng header đi tới bước tìm content (content_checks là 1), "
        "dù cả năm rule đều có chuỗi GET khớp với gói.",
        {
            "exit_code": 0, "detection_count": 1,
            "candidates.0": [100701, 100702, 100705],
            "report.engine.rules_in_repository": 5,
            "report.engine.candidate_rules": 3,
            "report.engine.rejected.header": 2,
            "report.engine.rejected.content": 0,
            "report.engine.content_checks": 1,
            "report.engine.matches": 1,
            "by_packet.1": [100705],
        },
        [get_request(0.0, "/index.html")],
        rules={"input.rules": "\n".join([
            'alert tcp 10.9.9.9 any -> any 80 (msg:"Sai IP nguon"; content:"GET"; sid:100701; rev:1;)',
            'alert tcp any any -> 192.168.99.0/24 80 (msg:"Sai IP dich"; content:"GET"; sid:100702; rev:1;)',
            'alert tcp any any -> any 8080 (msg:"Sai port dich"; content:"GET"; sid:100703; rev:1;)',
            'alert udp any any -> any 80 (msg:"Sai giao thuc"; content:"GET"; sid:100704; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Dung header"; content:"GET"; sid:100705; rev:1;)',
        ]) + "\n"},
    )


def _case08_flow() -> DetectionCase:
    """Ca 08: flow:to_server,established và các giá trị flow khác."""
    return DetectionCase(
        "08", "case08_flow", "flow:to_server,established",
        "Match đúng theo Flow Tracker.",
        "Một phiên TCP sáu gói có chuỗi secret ở gói SYN, request, response và gói FIN kèm dữ liệu. Bốn rule dùng <> "
        "để header khớp cả hai chiều, chỉ còn flow quyết định: to_server,established; to_client,established; "
        "not_established; established.",
        "Gói SYN có chuỗi secret nhưng kết nối chưa thông nên to_server,established không khớp. Request chỉ khớp "
        "to_server, response chỉ khớp to_client. Gói FIN kèm dữ liệu ở trạng thái CLOSING vẫn tính là established, vì "
        "kết nối đã thông và vẫn đang truyền dữ liệu.",
        {
            "exit_code": 0, "detection_count": 9,
            "events.0.flow_state": "NEW", "events.1.flow_state": "HANDSHAKE", "events.2.flow_state": "ESTABLISHED",
            "events.3.direction": "forward", "events.4.direction": "backward", "events.5.flow_state": "CLOSING",
            "by_packet.1": [100803],
            "by_packet.2": [100803],
            "by_packet.3": [100804],
            "by_packet.4": [100801, 100804],
            "by_packet.5": [100802, 100804],
            "by_packet.6": [100801, 100804],
            "report.engine.matches": 9,
            "detections.3.match.flow": {"direction": "forward", "state": "ESTABLISHED", "established": True},
        },
        [
            tcp(0.00, CLIENT, CLIENT_PORT, SERVER, 80, "S", b"secret", seq=1000),
            tcp(0.01, SERVER, 80, CLIENT, CLIENT_PORT, "SA", seq=5000, ack=1001),
            tcp(0.02, CLIENT, CLIENT_PORT, SERVER, 80, "A", seq=1001, ack=5001),
            tcp(0.03, CLIENT, CLIENT_PORT, SERVER, 80, "PA", b"GET /secret", seq=1001, ack=5001),
            tcp(0.04, SERVER, 80, CLIENT, CLIENT_PORT, "PA", b"secret data", seq=5001, ack=1012),
            tcp(0.05, CLIENT, CLIENT_PORT, SERVER, 80, "FPA", b"secret bye", seq=1012, ack=5012),
        ],
        rules={"input.rules": "\n".join([
            'alert tcp any any <> any 80 (msg:"Ca 08 - to_server,established"; flow:to_server,established; '
            'content:"secret"; sid:100801; rev:1;)',
            'alert tcp any any <> any 80 (msg:"Ca 08 - to_client,established"; flow:to_client,established; '
            'content:"secret"; sid:100802; rev:1;)',
            'alert tcp any any <> any 80 (msg:"Ca 08 - not_established"; flow:not_established; sid:100803; rev:1;)',
            'alert tcp any any <> any 80 (msg:"Ca 08 - established"; flow:established; sid:100804; rev:1;)',
        ]) + "\n"},
    )


def _case09_nocase() -> DetectionCase:
    """Ca 09: content có và không có nocase."""
    return DetectionCase(
        "09", "case09_nocase", "content có/không có nocase",
        "Phân biệt/không phân biệt hoa thường đúng.",
        "Một gói GET /ADMIN/login. Bốn rule: content ADMIN đúng kiểu chữ; content admin không có nocase; content admin "
        "có nocase; content viết bằng byte hex của chữ ADMIN.",
        "Không có nocase thì phải đúng kiểu chữ nên rule admin thường không khớp. Có nocase thì khớp, vị trí tìm thấy "
        "là byte 5. Chuỗi viết bằng hex cho cùng kết quả với chuỗi chữ.",
        {
            "exit_code": 0, "detection_count": 3,
            "by_packet.1": [100901, 100903, 100904],
            "report.engine.rejected.content": 1,
            "detections.0.match.contents.0.nocase": False,
            "detections.1.match.contents.0.nocase": True,
            "detections.1.match.contents.0.position": 5,
            "detections.2.match.contents.0.content": "|41 44 4D 49 4E|",
        },
        [get_request(0.0, "/ADMIN/login")],
        rules={"input.rules": "\n".join([
            'alert tcp any any -> any 80 (msg:"Ca 09 - dung kieu chu"; content:"ADMIN"; sid:100901; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Ca 09 - sai kieu chu"; content:"admin"; sid:100902; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Ca 09 - co nocase"; content:"admin"; nocase; sid:100903; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Ca 09 - viet bang hex"; content:"|41 44 4D 49 4E|"; sid:100904; rev:1;)',
        ]) + "\n"},
    )


def _case10_offset_depth() -> DetectionCase:
    """Ca 10: offset và depth."""
    return DetectionCase(
        "10", "case10_offset_depth", "offset/depth",
        "Chỉ match trong vùng được chỉ định.",
        "Một gói có dữ liệu GET /index.html ..., chuỗi GET ở byte 0-2, chuỗi index ở byte 5-9. Sáu rule thử vùng tìm: "
        "GET với depth:3; GET với offset:1; index với offset:5 và depth:5; index với depth:5; index với offset:6; "
        "index với offset:4 và depth:5.",
        "Chỉ rule có vùng tìm chứa trọn chuỗi mới khớp. Vùng offset:5 depth:5 là byte 5-9, chứa vừa đủ index. Vùng "
        "depth:5 là byte 0-4 và vùng offset:4 depth:5 là byte 4-8 đều chỉ chứa một phần chuỗi nên không khớp.",
        {
            "exit_code": 0, "detection_count": 2,
            "by_packet.1": [101001, 101003],
            "report.engine.rejected.content": 4,
            "detections.0.match.contents.0.position": 0,
            "detections.1.match.contents.0.position": 5,
            "detections.0.match.buffer": "payload",
        },
        [get_request(0.0, "/index.html")],
        rules={"input.rules": "\n".join([
            'alert tcp any any -> any 80 (msg:"Ca 10 - GET depth 3"; content:"GET"; depth:3; sid:101001; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Ca 10 - GET offset 1"; content:"GET"; offset:1; sid:101002; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Ca 10 - index 5,5"; content:"index"; offset:5; depth:5; sid:101003; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Ca 10 - index depth 5"; content:"index"; depth:5; sid:101004; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Ca 10 - index offset 6"; content:"index"; offset:6; sid:101005; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Ca 10 - index 4,5"; content:"index"; offset:4; depth:5; sid:101006; rev:1;)',
        ]) + "\n"},
    )


def _case11_distance_within() -> DetectionCase:
    """Ca 11: hai content với distance và within."""
    return DetectionCase(
        "11", "case11_distance_within", "Hai content với distance/within",
        "Relative matching đúng.",
        "Một gói TCP tới port 9000 có dữ liệu ABC12345DEF..ABCDEF: ABC ở byte 0 và 13, DEF ở byte 8 và 16. Sáu rule "
        "gồm hai content với distance/within khác nhau, trong đó có distance âm.",
        "101101: DEF cách ABC đầu ít nhất 1 byte. 101102: DEF phải nằm ngay sau ABC, ABC đầu không thỏa nên phải thử "
        "ABC ở byte 13. 101103: distance quá lớn, không còn dữ liệu. 101104: ABC thứ hai chỉ nằm một phần trong vùng "
        "within. 101105: sau DEF bỏ 2 byte rồi có ABC. 101106: distance âm quay lại tìm 345 ngay trước DEF.",
        {
            "exit_code": 0, "detection_count": 4,
            "by_packet.1": [101101, 101102, 101105, 101106],
            "report.engine.rejected.content": 2,
            "detections.0.match.contents.0.position": 0, "detections.0.match.contents.1.position": 8,
            "detections.1.match.contents.0.position": 13, "detections.1.match.contents.1.position": 16,
            "detections.2.match.contents.0.position": 8, "detections.2.match.contents.1.position": 13,
            "detections.3.match.contents.0.position": 8, "detections.3.match.contents.1.position": 5,
        },
        [tcp(0.0, CLIENT, CLIENT_PORT, SERVER, 9000, "PA", b"ABC12345DEF..ABCDEF")],
        rules={"input.rules": "\n".join([
            'alert tcp any any -> any 9000 (msg:"Ca 11 - distance 1"; content:"ABC"; content:"DEF"; distance:1; '
            'sid:101101; rev:1;)',
            'alert tcp any any -> any 9000 (msg:"Ca 11 - distance 0 within 3"; content:"ABC"; content:"DEF"; distance:0; '
            'within:3; sid:101102; rev:1;)',
            'alert tcp any any -> any 9000 (msg:"Ca 11 - distance 20"; content:"ABC"; content:"DEF"; distance:20; '
            'sid:101103; rev:1;)',
            'alert tcp any any -> any 9000 (msg:"Ca 11 - within 3"; content:"DEF"; content:"ABC"; within:3; '
            'sid:101104; rev:1;)',
            'alert tcp any any -> any 9000 (msg:"Ca 11 - distance 2 within 3"; content:"DEF"; content:"ABC"; distance:2; '
            'within:3; sid:101105; rev:1;)',
            'alert tcp any any -> any 9000 (msg:"Ca 11 - distance am"; content:"DEF"; content:"345"; distance:-6; '
            'within:3; sid:101106; rev:1;)',
        ]) + "\n"},
    )


def _case12_flags_dsize() -> DetectionCase:
    """Ca 12: flags và dsize."""
    return DetectionCase(
        "12", "case12_flags_dsize", "flags và dsize",
        "Match/không match đúng theo event.",
        "Bảy gói: SYN; SYN/ACK; PSH/ACK 5 byte; FIN/ACK; ACK 200 byte; gói không có cờ; SYN có thêm hai cờ ECN (CWR, "
        "ECE). Mười ba rule thử các dạng flags (đúng cờ, +, *, !, 0, cờ bỏ qua) và dsize (bằng, >, <, khoảng, kết hợp).",
        "flags:S chỉ khớp gói có đúng cờ SYN, không khớp gói SYN có thêm cờ ECN; flags:S,CE bỏ qua hai cờ ECN nên khớp "
        "cả hai. flags:+A khớp mọi gói có ACK, flags:!A khớp gói không có ACK, flags:0 chỉ khớp gói không có cờ. dsize "
        "khoảng 3<>5 tính cả hai đầu nên khớp gói 5 byte; khoảng 6<>199 không có gói nào.",
        {
            "exit_code": 0,
            "by_packet.1": [101201, 101205, 101207, 101210],
            "by_packet.2": [101202, 101203, 101210],
            "by_packet.3": [101203, 101208, 101211, 101213],
            "by_packet.4": [101203, 101204, 101210],
            "by_packet.5": [101203, 101209],
            "by_packet.6": [101205, 101206, 101210],
            "by_packet.7": [101205, 101207, 101210],
            "events.5.transport.flags": "",
            "events.6.transport.flags": "SEC",
            "report.summary.valid": 13,
        },
        [
            tcp(0.0, CLIENT, CLIENT_PORT, SERVER, 80, "S"),
            tcp(0.1, SERVER, 80, CLIENT, CLIENT_PORT, "SA"),
            tcp(0.2, CLIENT, CLIENT_PORT, SERVER, 80, "PA", b"hello"),
            tcp(0.3, CLIENT, CLIENT_PORT, SERVER, 80, "FA"),
            tcp(0.4, CLIENT, CLIENT_PORT, SERVER, 80, "A", b"x" * 200),
            tcp(0.5, CLIENT, CLIENT_PORT, SERVER, 80, ""),
            tcp(0.6, CLIENT, CLIENT_PORT, SERVER, 80, "SEC"),
        ],
        rules={"input.rules": "\n".join([
            f'alert tcp any any <> any 80 (msg:"Ca 12 - {options}"; {options}; sid:{sid}; rev:1;)'
            for sid, options in [
                (101201, "flags:S"), (101202, "flags:SA"), (101203, "flags:+A"), (101204, "flags:*FR"),
                (101205, "flags:!A"), (101206, "flags:0"), (101207, "flags:S,CE"), (101208, "dsize:5"),
                (101209, "dsize:>100"), (101210, "dsize:<1"), (101211, "dsize:3<>5"), (101212, "dsize:6<>199"),
                (101213, "flags:+A; dsize:5"),
            ]
        ]) + "\n"},
    )


def _case13_several_rules() -> DetectionCase:
    """Ca 13: một event khớp nhiều rule cùng lúc."""
    return DetectionCase(
        "13", "case13_several_rules", "Một event match ≥2 rule",
        "Sinh đầy đủ các kết quả match.",
        "Phiên TCP có bắt tay rồi GET /etc/passwd. Năm rule: theo port đích 80; theo content passwd; theo dải IP và "
        "flow established; rule ip có dsize lớn hơn 0; và một rule có content không có trong gói.",
        "Gói GET khớp đồng thời bốn rule và sinh đủ bốn Detection Event; engine không dừng ở rule đầu tiên. Rule có "
        "content không tồn tại không sinh kết quả. Các gói bắt tay chỉ khớp những rule phù hợp với chúng.",
        {
            "exit_code": 0, "detection_count": 7,
            "by_packet.1": [101301],
            "by_packet.2": [],
            "by_packet.3": [101301, 101303],
            "by_packet.4": [101301, 101302, 101303, 101304],
            "report.engine.matches": 7,
            # Rule tìm passwd bị loại ở cả 3 gói bắt tay; rule tìm khong_co bị loại ở 3 gói tới port 80.
            "report.engine.rejected.content": 6,
            "detections.3.packet_id": 4, "detections.4.packet_id": 4, "detections.5.packet_id": 4,
            "detections.6.packet_id": 4,
        },
        [*handshake(), get_request(0.03, "/etc/passwd")],
        rules={"input.rules": "\n".join([
            'alert tcp any any -> any 80 (msg:"Ca 13 - theo port"; sid:101301; rev:1;)',
            'alert tcp any any -> any any (msg:"Ca 13 - theo content"; content:"passwd"; sid:101302; rev:1;)',
            'alert tcp 10.0.0.0/8 any -> 192.168.1.0/24 any (msg:"Ca 13 - theo dai IP"; flow:to_server,established; '
            'sid:101303; rev:1;)',
            'alert ip any any -> any any (msg:"Ca 13 - moi goi co du lieu"; dsize:>0; sid:101304; rev:1;)',
            'alert tcp any any -> any 80 (msg:"Ca 13 - khong khop"; content:"khong_co"; sid:101305; rev:1;)',
        ]) + "\n"},
    )


def _case14_detection_event() -> DetectionCase:
    """Ca 14: Detection Event có đủ các trường."""
    return DetectionCase(
        "14", "case14_detection_event", "Detection Event",
        "Có đủ sid/msg/flow/5-tuple/protocol/match info.",
        "Phiên HTTP từ 10.0.0.5:52133 tới 192.168.1.20:80 (đúng ví dụ trong đề): bắt tay, GET /../../etc/passwd, rồi GET "
        "viết mã hóa /a/..%2f..%2fetc/passwd. Một rule Directory traversal có đủ msg, sid, rev, classtype, priority.",
        "Detection Event có đủ timestamp, sid, rev, msg, priority, classtype, 5-tuple, protocol, application_protocol, "
        "flow_id và thông tin khớp (chuỗi và vị trí). Gói thứ hai không có ../ trong byte gốc nhưng vẫn bị phát hiện "
        "nhờ URI đã giải mã; thông tin khớp ghi rõ buffer là application.",
        {
            "exit_code": 0, "detection_count": 2,
            "detections.0.timestamp": BASE_TIME + 0.03,
            "detections.0.packet_id": 4,
            "detections.0.sid": 100001, "detections.0.rev": 1,
            "detections.0.msg": "Directory traversal detected",
            "detections.0.priority": 1, "detections.0.classtype": "web-application-attack",
            "detections.0.src_ip": CLIENT, "detections.0.src_port": CLIENT_PORT,
            "detections.0.dst_ip": SERVER, "detections.0.dst_port": 80,
            "detections.0.protocol": "TCP", "detections.0.application_protocol": "HTTP",
            "detections.0.match.buffer": "payload",
            "detections.0.match.contents": [{"content": "../", "position": 5, "nocase": False, "negated": False}],
            "detections.0.match.flow": {"direction": "forward", "state": "ESTABLISHED", "established": True},
            "detections.1.packet_id": 5,
            "detections.1.match.buffer": "application",
        },
        [*handshake(), get_request(0.03, "/../../etc/passwd"), get_request(0.04, "/a/..%2f..%2fetc/passwd")],
        rules={"input.rules": (
            'alert tcp any any -> any 80 (msg:"Directory traversal detected"; flow:to_server,established; content:"../"; '
            'classtype:web-application-attack; priority:1; sid:100001; rev:1;)\n'
        )},
        equal_paths=[("detections.0.flow_id", "events.3.flow_id"), ("detections.1.flow_id", "events.3.flow_id")],
    )


def _extra_snort_community_rules() -> DetectionCase:
    """Ca bổ sung: nạp bộ rule cộng đồng của Snort đặt trong thư mục rules/."""
    return DetectionCase(
        "B1", "snort_community_rules", "Bộ rule cộng đồng của Snort",
        "Rule/keyword ngoài phạm vi được báo unsupported, không làm chương trình dừng.",
        "Nạp nguyên file rules/community.rules tải từ snort.org, gồm 568 rule đang bật và các rule đã bị comment. Một "
        "gói HTTP GET để chạy trọn đường đi.",
        "Cả 568 rule đều đúng cú pháp nhưng đều có keyword ngoài phạm vi (ít nhất là metadata), nên đều là unsupported "
        "và bị bỏ theo quy tắc của bài làm: kho rule rỗng và không có Detection Event. Chương trình đọc hết file, thoát "
        "với mã 0, report.unsupported_keywords cho biết keyword nào làm rule bị bỏ.",
        {
            "exit_code": 0, "detection_count": 0,
            "report.summary.rule_lines": 568, "report.summary.valid": 0, "report.summary.invalid": 0,
            "report.summary.unsupported": 568,
            "report.unsupported_keywords.metadata": 568,
            "report.engine.rules_in_repository": 0,
            "report.engine.events_evaluated": 1,
            "report.engine.errors": 0,
        },
        [get_request(0.0, "/index.html")],
        repo_rules=["rules/community.rules"],
        extra=True,
    )
