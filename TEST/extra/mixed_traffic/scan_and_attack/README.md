# Quét port, SYN flood và dò mật khẩu

Một máy quét 101 port, một đợt SYN flood 150 gói từ nhiều nguồn, 50 lần dò mật khẩu vào /login và 25 tấn công web, lẫn trong traffic nền gồm web và DNS. Thời gian chờ được đặt ngắn (TCP 30 s, UDP 10 s) để nhiều flow hết hạn ngay trong lúc chạy.

`input.pcap` có **2013 gói** (328 KB), kéo dài khoảng 266 giây, tạo **489 flow**. Dữ liệu là traffic tổng hợp dựng bằng Scapy từ seed `20261103` (địa chỉ thuộc dải dành cho tài liệu và mạng riêng), được đọc offline, không gửi ra mạng.

## Thành phần

| Loại | Số phiên (mỗi phiên là một flow) | Số gói |
| --- | --- | --- |
| dns | 120 | 240 |
| http | 107 | 1337 |
| http_open | 6 | 45 |
| http_reset | 5 | 41 |
| scan_closed | 95 | 190 |
| scan_filtered | 4 | 4 |
| scan_open | 2 | 6 |
| syn_flood | 150 | 150 |

## Rule

| sid | Rule | Số lần khớp mong đợi |
| --- | --- | --- |
| 3100001 | `alert tcp any any -> any 7000:7100 (msg:"SYN probe on service ports"; flags:S; classtype:attempted-recon; priority:2; sid:3100001; rev:1;)` | 101 |
| 3100002 | `alert tcp any any -> any 80 (msg:"SYN to web server"; flags:S; sid:3100002; rev:1;)` | 268 |
| 3100003 | `alert tcp any any -> any 80 (msg:"Login attempt"; flow:to_server,established; content:"POST /login"; offset:0; depth:11; sid:3100003; rev:1;)` | 50 |
| 3000001 | `alert tcp any any -> any 80 (msg:"Directory traversal"; flow:to_server,established; content:"../"; classtype:web-application-attack; priority:1; sid:3000001; rev:1;)` | 14 |
| 3000002 | `alert tcp any any -> any 80 (msg:"SQL injection attempt"; flow:to_server,established; content:"' OR 1=1"; nocase; classtype:web-application-attack; priority:1; sid:3000002; rev:1;)` | 11 |

Cấu hình khác mặc định: `tcp_idle_timeout` = 30, `udp_idle_timeout` = 10.

## Cách đối chiếu

`expected.json` **không lấy từ kết quả của chương trình**. Nó được tính từ chính các gói Scapy vừa dựng: số gói, số byte, số cờ SYN/ACK/FIN/RST và chiều đi của từng flow đếm thẳng từ các gói; trạng thái cuối và lý do kết thúc lấy từ cách dựng từng phiên (phiên đóng bằng FIN thì phải `CLOSED`, bị RST thì phải `RESET`, phiên không tự kết thúc thì hết hạn nếu thời điểm cuối của cả bộ vượt `last_seen` cộng thời gian chờ). Gói nào phải khớp rule nào được viết lại độc lập bằng Python, không dùng code của engine. Mỗi flow mong đợi được ghép với flow thật cùng 5-tuple và so từng trường; mỗi gói được so tập sid đã khớp.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp. File event rất lớn nên không được lưu trong repo; chạy lệnh dưới đây sẽ tạo nó trong `output/`:

```powershell
python main.py --pcap TEST/extra/mixed_traffic/scan_and_attack/input.pcap --rules TEST/extra/mixed_traffic/scan_and_attack/input.rules --config TEST/extra/mixed_traffic/scan_and_attack/config.json --output output/scan_and_attack_events.jsonl --flow-output output/scan_and_attack_flows.jsonl --detection-output output/scan_and_attack_detections.jsonl --rule-report output/scan_and_attack_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu bằng script:

```powershell
python TEST/extra/mixed_traffic/run_scenarios.py --scenario scan_and_attack --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (18/18 phép đối chiếu).
- Mã thoát CLI: `0`; số gói: `2013`; số flow ghi ra: `489`; số Detection Event: `444`.

| Phép đối chiếu | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `2013` | `2013` | ĐẠT |
| `skipped_events` | `0` | `0` | ĐẠT |
| `invalid_events` | `0` | `0` | ĐẠT |
| `unexpected_errors` | `0` | `0` | ĐẠT |
| `events_with_flow` | `2013` | `2013` | ĐẠT |
| `events_with_unknown_flow` | `0` | `0` | ĐẠT |
| `packets_counted_in_flows` | `2013` | `2013` | ĐẠT |
| `flow_count` | `489` | `489` | ĐẠT |
| `flows_different_from_expected` | `0` | `0` | ĐẠT |
| `detection_count` | `444` | `444` | ĐẠT |
| `detections_by_sid` | `{"3000001": 14, "3000002": 11, "3100001": 101, "3100002": 268, "3100003": 50}` | `{"3000001": 14, "3000002": 11, "3100001": 101, "3100002": 268, "3100003": 50}` | ĐẠT |
| `packets_with_different_detections` | `0` | `0` | ĐẠT |
| `engine.rules_in_repository` | `5` | `5` | ĐẠT |
| `engine.events_seen` | `2013` | `2013` | ĐẠT |
| `engine.matches` | `444` | `444` | ĐẠT |
| `engine.errors` | `0` | `0` | ĐẠT |
| `index_skips_rules` | `true` | `true` | ĐẠT |

## Artifact

- `input.pcap`: traffic đầu vào.
- `input.rules`: các rule đã nạp.
- `config.json`: các tùy chọn cấu hình khác mặc định.
- `expected.json`: thành phần của bộ traffic, flow và Detection Event mong đợi.
- `flows.jsonl`: tổng kết từng flow do chương trình ghi ra.
- `detections.jsonl`: các Detection Event, mỗi dòng một lần rule khớp.
- `rule_report.json`: kết quả nạp rule và số liệu đánh giá của engine.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về README của các bộ traffic](../README.md)
