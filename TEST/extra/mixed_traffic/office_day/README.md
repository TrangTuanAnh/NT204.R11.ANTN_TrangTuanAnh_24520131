# Một ngày làm việc của văn phòng

Web, thư, DNS, SSH và luồng UDP của nhiều máy xen kẽ nhau trong 9 phút, thêm gói ICMP, ARP, IP phân mảnh và một số tấn công (directory traversal, SQL injection, truy vấn DNS tới tên miền lạ, thư kèm file .exe). Thời gian chờ để mặc định.

`input.pcap` có **2130 gói** (329 KB), kéo dài khoảng 542 giây, tạo **236 flow**. Dữ liệu là traffic tổng hợp dựng bằng Scapy từ seed `20261101` (địa chỉ thuộc dải dành cho tài liệu và mạng riêng), được đọc offline, không gửi ra mạng.

## Thành phần

| Loại | Số phiên (mỗi phiên là một flow) | Số gói |
| --- | --- | --- |
| dns | 136 | 272 |
| http | 58 | 832 |
| http_reset | 6 | 50 |
| smtp | 15 | 495 |
| ssh | 13 | 355 |
| udp_game | 8 | 88 |
| unsupported | - | 38 |

## Rule

| sid | Rule | Số lần khớp mong đợi |
| --- | --- | --- |
| 3000001 | `alert tcp any any -> any 80 (msg:"Directory traversal"; flow:to_server,established; content:"../"; classtype:web-application-attack; priority:1; sid:3000001; rev:1;)` | 6 |
| 3000002 | `alert tcp any any -> any 80 (msg:"SQL injection attempt"; flow:to_server,established; content:"' OR 1=1"; nocase; classtype:web-application-attack; priority:1; sid:3000002; rev:1;)` | 4 |
| 3000003 | `alert udp any any -> any 53 (msg:"DNS query to suspicious domain"; content:"c2-update"; nocase; classtype:trojan-activity; priority:2; sid:3000003; rev:1;)` | 4 |
| 3000004 | `alert tcp any any -> any 25 (msg:"Executable attachment in mail"; flow:to_server,established; content:"invoice.exe"; nocase; classtype:policy-violation; priority:3; sid:3000004; rev:1;)` | 3 |
| 3000005 | `alert tcp any any -> any 22 (msg:"SSH banner"; flow:to_server,established; content:"SSH-"; offset:0; depth:4; sid:3000005; rev:1;)` | 13 |
| 3000006 | `alert udp any any -> any 5000 (msg:"Large game packet"; dsize:>150; sid:3000006; rev:1;)` | 23 |

Cấu hình mặc định.

## Cách đối chiếu

`expected.json` **không lấy từ kết quả của chương trình**. Nó được tính từ chính các gói Scapy vừa dựng: số gói, số byte, số cờ SYN/ACK/FIN/RST và chiều đi của từng flow đếm thẳng từ các gói; trạng thái cuối và lý do kết thúc lấy từ cách dựng từng phiên (phiên đóng bằng FIN thì phải `CLOSED`, bị RST thì phải `RESET`, phiên không tự kết thúc thì hết hạn nếu thời điểm cuối của cả bộ vượt `last_seen` cộng thời gian chờ). Gói nào phải khớp rule nào được viết lại độc lập bằng Python, không dùng code của engine. Mỗi flow mong đợi được ghép với flow thật cùng 5-tuple và so từng trường; mỗi gói được so tập sid đã khớp.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp. File event rất lớn nên không được lưu trong repo; chạy lệnh dưới đây sẽ tạo nó trong `output/`:

```powershell
python main.py --pcap TEST/extra/mixed_traffic/office_day/input.pcap --rules TEST/extra/mixed_traffic/office_day/input.rules --config TEST/extra/mixed_traffic/office_day/config.json --output output/office_day_events.jsonl --flow-output output/office_day_flows.jsonl --detection-output output/office_day_detections.jsonl --rule-report output/office_day_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu bằng script:

```powershell
python TEST/extra/mixed_traffic/run_scenarios.py --scenario office_day --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (18/18 phép đối chiếu).
- Mã thoát CLI: `0`; số gói: `2130`; số flow ghi ra: `236`; số Detection Event: `53`.

| Phép đối chiếu | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `2130` | `2130` | ĐẠT |
| `skipped_events` | `38` | `38` | ĐẠT |
| `invalid_events` | `0` | `0` | ĐẠT |
| `unexpected_errors` | `0` | `0` | ĐẠT |
| `events_with_flow` | `2092` | `2092` | ĐẠT |
| `events_with_unknown_flow` | `0` | `0` | ĐẠT |
| `packets_counted_in_flows` | `2092` | `2092` | ĐẠT |
| `flow_count` | `236` | `236` | ĐẠT |
| `flows_different_from_expected` | `0` | `0` | ĐẠT |
| `detection_count` | `53` | `53` | ĐẠT |
| `detections_by_sid` | `{"3000001": 6, "3000002": 4, "3000003": 4, "3000004": 3, "3000005": 13, "3000006": 23}` | `{"3000001": 6, "3000002": 4, "3000003": 4, "3000004": 3, "3000005": 13, "3000006": 23}` | ĐẠT |
| `packets_with_different_detections` | `0` | `0` | ĐẠT |
| `engine.rules_in_repository` | `6` | `6` | ĐẠT |
| `engine.events_seen` | `2130` | `2130` | ĐẠT |
| `engine.matches` | `53` | `53` | ĐẠT |
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
