# Ca 01 - Nạp file rule

**Kết quả mong đợi theo đề:** Chỉ rule hợp lệ được đưa sang parser.

## Dữ liệu đầu vào

File input.rules có 3 dòng comment (một dòng là rule đã bị comment), 2 dòng trống, một rule viết trên một dòng, một rule viết trên hai dòng và một rule bị tắt bằng disabled_sids. File disabled.rules bị tắt cả file bằng disabled_rule_files. Một gói HTTP GET có đủ các chuỗi mà mọi rule tìm. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình khác mặc định: `disabled_rule_files` = ["disabled.rules"], `disabled_sids` = [100104].

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case01_rule_loading/input.pcap --rules TEST/BT3/case01_rule_loading/input.rules TEST/BT3/case01_rule_loading/disabled.rules --config TEST/BT3/case01_rule_loading/config.json --output output/case01_events.jsonl --flow-output output/case01_flows.jsonl --detection-output output/case01_detections.jsonl --rule-report output/case01_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_detection_cases.py --case 01 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (21/21 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `1`; số Detection Event: `2`.
- Ý nghĩa: Chỉ ba rule của input.rules tới bước phân tích; comment và dòng trống bị bỏ, rule đã comment (sid 100102) không được nạp. Rule tắt bằng sid và cả file bị tắt không sinh cảnh báo. Gói GET chỉ khớp hai rule còn lại.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `2` | `2` | ĐẠT |
| `report.summary.files` | `2` | `2` | ĐẠT |
| `report.summary.disabled_files` | `1` | `1` | ĐẠT |
| `report.summary.comment_lines` | `3` | `3` | ĐẠT |
| `report.summary.blank_lines` | `2` | `2` | ĐẠT |
| `report.summary.rule_lines` | `3` | `3` | ĐẠT |
| `report.summary.valid` | `2` | `2` | ĐẠT |
| `report.summary.invalid` | `0` | `0` | ĐẠT |
| `report.summary.disabled` | `1` | `1` | ĐẠT |
| `report.files.1.enabled` | `false` | `false` | ĐẠT |
| `report.rules.0.line` | `4` | `4` | ĐẠT |
| `report.rules.0.sid` | `100101` | `100101` | ĐẠT |
| `report.rules.0.status` | `"valid"` | `"valid"` | ĐẠT |
| `report.rules.1.line` | `7` | `7` | ĐẠT |
| `report.rules.1.sid` | `100103` | `100103` | ĐẠT |
| `report.rules.1.status` | `"valid"` | `"valid"` | ĐẠT |
| `report.rules.2.line` | `9` | `9` | ĐẠT |
| `report.rules.2.sid` | `100104` | `100104` | ĐẠT |
| `report.rules.2.status` | `"disabled"` | `"disabled"` | ĐẠT |
| `by_packet.1` | `[100101, 100103]` | `[100101, 100103]` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `input.rules`: file rule của ca.
- `disabled.rules`: file rule của ca.
- `config.json`: các tùy chọn cấu hình khác mặc định.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`, `flows.jsonl`: event và tổng kết flow của các bước trước.
- `detections.jsonl`: các Detection Event, mỗi dòng một lần rule khớp.
- `rule_report.json`: kết quả nạp từng rule và số liệu đánh giá của engine.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
