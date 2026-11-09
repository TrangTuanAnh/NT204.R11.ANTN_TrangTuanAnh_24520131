# Ca B1 - Bộ rule cộng đồng của Snort

**Kết quả mong đợi theo đề:** Rule/keyword ngoài phạm vi được báo unsupported, không làm chương trình dừng.

## Dữ liệu đầu vào

Nạp nguyên file rules/community.rules tải từ snort.org, gồm 568 rule đang bật và các rule đã bị comment. Một gói HTTP GET để chạy trọn đường đi. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/extra/snort_community_rules/input.pcap --rules rules/community.rules --config TEST/extra/snort_community_rules/config.json --output output/snort_community_rules_events.jsonl --flow-output output/snort_community_rules_flows.jsonl --detection-output output/snort_community_rules_detections.jsonl --rule-report output/snort_community_rules_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/BT3/run_cases.py --case B1 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (10/10 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `1`; số Detection Event: `0`.
- Ý nghĩa: Cả 568 rule đều đúng cú pháp nhưng đều có keyword ngoài phạm vi (ít nhất là metadata), nên đều là unsupported và bị bỏ theo quy tắc của bài làm: kho rule rỗng và không có Detection Event. Chương trình đọc hết file, thoát với mã 0, report.unsupported_keywords cho biết keyword nào làm rule bị bỏ.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `0` | `0` | ĐẠT |
| `report.summary.rule_lines` | `568` | `568` | ĐẠT |
| `report.summary.valid` | `0` | `0` | ĐẠT |
| `report.summary.invalid` | `0` | `0` | ĐẠT |
| `report.summary.unsupported` | `568` | `568` | ĐẠT |
| `report.unsupported_keywords.metadata` | `568` | `568` | ĐẠT |
| `report.engine.rules_in_repository` | `0` | `0` | ĐẠT |
| `report.engine.events_evaluated` | `1` | `1` | ĐẠT |
| `report.engine.errors` | `0` | `0` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `rules/community.rules`: file rule có sẵn trong repo.
- `config.json`: các tùy chọn cấu hình khác mặc định.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`, `flows.jsonl`: event và tổng kết flow của các bước trước.
- `detections.jsonl`: các Detection Event, mỗi dòng một lần rule khớp.
- `rule_report.json`: kết quả nạp từng rule và số liệu đánh giá của engine.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
