# Ca 06 - Indexer với IP, TCP, UDP và any

**Kết quả mong đợi theo đề:** Trả đúng tập candidate rules.

## Dữ liệu đầu vào

Tám rule: ip; tcp any; tcp đích 80; tcp nguồn 80; tcp đích khoảng 8000-8100; udp any; udp đích 53; tcp đích 443 kèm IP cụ thể. Tám gói: TCP tới 80, TCP từ 80, TCP tới 8080, TCP tới 443, TCP tới 22, UDP tới 53, UDP tới 123 và một gói ICMP. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case06_indexer/input.pcap --rules TEST/BT3/case06_indexer/input.rules --config TEST/BT3/case06_indexer/config.json --output output/case06_events.jsonl --flow-output output/case06_flows.jsonl --detection-output output/case06_detections.jsonl --rule-report output/case06_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_detection_cases.py --case 06 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (13/13 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `8`; số Detection Event: `20`.
- Ý nghĩa: candidates.<i> là tập rule mà chỉ mục chọn cho gói thứ i, lấy trực tiếp từ Repository: rule ip luôn được chọn; rule TCP/UDP chỉ được chọn đúng giao thức và port; gói ICMP không có port nên chỉ có rule ip. Tổng cộng chỉ phải xét 20 lượt rule thay vì 64 lượt nếu duyệt toàn bộ (8 gói × 8 rule).

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `report.summary.valid` | `8` | `8` | ĐẠT |
| `candidates.0` | `[100601, 100602, 100603]` | `[100601, 100602, 100603]` | ĐẠT |
| `candidates.1` | `[100601, 100602, 100604]` | `[100601, 100602, 100604]` | ĐẠT |
| `candidates.2` | `[100601, 100602, 100605]` | `[100601, 100602, 100605]` | ĐẠT |
| `candidates.3` | `[100601, 100602, 100608]` | `[100601, 100602, 100608]` | ĐẠT |
| `candidates.4` | `[100601, 100602]` | `[100601, 100602]` | ĐẠT |
| `candidates.5` | `[100601, 100606, 100607]` | `[100601, 100606, 100607]` | ĐẠT |
| `candidates.6` | `[100601, 100606]` | `[100601, 100606]` | ĐẠT |
| `candidates.7` | `[100601]` | `[100601]` | ĐẠT |
| `report.engine.events_evaluated` | `8` | `8` | ĐẠT |
| `report.engine.rules_in_repository` | `8` | `8` | ĐẠT |
| `report.engine.candidate_rules` | `20` | `20` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `input.rules`: file rule của ca.
- `config.json`: các tùy chọn cấu hình khác mặc định.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`, `flows.jsonl`: event và tổng kết flow của các bước trước.
- `detections.jsonl`: các Detection Event, mỗi dòng một lần rule khớp.
- `rule_report.json`: kết quả nạp từng rule và số liệu đánh giá của engine.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
