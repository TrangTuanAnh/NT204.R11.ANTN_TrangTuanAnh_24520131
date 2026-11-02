# Ca 07 - Header không match

**Kết quả mong đợi theo đề:** Rule bị loại trước content matching.

## Dữ liệu đầu vào

Năm rule đều tìm chuỗi GET có trong gói: sai IP nguồn, sai IP đích, sai port đích, sai giao thức và một rule đúng header. Một gói HTTP GET tới port 80. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case07_header_mismatch/input.pcap --rules TEST/BT3/case07_header_mismatch/input.rules --config TEST/BT3/case07_header_mismatch/config.json --output output/case07_events.jsonl --flow-output output/case07_flows.jsonl --detection-output output/case07_detections.jsonl --rule-report output/case07_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_detection_cases.py --case 07 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (10/10 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `1`; số Detection Event: `1`.
- Ý nghĩa: Rule sai port và sai giao thức bị chỉ mục loại ngay (candidates chỉ còn 3 rule). Hai rule sai IP bị loại ở bước header (rejected.header là 2). Chỉ rule đúng header đi tới bước tìm content (content_checks là 1), dù cả năm rule đều có chuỗi GET khớp với gói.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `1` | `1` | ĐẠT |
| `candidates.0` | `[100701, 100702, 100705]` | `[100701, 100702, 100705]` | ĐẠT |
| `report.engine.rules_in_repository` | `5` | `5` | ĐẠT |
| `report.engine.candidate_rules` | `3` | `3` | ĐẠT |
| `report.engine.rejected.header` | `2` | `2` | ĐẠT |
| `report.engine.rejected.content` | `0` | `0` | ĐẠT |
| `report.engine.content_checks` | `1` | `1` | ĐẠT |
| `report.engine.matches` | `1` | `1` | ĐẠT |
| `by_packet.1` | `[100705]` | `[100705]` | ĐẠT |

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
