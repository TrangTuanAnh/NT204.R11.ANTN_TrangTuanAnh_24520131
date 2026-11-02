# Ca 03 - Keyword ngoài phạm vi

**Kết quả mong đợi theo đề:** Đánh dấu unsupported; không crash.

## Dữ liệu đầu vào

Tám rule đều tìm chuỗi GET có trong gói: một rule trong phạm vi và bảy rule dùng thành phần ngoài phạm vi: pcre, byte_test, http_uri, metadata, hành động drop, giao thức icmp, flow:from_client. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case03_out_of_scope_keywords/input.pcap --rules TEST/BT3/case03_out_of_scope_keywords/input.rules --config TEST/BT3/case03_out_of_scope_keywords/config.json --output output/case03_events.jsonl --flow-output output/case03_flows.jsonl --detection-output output/case03_detections.jsonl --rule-report output/case03_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_detection_cases.py --case 03 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (17/17 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `1`; số Detection Event: `1`.
- Ý nghĩa: Bảy rule ngoài phạm vi có status unsupported kèm lý do và bị bỏ hẳn: dù gói có chuỗi GET, chúng không sinh Detection Event. report.unsupported_keywords thống kê các keyword đã làm rule bị bỏ.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `1` | `1` | ĐẠT |
| `report.summary.rule_lines` | `8` | `8` | ĐẠT |
| `report.summary.valid` | `1` | `1` | ĐẠT |
| `report.summary.unsupported` | `7` | `7` | ĐẠT |
| `report.summary.invalid` | `0` | `0` | ĐẠT |
| `report.engine.rules_in_repository` | `1` | `1` | ĐẠT |
| `report.rules.1.status` | `"unsupported"` | `"unsupported"` | ĐẠT |
| `report.rules.1.reasons` | `["Keyword pcre ngoài phạm vi hỗ trợ"]` | `["Keyword pcre ngoài phạm vi hỗ trợ"]` | ĐẠT |
| `report.rules.2.reasons` | `["Keyword byte_test ngoài phạm vi hỗ trợ"]` | `["Keyword byte_test ngoài phạm vi hỗ trợ"]` | ĐẠT |
| `report.rules.3.reasons` | `["Keyword http_uri ngoài phạm vi hỗ trợ"]` | `["Keyword http_uri ngoài phạm vi hỗ trợ"]` | ĐẠT |
| `report.rules.4.reasons` | `["Keyword metadata ngoài phạm vi hỗ trợ"]` | `["Keyword metadata ngoài phạm vi hỗ trợ"]` | ĐẠT |
| `report.rules.5.reasons` | `["Hành động drop ngoài phạm vi hỗ trợ"]` | `["Hành động drop ngoài phạm vi hỗ trợ"]` | ĐẠT |
| `report.rules.6.reasons` | `["Giao thức icmp ngoài phạm vi hỗ trợ"]` | `["Giao thức icmp ngoài phạm vi hỗ trợ"]` | ĐẠT |
| `report.rules.7.reasons` | `["Giá trị flow from_client ngoài phạm vi hỗ trợ"]` | `["Giá trị flow from_client ngoài phạm vi hỗ trợ"]` | ĐẠT |
| `report.unsupported_keywords` | `{"pcre": 1, "byte_test": 1, "http_uri": 1, "metadata": 1, "flow:from_client": 1}` | `{"pcre": 1, "byte_test": 1, "http_uri": 1, "metadata": 1, "flow:from_client": 1}` | ĐẠT |
| `by_packet.1` | `[100301]` | `[100301]` | ĐẠT |

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
