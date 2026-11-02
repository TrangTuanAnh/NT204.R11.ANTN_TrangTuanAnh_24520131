# Ca 08 - flow:to_server,established

**Kết quả mong đợi theo đề:** Match đúng theo Flow Tracker.

## Dữ liệu đầu vào

Một phiên TCP sáu gói có chuỗi secret ở gói SYN, request, response và gói FIN kèm dữ liệu. Bốn rule dùng <> để header khớp cả hai chiều, chỉ còn flow quyết định: to_server,established; to_client,established; not_established; established. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case08_flow/input.pcap --rules TEST/BT3/case08_flow/input.rules --config TEST/BT3/case08_flow/config.json --output output/case08_events.jsonl --flow-output output/case08_flows.jsonl --detection-output output/case08_detections.jsonl --rule-report output/case08_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_detection_cases.py --case 08 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (16/16 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `6`; số Detection Event: `9`.
- Ý nghĩa: Gói SYN có chuỗi secret nhưng kết nối chưa thông nên to_server,established không khớp. Request chỉ khớp to_server, response chỉ khớp to_client. Gói FIN kèm dữ liệu ở trạng thái CLOSING vẫn tính là established, vì kết nối đã thông và vẫn đang truyền dữ liệu.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `9` | `9` | ĐẠT |
| `events.0.flow_state` | `"NEW"` | `"NEW"` | ĐẠT |
| `events.1.flow_state` | `"HANDSHAKE"` | `"HANDSHAKE"` | ĐẠT |
| `events.2.flow_state` | `"ESTABLISHED"` | `"ESTABLISHED"` | ĐẠT |
| `events.3.direction` | `"forward"` | `"forward"` | ĐẠT |
| `events.4.direction` | `"backward"` | `"backward"` | ĐẠT |
| `events.5.flow_state` | `"CLOSING"` | `"CLOSING"` | ĐẠT |
| `by_packet.1` | `[100803]` | `[100803]` | ĐẠT |
| `by_packet.2` | `[100803]` | `[100803]` | ĐẠT |
| `by_packet.3` | `[100804]` | `[100804]` | ĐẠT |
| `by_packet.4` | `[100801, 100804]` | `[100801, 100804]` | ĐẠT |
| `by_packet.5` | `[100802, 100804]` | `[100802, 100804]` | ĐẠT |
| `by_packet.6` | `[100801, 100804]` | `[100801, 100804]` | ĐẠT |
| `report.engine.matches` | `9` | `9` | ĐẠT |
| `detections.3.match.flow` | `{"direction": "forward", "state": "ESTABLISHED", "established": true}` | `{"direction": "forward", "state": "ESTABLISHED", "established": true}` | ĐẠT |

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
