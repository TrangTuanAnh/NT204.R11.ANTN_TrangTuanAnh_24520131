# Ca 14 - Detection Event

**Kết quả mong đợi theo đề:** Có đủ sid/msg/flow/5-tuple/protocol/match info.

## Dữ liệu đầu vào

Phiên HTTP từ 10.0.0.5:52133 tới 192.168.1.20:80 (đúng ví dụ trong đề): bắt tay, GET /../../etc/passwd, rồi GET viết mã hóa /a/..%2f..%2fetc/passwd. Một rule Directory traversal có đủ msg, sid, rev, classtype, priority. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case14_detection_event/input.pcap --rules TEST/BT3/case14_detection_event/input.rules --config TEST/BT3/case14_detection_event/config.json --output output/case14_events.jsonl --flow-output output/case14_flows.jsonl --detection-output output/case14_detections.jsonl --rule-report output/case14_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_detection_cases.py --case 14 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (22/22 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `5`; số Detection Event: `2`.
- Ý nghĩa: Detection Event có đủ timestamp, sid, rev, msg, priority, classtype, 5-tuple, protocol, application_protocol, flow_id và thông tin khớp (chuỗi và vị trí). Gói thứ hai không có ../ trong byte gốc nhưng vẫn bị phát hiện nhờ URI đã giải mã; thông tin khớp ghi rõ buffer là application.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `2` | `2` | ĐẠT |
| `detections.0.timestamp` | `1700000000.03` | `1700000000.03` | ĐẠT |
| `detections.0.packet_id` | `4` | `4` | ĐẠT |
| `detections.0.sid` | `100001` | `100001` | ĐẠT |
| `detections.0.rev` | `1` | `1` | ĐẠT |
| `detections.0.msg` | `"Directory traversal detected"` | `"Directory traversal detected"` | ĐẠT |
| `detections.0.priority` | `1` | `1` | ĐẠT |
| `detections.0.classtype` | `"web-application-attack"` | `"web-application-attack"` | ĐẠT |
| `detections.0.src_ip` | `"10.0.0.5"` | `"10.0.0.5"` | ĐẠT |
| `detections.0.src_port` | `52133` | `52133` | ĐẠT |
| `detections.0.dst_ip` | `"192.168.1.20"` | `"192.168.1.20"` | ĐẠT |
| `detections.0.dst_port` | `80` | `80` | ĐẠT |
| `detections.0.protocol` | `"TCP"` | `"TCP"` | ĐẠT |
| `detections.0.application_protocol` | `"HTTP"` | `"HTTP"` | ĐẠT |
| `detections.0.match.buffer` | `"payload"` | `"payload"` | ĐẠT |
| `detections.0.match.contents` | `[{"content": "../", "position": 5, "nocase": false, "negated": false}]` | `[{"content": "../", "position": 5, "nocase": false, "negated": false}]` | ĐẠT |
| `detections.0.match.flow` | `{"direction": "forward", "state": "ESTABLISHED", "established": true}` | `{"direction": "forward", "state": "ESTABLISHED", "established": true}` | ĐẠT |
| `detections.1.packet_id` | `5` | `5` | ĐẠT |
| `detections.1.match.buffer` | `"application"` | `"application"` | ĐẠT |
| `detections.0.flow_id = events.3.flow_id` | `"hai giá trị bằng nhau"` | `["bf720fcad18fbaa7", "bf720fcad18fbaa7"]` | ĐẠT |
| `detections.1.flow_id = events.3.flow_id` | `"hai giá trị bằng nhau"` | `["bf720fcad18fbaa7", "bf720fcad18fbaa7"]` | ĐẠT |

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
