# Ca 05 - Direction -> và <>

**Kết quả mong đợi theo đề:** So khớp đúng chiều/bidirectional.

## Dữ liệu đầu vào

Ba gói: client 10.0.0.5:52133 → server 192.168.1.20:80; server → client (chiều ngược); và một client khác 10.0.0.6 → server. Hai rule cùng địa chỉ, một rule dùng -> và một rule dùng <>. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case05_direction/input.pcap --rules TEST/BT3/case05_direction/input.rules --config TEST/BT3/case05_direction/config.json --output output/case05_events.jsonl --flow-output output/case05_flows.jsonl --detection-output output/case05_detections.jsonl --rule-report output/case05_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_detection_cases.py --case 05 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (12/12 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `3`; số Detection Event: `3`.
- Ý nghĩa: Rule -> chỉ khớp gói đi đúng chiều. Rule <> khớp cả hai chiều và ghi reversed_direction là true với gói ngược; Detection Event vẫn ghi đúng nguồn và đích thật của gói. Gói từ client khác không khớp rule nào.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `3` | `3` | ĐẠT |
| `by_packet.1` | `[100501, 100502]` | `[100501, 100502]` | ĐẠT |
| `by_packet.2` | `[100502]` | `[100502]` | ĐẠT |
| `by_packet.3` | `[]` | `[]` | ĐẠT |
| `detections.0.match.reversed_direction` | `false` | `false` | ĐẠT |
| `detections.1.match.reversed_direction` | `false` | `false` | ĐẠT |
| `detections.2.match.reversed_direction` | `true` | `true` | ĐẠT |
| `detections.2.src_ip` | `"192.168.1.20"` | `"192.168.1.20"` | ĐẠT |
| `detections.2.src_port` | `80` | `80` | ĐẠT |
| `detections.2.dst_ip` | `"10.0.0.5"` | `"10.0.0.5"` | ĐẠT |
| `detections.2.dst_port` | `52133` | `52133` | ĐẠT |

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
