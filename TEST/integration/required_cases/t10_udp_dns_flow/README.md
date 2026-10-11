# T10 - UDP query/response

**Kết quả mong đợi theo đề:** 1 UDP flow, packet/byte count đúng.

## Dữ liệu đầu vào

Một truy vấn DNS từ 192.0.2.10:53000 tới 192.0.2.53:53 và câu trả lời ngược lại (bản ghi A 192.0.2.80). File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t10_udp_dns_flow/input.pcap --config TEST/integration/required_cases/t10_udp_dns_flow/config.json --output output/t10_events.jsonl --flow-output output/t10_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T10 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (18/18 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `2`; số flow ghi ra: `1`.
- Ý nghĩa: Hai gói ngược chiều cùng 5-tuple tạo một flow UDP. byte_count là tổng độ dài hai khung Ethernet (76 + 108 byte). UDP không có trạng thái kết nối nên state và các bộ đếm cờ TCP là null.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `2` | `2` | ĐẠT |
| `flow_count` | `1` | `1` | ĐẠT |
| `events.0.direction` | `"forward"` | `"forward"` | ĐẠT |
| `events.1.direction` | `"backward"` | `"backward"` | ĐẠT |
| `events.1.application.answers` | `[{"name": "www.example.test", "type": 1, "data": "192.0.2.80"}]` | `[{"name": "www.example.test", "type": 1, "data": "192.0.2.80"}]` | ĐẠT |
| `flows.0.protocol` | `"UDP"` | `"UDP"` | ĐẠT |
| `flows.0.application_protocol` | `"DNS"` | `"DNS"` | ĐẠT |
| `flows.0.packet_count` | `2` | `2` | ĐẠT |
| `flows.0.byte_count` | `184` | `184` | ĐẠT |
| `flows.0.forward_packet_count` | `1` | `1` | ĐẠT |
| `flows.0.forward_byte_count` | `76` | `76` | ĐẠT |
| `flows.0.backward_packet_count` | `1` | `1` | ĐẠT |
| `flows.0.backward_byte_count` | `108` | `108` | ĐẠT |
| `flows.0.duration` | `0.05` | `0.05` | ĐẠT |
| `flows.0.state` | `null` | `null` | ĐẠT |
| `flows.0.SYN_count` | `null` | `null` | ĐẠT |
| `same_flow [0, 1]` | `"cùng một flow_id"` | `["5d8565c772fdef1a", "5d8565c772fdef1a"]` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
