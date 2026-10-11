# T07 - TCP handshake

**Kết quả mong đợi theo đề:** 1 flow; trạng thái ESTABLISHED.

## Dữ liệu đầu vào

Ba gói: client 192.0.2.10:40000 gửi SYN, server 192.0.2.20:80 trả SYN/ACK, client gửi ACK. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t07_tcp_connection_handshake/input.pcap --config TEST/integration/required_cases/t07_tcp_connection_handshake/config.json --output output/t07_events.jsonl --flow-output output/t07_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T07 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (13/13 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `3`; số flow ghi ra: `1`.
- Ý nghĩa: Sau từng gói, trạng thái lần lượt là NEW → HANDSHAKE → ESTABLISHED; cả ba gói thuộc một flow và handshake_observed là true.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `3` | `3` | ĐẠT |
| `flow_count` | `1` | `1` | ĐẠT |
| `events.0.flow_state` | `"NEW"` | `"NEW"` | ĐẠT |
| `events.1.flow_state` | `"HANDSHAKE"` | `"HANDSHAKE"` | ĐẠT |
| `events.2.flow_state` | `"ESTABLISHED"` | `"ESTABLISHED"` | ĐẠT |
| `flows.0.state` | `"ESTABLISHED"` | `"ESTABLISHED"` | ĐẠT |
| `flows.0.handshake_observed` | `true` | `true` | ĐẠT |
| `flows.0.packet_count` | `3` | `3` | ĐẠT |
| `flows.0.SYN_count` | `2` | `2` | ĐẠT |
| `flows.0.ACK_count` | `2` | `2` | ĐẠT |
| `flows.0.end_reason` | `"end_of_input"` | `"end_of_input"` | ĐẠT |
| `same_flow [0, 1, 2]` | `"cùng một flow_id"` | `["d708470a798cb5d1", "d708470a798cb5d1", "d708470a798cb5d1"]` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
