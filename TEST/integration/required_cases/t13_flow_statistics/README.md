# T13 - Statistics

**Kết quả mong đợi theo đề:** packet/byte/flag counters và duration đúng.

## Dữ liệu đầu vào

Một phiên TCP đầy đủ gồm 10 gói trong 0,32 giây: bắt tay, client gửi POST 64 byte dữ liệu, server ACK rồi trả response, client ACK, hai bên trao đổi FIN/ACK và ACK cuối. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định (ghi đầy đủ trong `config.json`).

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/integration/required_cases/t13_flow_statistics/input.pcap --config TEST/integration/required_cases/t13_flow_statistics/config.json --output output/t13_events.jsonl --flow-output output/t13_flows.jsonl
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_required_cases.py --case T13 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (21/21 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `10`; số flow ghi ra: `1`.
- Ý nghĩa: Chiều forward (client → server) có 6 gói, 479 byte; chiều backward có 4 gói, 288 byte. Cờ: 2 SYN (SYN, SYN/ACK), 9 ACK (mọi gói trừ SYN đầu), 2 FIN, 0 RST. Duration = 0,32 giây; flow kết thúc ở trạng thái CLOSED.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `event_count` | `10` | `10` | ĐẠT |
| `flow_count` | `1` | `1` | ĐẠT |
| `flows.0.packet_count` | `10` | `10` | ĐẠT |
| `flows.0.byte_count` | `767` | `767` | ĐẠT |
| `flows.0.forward_packet_count` | `6` | `6` | ĐẠT |
| `flows.0.forward_byte_count` | `479` | `479` | ĐẠT |
| `flows.0.backward_packet_count` | `4` | `4` | ĐẠT |
| `flows.0.backward_byte_count` | `288` | `288` | ĐẠT |
| `flows.0.SYN_count` | `2` | `2` | ĐẠT |
| `flows.0.ACK_count` | `9` | `9` | ĐẠT |
| `flows.0.FIN_count` | `2` | `2` | ĐẠT |
| `flows.0.RST_count` | `0` | `0` | ĐẠT |
| `flows.0.start_time` | `1700000000.0` | `1700000000.0` | ĐẠT |
| `flows.0.last_seen` | `1700000000.32` | `1700000000.32` | ĐẠT |
| `flows.0.duration` | `0.32` | `0.32` | ĐẠT |
| `flows.0.state` | `"CLOSED"` | `"CLOSED"` | ĐẠT |
| `flows.0.handshake_observed` | `true` | `true` | ĐẠT |
| `flows.0.application_protocol` | `"HTTP"` | `"HTTP"` | ĐẠT |
| `flows.0.end_reason` | `"tcp_closed"` | `"tcp_closed"` | ĐẠT |
| `same_flow [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]` | `"cùng một flow_id"` | `["d708470a798cb5d1", "d708470a798cb5d1", "d708470a798cb5d1", "d708470a798cb5d1", "d708470a798cb5d1", "d708470a798cb5d1", "d708470a798cb5d1", "d708470a798cb5d1", "d708470a798cb5d1", "d708470a798cb5d1"]` | ĐẠT |

## Artifact

- `input.pcap`: dữ liệu đầu vào.
- `config.json`: cấu hình đã dùng.
- `expected.json`: các giá trị phải quan sát được.
- `events.jsonl`: event sau toàn bộ pipeline, mỗi dòng ứng với một gói/event đầu vào.
- `flows.jsonl`: tổng kết flow theo thứ tự được ghi ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.

[Về bảng tổng hợp](../README.md)
