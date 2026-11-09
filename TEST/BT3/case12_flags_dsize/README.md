# Ca 12 - flags và dsize

**Kết quả mong đợi theo đề:** Match/không match đúng theo event.

## Dữ liệu đầu vào

Bảy gói: SYN; SYN/ACK; PSH/ACK 5 byte; FIN/ACK; ACK 200 byte; gói không có cờ; SYN có thêm hai cờ ECN (CWR, ECE). Mười ba rule thử các dạng flags (đúng cờ, +, *, !, 0, cờ bỏ qua) và dsize (bằng, >, <, khoảng, kết hợp). File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case12_flags_dsize/input.pcap --rules TEST/BT3/case12_flags_dsize/input.rules --config TEST/BT3/case12_flags_dsize/config.json --output output/case12_events.jsonl --flow-output output/case12_flows.jsonl --detection-output output/case12_detections.jsonl --rule-report output/case12_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/BT3/run_cases.py --case 12 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (11/11 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `7`; số Detection Event: `22`.
- Ý nghĩa: flags:S chỉ khớp gói có đúng cờ SYN, không khớp gói SYN có thêm cờ ECN; flags:S,CE bỏ qua hai cờ ECN nên khớp cả hai. flags:+A khớp mọi gói có ACK, flags:!A khớp gói không có ACK, flags:0 chỉ khớp gói không có cờ. dsize khoảng 3<>5 tính cả hai đầu nên khớp gói 5 byte; khoảng 6<>199 không có gói nào.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `by_packet.1` | `[101201, 101205, 101207, 101210]` | `[101201, 101205, 101207, 101210]` | ĐẠT |
| `by_packet.2` | `[101202, 101203, 101210]` | `[101202, 101203, 101210]` | ĐẠT |
| `by_packet.3` | `[101203, 101208, 101211, 101213]` | `[101203, 101208, 101211, 101213]` | ĐẠT |
| `by_packet.4` | `[101203, 101204, 101210]` | `[101203, 101204, 101210]` | ĐẠT |
| `by_packet.5` | `[101203, 101209]` | `[101203, 101209]` | ĐẠT |
| `by_packet.6` | `[101205, 101206, 101210]` | `[101205, 101206, 101210]` | ĐẠT |
| `by_packet.7` | `[101205, 101207, 101210]` | `[101205, 101207, 101210]` | ĐẠT |
| `events.5.transport.flags` | `""` | `""` | ĐẠT |
| `events.6.transport.flags` | `"SEC"` | `"SEC"` | ĐẠT |
| `report.summary.valid` | `13` | `13` | ĐẠT |

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
