# Ca 10 - offset/depth

**Kết quả mong đợi theo đề:** Chỉ match trong vùng được chỉ định.

## Dữ liệu đầu vào

Một gói có dữ liệu GET /index.html ..., chuỗi GET ở byte 0-2, chuỗi index ở byte 5-9. Sáu rule thử vùng tìm: GET với depth:3; GET với offset:1; index với offset:5 và depth:5; index với depth:5; index với offset:6; index với offset:4 và depth:5. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case10_offset_depth/input.pcap --rules TEST/BT3/case10_offset_depth/input.rules --config TEST/BT3/case10_offset_depth/config.json --output output/case10_events.jsonl --flow-output output/case10_flows.jsonl --detection-output output/case10_detections.jsonl --rule-report output/case10_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/BT3/run_cases.py --case 10 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (7/7 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `1`; số Detection Event: `2`.
- Ý nghĩa: Chỉ rule có vùng tìm chứa trọn chuỗi mới khớp. Vùng offset:5 depth:5 là byte 5-9, chứa vừa đủ index. Vùng depth:5 là byte 0-4 và vùng offset:4 depth:5 là byte 4-8 đều chỉ chứa một phần chuỗi nên không khớp.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `2` | `2` | ĐẠT |
| `by_packet.1` | `[101001, 101003]` | `[101001, 101003]` | ĐẠT |
| `report.engine.rejected.content` | `4` | `4` | ĐẠT |
| `detections.0.match.contents.0.position` | `0` | `0` | ĐẠT |
| `detections.1.match.contents.0.position` | `5` | `5` | ĐẠT |
| `detections.0.match.buffer` | `"payload"` | `"payload"` | ĐẠT |

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
