# Ca 02 - Rule sai cú pháp

**Kết quả mong đợi theo đề:** Đánh dấu invalid, có lý do; engine tiếp tục chạy.

## Dữ liệu đầu vào

Mười bốn rule: hai rule hợp lệ ở đầu và cuối file, xen giữa là mười hai rule sai: thiếu chiều, chiều sai, IP sai, port quá lớn, thiếu dấu đóng ngoặc, thiếu dấu nháy đóng, thiếu msg, thiếu sid, sid không phải số, nocase không có content, content hex lẻ chữ số, sid trùng rule khác. File `input.pcap` chứa gói tin tổng hợp dựng bằng Scapy, được đọc offline.

Cấu hình mặc định.

## Cách chạy lại

Từ thư mục gốc repo; dùng tên file output mới vì chương trình ghi nối tiếp:

```powershell
python main.py --pcap TEST/BT3/case02_syntax_errors/input.pcap --rules TEST/BT3/case02_syntax_errors/input.rules --config TEST/BT3/case02_syntax_errors/config.json --output output/case02_events.jsonl --flow-output output/case02_flows.jsonl --detection-output output/case02_detections.jsonl --rule-report output/case02_rule_report.json
```

Tạo lại toàn bộ đầu vào, chạy và đối chiếu ca này bằng script:

```powershell
python TEST/integration/run_detection_cases.py --case 02 --overwrite
```

## Kết quả đã chạy

- Kết luận: **ĐẠT** (22/22 phép đối chiếu).
- Mã thoát CLI: `0`; số event: `1`; số Detection Event: `2`.
- Ý nghĩa: Mỗi rule sai có status invalid kèm lý do cụ thể và không vào kho rule. Rule hợp lệ đứng sau các rule sai vẫn được nạp, chương trình thoát với mã 0 và gói GET vẫn khớp hai rule hợp lệ.

| Trường kiểm tra | Mong đợi | Thực tế | Kết quả |
| --- | --- | --- | --- |
| `exit_code` | `0` | `0` | ĐẠT |
| `detection_count` | `2` | `2` | ĐẠT |
| `report.summary.rule_lines` | `14` | `14` | ĐẠT |
| `report.summary.valid` | `2` | `2` | ĐẠT |
| `report.summary.invalid` | `12` | `12` | ĐẠT |
| `report.engine.rules_in_repository` | `2` | `2` | ĐẠT |
| `report.rules.0.status` | `"valid"` | `"valid"` | ĐẠT |
| `report.rules.1.status` | `"invalid"` | `"invalid"` | ĐẠT |
| `report.rules.1.reasons` | `["Header phải có đủ 7 phần, đang có 6: 'alert tcp any any any 80'"]` | `["Header phải có đủ 7 phần, đang có 6: 'alert tcp any any any 80'"]` | ĐẠT |
| `report.rules.2.reasons` | `["Chiều phải là -> hoặc <>, đang là '=>'"]` | `["Chiều phải là -> hoặc <>, đang là '=>'"]` | ĐẠT |
| `report.rules.3.reasons` | `["IP nguồn không hợp lệ (999.1.1.1): '999.1.1.1' does not appear to be an IPv4 or IPv6 network"]` | `["IP nguồn không hợp lệ (999.1.1.1): '999.1.1.1' does not appear to be an IPv4 or IPv6 network"]` | ĐẠT |
| `report.rules.4.reasons` | `["Port nguồn không hợp lệ (70000): port phải từ 0 đến 65535"]` | `["Port nguồn không hợp lệ (70000): port phải từ 0 đến 65535"]` | ĐẠT |
| `report.rules.5.reasons` | `["Rule phải kết thúc bằng dấu \")\""]` | `["Rule phải kết thúc bằng dấu \")\""]` | ĐẠT |
| `report.rules.6.reasons` | `["Phần tùy chọn sai cú pháp: thiếu dấu \" đóng"]` | `["Phần tùy chọn sai cú pháp: thiếu dấu \" đóng"]` | ĐẠT |
| `report.rules.7.reasons` | `["Rule thiếu keyword bắt buộc msg"]` | `["Rule thiếu keyword bắt buộc msg"]` | ĐẠT |
| `report.rules.8.reasons` | `["Rule thiếu keyword bắt buộc sid"]` | `["Rule thiếu keyword bắt buộc sid"]` | ĐẠT |
| `report.rules.9.reasons` | `["Keyword sid không hợp lệ (abc): phải là số nguyên"]` | `["Keyword sid không hợp lệ (abc): phải là số nguyên"]` | ĐẠT |
| `report.rules.10.reasons` | `["Keyword nocase không hợp lệ (None): phải đứng sau một content"]` | `["Keyword nocase không hợp lệ (None): phải đứng sau một content"]` | ĐẠT |
| `report.rules.11.reasons` | `["Keyword content không hợp lệ (\"\|0\|\"): phần hex phải gồm từng cặp chữ số hex"]` | `["Keyword content không hợp lệ (\"\|0\|\"): phần hex phải gồm từng cặp chữ số hex"]` | ĐẠT |
| `report.rules.12.reasons` | `["sid 100201 đã được dùng cho rule khác"]` | `["sid 100201 đã được dùng cho rule khác"]` | ĐẠT |
| `report.rules.13.status` | `"valid"` | `"valid"` | ĐẠT |
| `by_packet.1` | `[100201, 100214]` | `[100201, 100214]` | ĐẠT |

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
