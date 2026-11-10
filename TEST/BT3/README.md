# Kết quả kiểm thử Bài tập 3 - Core Engine

Thư mục này lưu kết quả 14 ca kiểm thử bắt buộc của Bài tập 3. Ca bổ sung chạy với bộ rule của Snort nằm ở phần mở rộng: [extra/snort_community_rules](../extra/snort_community_rules/README.md). Mỗi ca một thư mục gồm gói tin đầu vào, file rule, giá trị mong đợi, kết quả chương trình ghi ra, kết quả đối chiếu và README riêng.

- Gói tin là dữ liệu tổng hợp dựng bằng Scapy rồi lưu ra PCAP, đọc offline, không gửi ra mạng.
- Các giá trị mong đợi được khai báo riêng trong [cases.py](cases.py), theo đề bài, Snort manual và các quy tắc ghi trong README của module [rules](../../src/rules/README.md) và [detection](../../src/detection/README.md).
- `candidates` lấy trực tiếp từ Repository. Các số `rejected`, `content_checks`, `candidate_rules` nằm trong mục `engine` của `rule_report.json`.

| Ca | Nội dung xác nhận | Kết quả quan sát | Đối chiếu |
| --- | --- | --- | --- |
| [01 Nạp file rule](case01_rule_loading/README.md) | Chỉ rule được đưa sang parser; bật/tắt rule và file bằng cấu hình. | 3 dòng comment và 2 dòng trống bị bỏ; rule viết trên hai dòng được ghép; rule tắt bằng sid và cả file bị tắt không được dùng. | ĐẠT (21/21) |
| [02 Rule sai cú pháp](case02_syntax_errors/README.md) | Rule sai có status `invalid` và lý do; engine chạy tiếp. | 12 rule sai, mỗi rule có lý do riêng; rule hợp lệ đứng sau vẫn được nạp và vẫn khớp. | ĐẠT (22/22) |
| [03 Keyword ngoài phạm vi](case03_out_of_scope_keywords/README.md) | Rule có keyword ngoài phạm vi là `unsupported`; không crash. | `pcre`, `byte_test`, `http_uri`, `metadata`, `drop`, `icmp`, `flow:from_client` đều bị bỏ dù gói có chuỗi cần tìm. | ĐẠT (17/17) |
| [04 Parse header](case04_header_object/README.md) | Internal Rule Object đúng với any, IP đơn, CIDR, port đơn, khoảng port. | `10.0.0.5` → `10.0.0.5/32`; `:1023` → `[0, 1023]`; `1024:` → `[1024, 65535]`. | ĐẠT (23/23) |
| [05 Direction](case05_direction/README.md) | `->` một chiều, `<>` hai chiều. | Rule `->` khớp 1 gói; rule `<>` khớp 2 gói và ghi `reversed_direction`; gói của client khác không khớp. | ĐẠT (12/12) |
| [06 Indexer](case06_indexer/README.md) | Chọn đúng rule theo IP, TCP, UDP và any. | Đúng tập rule cho cả 8 gói, gói ICMP chỉ có rule `ip`; 20 lượt xét thay vì 64. | ĐẠT (13/13) |
| [07 Header không khớp](case07_header_mismatch/README.md) | Rule bị loại trước bước tìm content. | 2 rule bị chỉ mục loại, 2 rule bị loại ở bước header; `content_checks` là 1 dù cả 5 rule đều có chuỗi khớp. | ĐẠT (10/10) |
| [08 flow](case08_flow/README.md) | `flow:to_server,established` khớp theo Flow Tracker. | Gói SYN có chuỗi cần tìm không khớp; request khớp `to_server`; response khớp `to_client`; gói FIN kèm dữ liệu vẫn là `established`. | ĐẠT (16/16) |
| [09 nocase](case09_nocase/README.md) | Có và không có `nocase`. | `admin` không có `nocase` không khớp `/ADMIN`; có `nocase` thì khớp ở byte 5; viết bằng hex cho cùng kết quả. | ĐẠT (8/8) |
| [10 offset/depth](case10_offset_depth/README.md) | Chỉ khớp trong vùng được chỉ định. | 2 rule khớp; 4 rule không khớp vì vùng tìm không chứa trọn chuỗi. | ĐẠT (7/7) |
| [11 distance/within](case11_distance_within/README.md) | Tìm tương đối giữa hai content. | 4 rule khớp, gồm trường hợp phải thử chỗ xuất hiện tiếp theo và `distance` âm; 2 rule không khớp. | ĐẠT (12/12) |
| [12 flags và dsize](case12_flags_dsize/README.md) | Khớp và không khớp theo event. | Đúng với mọi dạng `flags` (`+`, `*`, `!`, `0`, cờ bỏ qua) và `dsize` (bằng, `>`, `<`, khoảng tính cả hai đầu). | ĐẠT (11/11) |
| [13 Nhiều rule](case13_several_rules/README.md) | Một event khớp từ 2 rule trở lên. | Gói GET sinh đủ 4 Detection Event; rule không khớp không sinh kết quả. | ĐẠT (12/12) |
| [14 Detection Event](case14_detection_event/README.md) | Có đủ sid, msg, flow, 5-tuple, protocol, thông tin khớp. | Đủ mọi trường; `../` ở byte 5; bản mã hóa `..%2f` được phát hiện trong vùng `application`. | ĐẠT (22/22) |

## Chạy lại

Từ thư mục gốc repo:

```powershell
python TEST/BT3/run_cases.py --case 07 --overwrite   # một ca
python TEST/BT3/run_cases.py --overwrite             # tất cả các ca (cả ca bổ sung trong TEST/extra)
python -m pytest TEST/BT3                            # đối chiếu, không ghi đè kết quả đã lưu
```

Không có `--overwrite` thì script từ chối ghi đè kết quả đã có. Trường thay đổi giữa các lần chạy là `run_at` trong `result.json`.

## Chạy thử bằng `main.py`

Mỗi ca có sẵn lệnh chạy trong README của ca. Ba ví dụ dưới đây là ba tình huống chính: phát hiện được tấn công, rule sai không làm dừng chương trình, và nạp bộ rule Snort thật. Chạy tại thư mục gốc repo.

Chương trình **ghi nối tiếp** vào file kết quả, nên chạy lại cùng tên file sẽ làm các dòng bị lặp. Xóa kết quả cũ trước khi chạy lại: `Remove-Item output\demo_* -ErrorAction SilentlyContinue`.

### Phát hiện Directory traversal ([ca 14](case14_detection_event/README.md))

```powershell
python main.py --pcap TEST/BT3/case14_detection_event/input.pcap --rules TEST/BT3/case14_detection_event/input.rules --output output/demo_events.jsonl --flow-output output/demo_flows.jsonl --detection-output output/demo_detections.jsonl --rule-report output/demo_rule_report.json
Get-Content output/demo_detections.jsonl | ForEach-Object { ($_ | ConvertFrom-Json) | Select-Object packet_id, sid, msg, src_ip, dst_ip, flow_id }
```

- Màn hình in `Nap rule: 1 hop le, 0 sai cu phap, 0 ngoai pham vi (da bo), 0 bi tat`.
- Có 2 Detection Event của rule `100001` ("Directory traversal detected"), ở gói 4 và gói 5, cùng luồng `10.0.0.5:52133 → 192.168.1.20:80` (TCP, HTTP) và cùng `flow_id`.
- Gói 4 khớp `../` ở byte 5 của payload thô (`buffer` là `payload`). Gói 5 viết `..%2f` nên không có `../` trong byte gốc, nhưng vẫn khớp nhờ URI đã giải mã (`buffer` là `application`).
- Cả hai gói có `flow_state` là `ESTABLISHED`, đúng với `flow:to_server,established` của rule.

### Rule sai cú pháp không làm dừng chương trình ([ca 02](case02_syntax_errors/README.md))

```powershell
python main.py --pcap TEST/BT3/case02_syntax_errors/input.pcap --rules TEST/BT3/case02_syntax_errors/input.rules --config TEST/BT3/case02_syntax_errors/config.json --output output/demo_e2.jsonl --flow-output output/demo_f2.jsonl --detection-output output/demo_d2.jsonl --rule-report output/demo_r2.json
```

- Màn hình in `2 hop le, 12 sai cu phap`, tiếp theo là 12 dòng `Canh bao` có số dòng, `sid` và lý do cụ thể, ví dụ `Chiều phải là -> hoặc <>, đang là '=>'`.
- Chương trình thoát với mã `0`; hai rule hợp lệ (đứng đầu và cuối file) vẫn được nạp và vẫn khớp gói tin.

### Bộ rule cộng đồng của Snort ([ca bổ sung B1](../extra/snort_community_rules/README.md))

```powershell
python main.py --pcap TEST/extra/snort_community_rules/input.pcap --rules rules/community.rules --output output/demo_e3.jsonl --flow-output output/demo_f3.jsonl --detection-output output/demo_d3.jsonl --rule-report output/demo_r3.json
```

- Màn hình in `0 hop le, 0 sai cu phap, 568 ngoai pham vi (da bo)`, kèm cảnh báo từng rule và các keyword làm rule bị bỏ (`fast_pattern`, `http_uri`, `pcre`, `flowbits`, `metadata`, `reference`).
- Chương trình thoát với mã `0` và `output/demo_d3.jsonl` rỗng: cả 568 rule đang bật đều có keyword ngoài phạm vi đề bài nên không rule nào được dùng. Đây là hạn chế đã nêu ở [README chính](../../README.md#6-giới-hạn-hiện-tại).

[Về README phần kiểm thử](../README.md)
