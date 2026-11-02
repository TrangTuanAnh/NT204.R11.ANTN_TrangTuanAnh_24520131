# Kết quả kiểm thử Bài tập 3 - Core Engine

Thư mục này lưu kết quả 14 ca kiểm thử bắt buộc của Bài tập 3 và một ca bổ sung với bộ rule của Snort. Mỗi ca một thư mục gồm gói tin đầu vào, file rule, giá trị mong đợi, kết quả chương trình ghi ra, kết quả đối chiếu và README riêng.

- Gói tin là dữ liệu tổng hợp dựng bằng Scapy rồi lưu ra PCAP, đọc offline, không gửi ra mạng.
- Các giá trị mong đợi được khai báo riêng trong [detection_cases.py](../integration/detection_cases.py), theo đề bài, Snort manual và các quy tắc ghi trong README của module [rules](../../src/rules/README.md) và [detection](../../src/detection/README.md).
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
| [15 Bộ rule Snort (bổ sung)](case15_snort_community_rules/README.md) | Nạp `rules/community.rules`; không dừng chương trình. | 568 rule đều đúng cú pháp nhưng đều có keyword ngoài phạm vi nên đều `unsupported`, không có Detection Event; thoát với mã 0. | ĐẠT (10/10) |

## Chạy lại

Từ thư mục gốc repo:

```powershell
python TEST/integration/run_detection_cases.py --case 07 --overwrite   # một ca
python TEST/integration/run_detection_cases.py --overwrite             # tất cả các ca
python -m pytest TEST/integration/test_detection_cases.py              # đối chiếu, không ghi đè kết quả đã lưu
```

Không có `--overwrite` thì script từ chối ghi đè kết quả đã có. Trường thay đổi giữa các lần chạy là `run_at` trong `result.json`.

[Về README phần kiểm thử](../README.md)
