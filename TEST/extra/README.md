# Kiểm thử mở rộng

Thư mục này chứa các kiểm thử **ngoài danh sách ca bắt buộc của đề**. Kết quả các ca bắt buộc nằm riêng trong [BT1](../BT1/README.md), [BT2](../BT2/README.md) và [BT3](../BT3/README.md).

| Thư mục | Nội dung | Thuộc bài |
| --- | --- | --- |
| [live_capture](live_capture/README.md) | Bắt gói thật trên card Wi-Fi qua Npcap, ghi event có `source` là `live`. Cần máy có card mạng, chạy tay, không nằm trong pytest. | 1 |
| [snort_community_rules](snort_community_rules/README.md) | Nạp nguyên bộ rule cộng đồng của Snort (`rules/community.rules`) để kiểm tra chương trình không dừng khi gặp rule ngoài phạm vi. Ca bổ sung **B1** của Bài tập 3. | 3 |
| [modules](modules) | Kiểm thử pytest từng module, mỗi thư mục con ứng với một thư mục trong `src/`. | 1, 2, 3 |

## Ca bổ sung B1 - bộ rule cộng đồng của Snort

| Ca kiểm thử | Nội dung xác nhận | Kết quả quan sát | Đối chiếu |
| --- | --- | --- | --- |
| [B1 Bộ rule Snort](snort_community_rules/README.md) | Nạp `rules/community.rules`; không dừng chương trình. | 568 rule đều đúng cú pháp nhưng đều có keyword ngoài phạm vi nên đều `unsupported`, không có Detection Event; thoát với mã 0. | ĐẠT (10/10) |

Thư mục ca có cùng các file như ca bắt buộc của Bài tập 3 và được tạo bằng cùng script `python TEST/BT3/run_cases.py --case B1 --overwrite`; khai báo ca nằm trong [BT3/cases.py](../BT3/cases.py), bài kiểm thử tự động là [BT3/test_bt3_cases.py](../BT3/test_bt3_cases.py).

## Kiểm thử từng module

Các bài kiểm thử đọc dữ liệu tổng hợp trong bộ nhớ hoặc PCAP/event tổng hợp, dùng bộ bắt gói giả, nên **không cần card mạng và không gửi gói nào ra mạng**. Dữ liệu mẫu dùng chung (hàm tạo event giống kết quả của parser) nằm trong [conftest.py](../conftest.py).

| Thư mục | Kiểm tra | Số test |
| --- | --- | --- |
| [modules/capture](modules/capture) | Đọc file event JSON Lines; bắt live có kiểm tra flow hết hạn định kỳ (bộ bắt gói giả) | 9 |
| [modules/parser](modules/parser) | Phần parser bổ sung: payload, byte đệm Ethernet, nội dung thư SMTP | 7 |
| [modules/decoder](modules/decoder) | URI/form, thực thể HTML, MIME, bảng mã, giới hạn kích thước | 35 |
| [modules/preprocessor](modules/preprocessor) | Kiểm tra trường, chuẩn hóa, dữ liệu thiếu/chưa hỗ trợ, chính sách bỏ event | 71 |
| [modules/flow](modules/flow) | Flow hai chiều, trạng thái TCP, thời gian chờ, thống kê, thông tin flow cho so khớp rule | 29 |
| [modules/rules](modules/rules) | Đọc file rule, phân loại valid/invalid/unsupported, chỉ mục, báo cáo nạp rule | 172 |
| [modules/detection](modules/detection) | So khớp header, flow, flags, dsize, content; đánh giá nhiều rule; Detection Event | 114 |
| [modules/pipeline](modules/pipeline) | Nối các bước, cô lập lỗi, chương trình chính `main.py`, cấu hình | 52 |

```powershell
python -m pytest TEST/extra                  # toàn bộ phần mở rộng
python -m pytest TEST/extra/modules/flow     # riêng một module
```

[Về README phần kiểm thử](../README.md)
