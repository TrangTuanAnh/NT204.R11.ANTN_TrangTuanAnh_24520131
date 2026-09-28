# Capture - Nhận packet đầu vào

Capture cung cấp packet Scapy và timestamp cho `main.py`. Module này chỉ phụ trách nhận dữ liệu; việc phân tích và ghi event do các module khác thực hiện.

## Các file và giao diện

| File | Hàm | Vai trò |
| --- | --- | --- |
| `interfaces.py` | `list_interfaces()` | Trả danh sách tên interface Scapy nhìn thấy |
| `live.py` | `capture_live(interface, process_packet, count=0, timeout=None)` | Gọi hàm xử lý cho mỗi packet bắt được |
| `pcap.py` | `iter_pcap(path)` | Trả lần lượt các cặp `(packet, timestamp)` |
| `__init__.py` | Xuất lại ba hàm trên | Cho phép import qua package |

```python
from src.capture.interfaces import list_interfaces
from src.capture.live import capture_live
from src.capture.pcap import iter_pcap
```

## Live capture hoạt động thế nào?

1. Kiểm tra interface có trong danh sách.
2. Gọi Scapy `sniff` với `store=False`.
3. Mỗi khi nhận packet, gọi `process_packet(packet, float(packet.time))`.

Hàm `process_packet` được truyền từ `main.py`; tại đó packet được đưa vào parser chung rồi ghi ra file. Callback chạy ngay trong luồng capture, nên việc phân tích và ghi file ảnh hưởng thời gian xử lý từng packet.

Trên Windows cần Npcap và quyền bắt gói phù hợp. `count=0` nghĩa là không giới hạn số packet; `timeout=None` nghĩa là không đặt giới hạn thời gian.

`--list-interfaces` có thể in GUID của card Windows. `live.py` tìm card tương ứng trong danh sách Scapy và dùng tên thiết bị để mở Npcap; vì vậy có thể truyền GUID được liệt kê hoặc tên card như `Wi-Fi`.

## PCAP được đọc thế nào?

`iter_pcap` mở file, đọc header của từng record, kiểm tra độ dài rồi nhờ Scapy đọc packet. Nó trả từng packet cùng timestamp có sẵn trong file; không nạp cả PCAP vào danh sách.

`main.py` duyệt các cặp trả về và gọi đúng hàm `process_packet` dùng cho live capture.

Phân biệt hai tình huống:

- Record còn nguyên nhưng packet được lưu thiếu một phần: parser có thể đọc các trường còn lại và đánh dấu `partial`.
- File bị cắt giữa header hoặc dữ liệu record: module báo lỗi và dừng đọc. Các event đã ghi trước đó vẫn còn trong file đầu ra.

Hiện hỗ trợ PCAP, chưa hỗ trợ PCAPNG. Module phụ thuộc một số thuộc tính reader của Scapy như `f`, `endian` và `snaplen`.

[Quay lại kiến trúc chung](../../README.md)
