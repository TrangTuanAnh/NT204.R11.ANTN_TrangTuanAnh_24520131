# Capture - Nhận dữ liệu đầu vào

Capture cung cấp dữ liệu đầu vào cho `main.py`: packet Scapy kèm timestamp (từ card mạng hoặc file PCAP), hoặc event đã lưu sẵn trong file JSON Lines. Module này chỉ phụ trách nhận dữ liệu; việc phân tích, giải mã, theo dõi flow và ghi kết quả do các module khác thực hiện.

## Các file và giao diện

| File | Hàm | Vai trò |
| --- | --- | --- |
| `interfaces.py` | `list_interfaces()` | Trả danh sách tên interface Scapy nhìn thấy |
| `live.py` | `capture_live(interface, process_packet, count=0, timeout=None, *, on_idle=None, idle_interval=1.0)` | Gọi hàm xử lý cho mỗi packet bắt được; nếu có `on_idle` thì gọi thêm hàm này định kỳ |
| `pcap.py` | `iter_pcap(path)` | Trả lần lượt các cặp `(packet, timestamp)` |
| `events.py` | `iter_events(path, max_line_bytes)` | Trả lần lượt từng event trong file JSON Lines |
| `__init__.py` | Xuất lại ba hàm `list_interfaces`, `capture_live`, `iter_pcap` | Cho phép import qua package |

```python
from src.capture.events import iter_events
from src.capture.interfaces import list_interfaces
from src.capture.live import capture_live
from src.capture.pcap import iter_pcap
```

## Live capture hoạt động thế nào?

1. Kiểm tra interface có trong danh sách.
2. Bắt gói với `store=False` (không giữ gói trong bộ nhớ).
3. Mỗi khi nhận packet, gọi `process_packet(packet, float(packet.time))`.

Hàm `process_packet` được truyền từ `main.py`; tại đó packet được đưa qua các bước xử lý rồi ghi ra file. Callback chạy ngay trong luồng capture, nên thời gian xử lý mỗi packet ảnh hưởng tới tốc độ nhận packet.

Có hai cách bắt gói:

- **Không truyền `on_idle`** (chế độ `--parse-only` của Bài tập 1): gọi Scapy `sniff` như trước.
- **Có `on_idle`** (chế độ đầy đủ): việc bắt gói chạy ở một luồng riêng bằng `AsyncSniffer`, còn luồng chính cứ mỗi `idle_interval` giây lại gọi `on_idle`, kể cả khi card mạng không nhận thêm gói nào. `main.py` dùng hàm này để đóng các flow đã hết hạn lúc mạng im lặng. Lỗi xảy ra trong luồng bắt gói (mở card thất bại) hoặc khi xử lý một gói (ghi file thất bại) làm dừng việc bắt gói và được báo lại ở luồng chính; Ctrl+C cũng tắt luồng bắt gói trước khi thoát.

Trên Windows cần Npcap và quyền bắt gói phù hợp. `count=0` nghĩa là không giới hạn số packet; `timeout=None` nghĩa là không đặt giới hạn thời gian.

`--list-interfaces` có thể in GUID của card Windows. `live.py` tìm card tương ứng trong danh sách Scapy và dùng tên thiết bị để mở Npcap; vì vậy có thể truyền GUID được liệt kê hoặc tên card như `Wi-Fi`.

## PCAP được đọc thế nào?

`iter_pcap` mở file, đọc header của từng record, kiểm tra độ dài rồi nhờ Scapy đọc packet. Nó trả từng packet cùng timestamp có sẵn trong file; không nạp cả PCAP vào danh sách.

`main.py` duyệt các cặp trả về và gọi đúng hàm `process_packet` dùng cho live capture.

Phân biệt hai tình huống:

- Record còn nguyên nhưng packet được lưu thiếu một phần: parser có thể đọc các trường còn lại và đánh dấu `partial`.
- File bị cắt giữa header hoặc dữ liệu record: module báo lỗi và dừng đọc. Các event đã ghi trước đó vẫn còn trong file đầu ra; ở chế độ đầy đủ, các flow còn mở cũng được ghi ra với lý do `source_error`.

Hiện hỗ trợ PCAP, chưa hỗ trợ PCAPNG. Module phụ thuộc một số thuộc tính reader của Scapy như `f`, `endian` và `snaplen`.

## Đọc event từ file JSON Lines

`iter_events` là nguồn vào thứ ba (`--events`): mỗi dòng của file là một event có cùng cấu trúc với event của parser. Nguồn này dùng để chạy Decoder, Preprocessor và Flow Tracker trên event có sẵn, ví dụ event thiếu trường hoặc viết sai cố ý để kiểm thử.

- Dòng trống được bỏ qua; ký tự BOM ở đầu file (do một số trình soạn thảo trên Windows thêm vào) được bỏ.
- Dòng hỏng không làm dừng việc đọc. Dòng không phải JSON, không phải JSON object, sai UTF-8 hoặc dài hơn `max_event_bytes` byte được đổi thành một event có `status` là `malformed` và `errors` ghi số dòng, ví dụ `Dòng 2 không phải JSON hợp lệ (...)`. Preprocessor sẽ đánh dấu event này `invalid` rồi chương trình đọc tiếp dòng sau.
- Giá trị `NaN`/`Infinity` (không hợp lệ trong JSON chuẩn) được giữ dưới dạng chữ để Preprocessor báo là sai.

[Quay lại kiến trúc chung](../../README.md)
