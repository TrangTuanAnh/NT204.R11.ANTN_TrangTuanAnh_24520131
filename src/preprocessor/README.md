# Preprocessor - Kiểm tra và chuẩn hóa event

Preprocessor nhận event đã qua [decoder](../decoder/README.md), kiểm tra các trường có hợp lệ không, đưa dữ liệu về một cách viết thống nhất và quyết định event có được đưa vào [Flow Tracker](../flow/README.md) hay không. Nhờ vậy các module phía sau luôn nhận cùng một dạng dữ liệu, dù event đến từ card mạng, file PCAP hay file event viết tay.

## Các file và cách gọi

| File | Nội dung |
| --- | --- |
| `event.py` | `preprocess_event(event, config)`: kiểm tra từng phần của event theo thứ tự, gắn trạng thái và lý do |
| `checks.py` | `CheckReport` (sổ ghi vấn đề) và các hàm kiểm tra một trường: số nguyên trong khoảng, IP, cờ TCP, true/false |
| `normalize.py` | Các phép chuẩn hóa: thời gian, IP, tên miền, header Host, URI, khung trường của từng giao thức ứng dụng |

```python
from src.config import Config
from src.preprocessor import preprocess_event

preprocess_event(event, Config())
print(event["preprocess_status"], event["processing_action"], event["reason"])
```

## Các bước kiểm tra

1. **Trường ghi chú:** `packet_id`, `source`, `errors`, `captured_length`.
2. **Thời gian** (`timestamp`): trường bắt buộc, đổi về số giây Unix.
3. **Lớp IP** (`network`): địa chỉ nguồn/đích là bắt buộc; các trường số phải đúng khoảng; IPv4 phân mảnh được đánh dấu chưa hỗ trợ.
4. **Lớp TCP/UDP** (`transport`): tên giao thức và hai port là bắt buộc; giao thức khác TCP/UDP được giữ lại nhưng đánh dấu chưa hỗ trợ.
5. **Phần ứng dụng** (`application`): chuẩn hóa và điền đủ khung trường của giao thức.
6. **Kết luận của parser** (`status`): parser báo `partial`/`malformed` thì event cũng chỉ là `partial`.
7. Xếp các trường theo thứ tự cố định, rồi thêm `preprocess_status`, `processing_action`, `reason`.

## Kết luận sau kiểm tra

| Trường hợp | `preprocess_status` | `processing_action` |
| --- | --- | --- |
| Thiếu hoặc sai trường bắt buộc (`timestamp`, `src_ip`, `dst_ip`, `transport.protocol`, `src_port`, `dst_port`); trường số của lớp IP/TCP/UDP sai kiểu hoặc ngoài khoảng; `network`/`transport` không phải object; event bị đánh dấu `malformed` mà không có lớp IP | `invalid` | `skip` (hoặc `drop`) |
| Dữ liệu đúng nhưng chưa hỗ trợ: không có lớp IP (ARP...), giao thức khác TCP/UDP (ICMP, SCTP...), gói IPv4 phân mảnh | `partial` | `skip` (hoặc `drop`) |
| Dùng được nhưng chưa đầy đủ: thiếu trường không bắt buộc, parser báo `partial`/`malformed` nhưng vẫn đọc được IP và TCP/UDP, phần ứng dụng sai cấu trúc, giao thức ứng dụng chưa hỗ trợ, trường ghi chú sai kiểu | `partial` | `process` |
| Đủ và đúng | `valid` | `process` |

- `process`: đưa vào Flow Tracker.
- `skip`: vẫn ghi event ra file (kèm lý do) nhưng không theo dõi flow.
- `drop`: bỏ hẳn event, không ghi ra file. Chỉ xảy ra khi bật `drop_invalid_events` (cho event `invalid`) hoặc `drop_unsupported_events` (cho dữ liệu chưa hỗ trợ) trong [cấu hình](../../README.md#cấu-hình).

`reason` là danh sách lý do theo thứ tự nặng đến nhẹ; event `valid` có `reason` là `[]`. Ví dụ: `["transport.src_port không hợp lệ: -1"]`, `["Giao thức IP số 1 chưa được hỗ trợ (chỉ theo dõi TCP/UDP)"]`.

Phần ứng dụng không dùng để ghép flow, nên lỗi ở phần này chỉ làm event `partial` và gói vẫn được đếm vào flow. Tương tự, gói mà parser báo `malformed` (ví dụ DNS hỏng) nhưng vẫn có IP/port hợp lệ vẫn được đếm, để lưu lượng bất thường không bị "biến mất" khỏi thống kê.

## Chuẩn hóa

| Dữ liệu | Cách chuẩn hóa | Ví dụ |
| --- | --- | --- |
| Tên giao thức | Viết hoa, bỏ khoảng trắng | `" tcp "` → `"TCP"`, `"http"` → `"HTTP"` |
| Cờ TCP | Viết hoa, xếp theo thứ tự cố định | `"af"` → `"FA"` |
| Địa chỉ IP | Cách viết chuẩn | `"2001:DB8:0:0::A"` → `"2001:db8::a"` |
| Tên miền (DNS, header Host) | Viết thường, bỏ dấu chấm cuối; Host giữ port | `"WWW.Example.TEST.:8080"` → `"www.example.test:8080"` |
| Tên header HTTP/SMTP | Viết thường, bỏ khoảng trắng thừa ở giá trị; header trùng tên được nối bằng dấu phẩy | `"User-AGENT"` → `"user-agent"` |
| Thời gian | Số giây Unix; nhận số, chuỗi số hoặc chuỗi ISO 8601 có múi giờ | `"2026-10-02T07:00:00+07:00"` → `1790899200.0` |
| URI | Giữ nguyên `uri` gốc; thêm `uri_normalized` | `/a/./b/../c%7e` → `/a/c~` |

`uri_normalized` chỉ chuẩn hóa ở **mức an toàn** (không làm đổi ý nghĩa URI): viết hoa phần hex sau `%`, giải mã các ký tự vốn không cần mã hóa (`%41` → `A`, `%7E` → `~`, `%2E` → `.`), bỏ đoạn `.` và `..` trong đường dẫn (không lùi quá thư mục gốc), viết thường phần `http://Host` của URI dạng đầy đủ. Các ký tự đặc biệt như `%2F` (dấu `/`) hay `%3F` (dấu `?`) giữ nguyên; `//` cũng giữ nguyên.

## Dữ liệu thiếu

- Trường bắt buộc thiếu → `invalid`.
- Trường thông tin gói không bắt buộc bị thiếu hẳn (ví dụ `captured_length`, `network.ttl`, `transport.window`) → điền `null`, event `partial`, `reason` liệt kê các trường đã điền. Trường đã ghi rõ `null` được coi là "không có giá trị", không bị báo thiếu.
- Trường ghi chú thiếu (`packet_id`, `source`, `status`) → `null`; `errors` thiếu → `[]`.
- Phần ứng dụng được điền đủ khung trường của giao thức: giá trị đơn thiếu là `null`, danh sách thiếu là `[]`, header thiếu là `{}`. Ví dụ event HTTP luôn có `message_type`, `method`, `uri`, `uri_normalized`, `version`, `status_code`, `reason`, `headers`, `body`; event DNS luôn có `questions` và `answers`.
- Giá trị sai kiểu được đổi về `null` sau khi ghi lý do, nên các module phía sau không gặp dữ liệu sai kiểu.

Lưu ý: `application.reason` của HTTP response là câu trạng thái do server gửi (ví dụ `OK`), khác với `reason` ở cấp event do Preprocessor thêm.

## Giới hạn hiện tại

- Không kiểm tra checksum hay tính hợp lệ sâu của nội dung ứng dụng.
- Parser hiện chỉ đọc IPv4; event IPv6 chỉ đến từ file event (`--events`), Preprocessor vẫn kiểm tra và chuẩn hóa được.
- Thời gian dạng chuỗi ISO phải có múi giờ; số giây không được đoán đơn vị (giây hay mili giây).

[Quay lại kiến trúc chung](../../README.md)
