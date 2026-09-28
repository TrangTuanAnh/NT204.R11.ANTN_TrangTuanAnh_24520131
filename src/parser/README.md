# Parser — Đọc packet và tạo event

Parser là nơi chuyển packet Scapy thành dữ liệu để các module IDS sau sử dụng. Cả live capture lẫn PCAP đều dùng hàm này thông qua `main.py`.

## Các file và cách gọi

- `packet.py`: chứa `parse_packet`, các hàm phân tích giao thức và kiểm tra độ đầy đủ của DNS trên byte gốc.
- `utils.py`: đổi byte thành chuỗi; thay ký tự không giải mã được bằng ký tự thay thế.
- `__init__.py`: xuất lại `parse_packet`.

```python
from src.parser.packet import parse_packet

# packet là đối tượng nhận từ capture.
event = parse_packet(
    packet,
    packet_id=1,
    timestamp=float(packet.time),
    source="pcap",
)
```

`packet_id`, `timestamp` và `source` do bên gọi cung cấp. `source` được chương trình chính đặt là `live` hoặc `pcap`. Các hàm bắt đầu bằng dấu gạch dưới là phần xử lý nội bộ.

## Luồng phân tích

```text
parse_packet
  → tạo khung event
  → _parse_network: đọc IPv4
  → _parse_transport: đọc TCP/UDP
  → kiểm tra IPv4 phân mảnh
  → _parse_application: chọn và gọi parser ứng dụng
  → trả event kèm trạng thái/lỗi
```

Nếu không có IPv4, chương trình trả event ở trạng thái `unknown`. Nếu gặp IPv4 phân mảnh, nó trả `partial` và chưa phân tích ứng dụng. Với lỗi xảy ra trong phần phân tích, thông báo lỗi được lưu vào `errors`.

## Cấu trúc kết quả

| Nhóm trường | Nội dung |
|---|---|
| Thông tin chung | `packet_id`, `timestamp`, `source`, `captured_length` |
| `network` | IP nguồn/đích, phiên bản, TTL, protocol, độ dài, thông tin phân mảnh |
| `transport` | TCP: port, sequence, acknowledgment, flags, window, độ dài payload; UDP: port, length, độ dài payload |
| `application` | Tên giao thức và các trường ứng dụng đã đọc |
| `status`, `errors` | Trạng thái phân tích và danh sách lỗi |

`network` và `transport` là `None` khi chưa đọc được lớp tương ứng. Nếu chưa nhận diện ứng dụng, `application` là `{"protocol": None}`. Khi ghi JSON, `None` thành `null`.

| Trạng thái | Ý nghĩa trong code hiện tại |
|---|---|
| `ok` | Một parser ứng dụng đã trả kết quả; chưa phải bảo đảm dữ liệu hoàn toàn hợp lệ |
| `unknown` | Chưa nhận diện ứng dụng hoặc packet không có IPv4; các trường mạng/transport vẫn có thể đã đọc được |
| `partial` | Phát hiện dữ liệu chưa đầy đủ hoặc thuộc cách đóng gói chưa được xử lý |
| `malformed` | Đầu vào không phải packet Scapy hoặc xảy ra lỗi khi phân tích |

Một packet TCP bắt tay hợp lệ có thể mang trạng thái `unknown` vì không có dữ liệu ứng dụng. Không dùng `status` này để kết luận xâm nhập.

## Các giao thức ứng dụng

- HTTP/1.x: request gồm method, URI, version, headers, body; response gồm version, status code, reason, headers, body. Body hiện được đổi thành chuỗi.
- DNS: transaction ID, query/response, response code, danh sách questions và answers. Query type/answer type được giữ dưới dạng số.
- SMTP: đọc dòng đầu thành command/argument hoặc status code/message. Ví dụ `MAIL FROM:<a@example.test>` được tách thành command `MAIL` và argument `FROM:<a@example.test>`.

## Giới hạn cần hiểu khi dùng

Trên TCP, parser xét dấu hiệu HTTP rồi SMTP trước; nếu chưa nhận diện mới xét nhánh DNS theo port 53. HTTP và lệnh SMTP có thể được nhận diện trên port không chuẩn, kể cả 53. Phản hồi SMTP vẫn cần port 25 hoặc 587 làm tín hiệu bổ trợ. DNS qua UDP/TCP vẫn cần port 53, chưa được nhận diện trên port khác.

DNS được kiểm tra trên byte gốc trước khi đưa cho Scapy đọc: số câu hỏi và bản ghi của cả bốn phần phải có đủ dữ liệu, tên miền và con trỏ nén tên phải hợp lệ. Sau đó danh sách câu hỏi/câu trả lời đọc được phải khớp số lượng khai báo. Nếu thiếu byte, event trả `partial` kèm lỗi, không xuất câu hỏi/câu trả lời mặc định. Cấu trúc không hợp lệ được báo `malformed`.

`_captured_length` được gọi trước khối bắt lỗi phân tích và chỉ bắt TypeError/ValueError. Vì vậy việc cô lập lỗi theo packet chưa bao trùm toàn bộ quá trình tạo event; cần rà thêm các lỗi phát sinh khi Scapy tính độ dài packet.

Parser chưa ghép TCP stream, tái lắp IPv4, giải mã TLS hay HTTP Transfer-Encoding. DNS/TCP chỉ đọc thông điệp đầu tiên; SMTP chỉ đọc dòng đầu. Phát hiện `partial` hiện dựa trên một số kiểm tra độ dài/kết thúc thông điệp, chưa bao phủ mọi kiểu dữ liệu thiếu.

[Quay lại kiến trúc chung](../../README.md)
