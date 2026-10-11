# Tổng hợp phần kiểm thử

Thư mục này tổng hợp các ca kiểm thử bắt buộc theo yêu cầu của từng task. Các phần test phát sinh ngoài yêu cầu của task sẽ được lưu ở thư mục khác

## Kết quả các ca kiểm thử task 1

- Các PCAP trong bộ này là dữ liệu tổng hợp (dựng bằng Scapy rồi lưu ra PCAP, không phải packet bắt trực tiếp từ card mạng) và được đọc offline
- Script tạo các packet Ethernet/IP/TCP/UDP/DNS/HTTP/SMTP rồi gọi wrpcap() để ghi file; result.json cũng lưu phiên bản Scapy đã dùng.
- Từ Bài tập 2, `main.py` mặc định chạy đủ pipeline; lệnh chạy lại của các ca này có thêm `--parse-only` để cho ra event đúng như lúc tạo kết quả.

| Ca kiểm thử | Nội dung xác nhận | Kết quả quan sát | Đối chiếu |
| --- | --- | --- | --- |
| [TCP handshake](tcp_handshake/README.md) | Nhận diện lần lượt ba cờ TCP `SYN`, `SYN/ACK`, `ACK`. | Có 3 event; cờ lần lượt là `S`, `SA`, `A`. | ĐẠT (23/23) |
| [TCP data](tcp_data/README.md) | Đọc các trường TCP và độ dài payload. | Payload 5 byte (`hello`), flags `PA`; ứng dụng unknown như mong đợi. | ĐẠT (11/11) |
| [UDP](udp/README.md) | Đọc port, UDP length và payload length. | Port `40000 → 9000`, UDP length 13 byte, payload 5 byte. | ĐẠT (11/11) |
| [HTTP GET](http_get/README.md) | Phân tích HTTP request, kể cả khi dùng port không chuẩn. | `GET /index.html`, HTTP/1.1, Host `example.test`, port 8088. | ĐẠT (12/12) |
| [HTTP POST](http_post/README.md) | Phân tích request có body và Content-Length. | `POST /submit`, Content-Length `5`, body `hello`. | ĐẠT (12/12) |
| [HTTP response](http_response/README.md) | Phân tích status code, headers và body của response. | Status `200`, Content-Type `text/plain`, body `OK`. | ĐẠT (12/12) |
| [DNS Query](dns_query/README.md) | Phân tích tên miền và loại truy vấn. | ID `123`, domain `example.test`, query type A (`1`). | ĐẠT (11/11) |
| [DNS Response](dns_response/README.md) | Phân tích response có ít nhất một answer. | ID `123`, có answer A `192.0.2.1`. | ĐẠT (12/12) |
| [SMTP command](smtp_command/README.md) | Phân tích các lệnh HELO, EHLO, MAIL FROM và RCPT TO. | Có 4 event; nhận diện đủ command và argument tương ứng. | ĐẠT (34/34) |
| [SMTP response](smtp_response/README.md) | Phân tích mã phản hồi SMTP. | Response code `250`, message `OK`. | ĐẠT (10/10) |
| [Unknown protocol](unknown_protocol/README.md) | Xử lý IPv4 protocol không được hỗ trợ mà không crash. | Protocol `99`, không có transport/application, status `unknown`. | ĐẠT (10/10) |
| [Malformed packet](malformed_packet/README.md) | Báo packet IPv4 sai header và tiếp tục xử lý packet sau. | Packet đầu `malformed`; packet TCP SYN kế tiếp vẫn được ghi. | ĐẠT (13/13) |

## Kết quả các ca kiểm thử task 2

- Mười bốn ca T01–T14 theo bảng test bắt buộc của Bài tập 2 (Decoder, Preprocessor, Flow/Connection Tracker), thư mục bắt đầu bằng mã ca (`t01_...` đến `t14_...`).
- Ca cần gói tin thật dùng `input.pcap` (gói tổng hợp dựng bằng Scapy, có đủ cờ TCP và số sequence/acknowledgment); ca cần event thiếu hoặc sai trường (T05, T06, T14) dùng `input.jsonl`, mỗi dòng một event.
- Mỗi thư mục có thêm `config.json` (cấu hình đã dùng) và `flows.jsonl` (tổng kết flow). `result.json` lưu từng phép đối chiếu cùng `active_flows_trace` - số flow còn trong bảng sau từng gói, lấy trực tiếp từ Flow Tracker.
- Toàn bộ thư mục được tạo bằng [run_required_cases.py](../run_required_cases.py) từ khai báo trong [cases.py](../cases.py); [test_required_cases.py](../test_required_cases.py) chạy lại các ca này bằng pytest. Cách chạy xem [TEST/README.md](../../README.md).

| Ca kiểm thử | Nội dung xác nhận | Kết quả quan sát | Đối chiếu |
| --- | --- | --- | --- |
| [T01 HTTP URL decode](t01_http_url_decode/README.md) | Giải mã percent-encoding trong URI, tham số và form; URI gốc giữ nguyên. | `%27%20OR%201%3D1` → `' OR 1=1`; `%2527` chỉ thành `%27` (giải mã một lượt); form `pass=a+b%26c` → `a b&c`. | ĐẠT (9/9) |
| [T02 HTML entity](t02_html_entity_decode/README.md) | Đổi thực thể HTML trong nội dung chữ của HTTP, không crash. | `&lt;script&gt;` → `<script>` trong text/html và text/plain; body JSON giữ nguyên. | ĐẠT (9/9) |
| [T03 SMTP Base64/QP](t03_smtp_mime_decode/README.md) | Giải mã thư MIME theo `Content-Transfer-Encoding` và ghi trạng thái giải mã. | Base64 và Quoted-Printable cho đúng chữ tiếng Việt, Subject `=?utf-8?b?...?=` được giải mã, file đính kèm 5 byte; thư Base64 hỏng có `decode_status` là `error`. | ĐẠT (15/15) |
| [T04 Invalid bytes](t04_invalid_character_bytes/README.md) | Byte không hợp lệ với UTF-8/ASCII được đánh dấu, chương trình chạy tiếp. | 4 gói lỗi có `decode_status` `partial` kèm vị trí byte sai; gói GET hợp lệ cuối cùng `ok`. | ĐẠT (14/14) |
| [T05 Normalization](t05_event_normalization/README.md) | Cùng thông tin viết khác kiểu cho ra một cách biểu diễn. | `" tcp "`, `"Tcp"` → `TCP`; `HOST: WWW.Example.TEST.` → `host: www.example.test`; IPv6 viết gọn; timestamp ISO → số giây Unix; `uri_normalized` bỏ `./`, `../`. | ĐẠT (22/22) |
| [T06 Missing field](t06_missing_optional_fields/README.md) | Event thiếu trường không bắt buộc được điền `null`/`[]`/`{}`, không exception. | Bốn event đều được xử lý; trường thiếu được liệt kê trong `reason`; `byte_count` dùng `total_length` khi thiếu `captured_length`. | ĐẠT (27/27) |
| [T07 TCP handshake](t07_tcp_connection_handshake/README.md) | SYN → SYN/ACK → ACK tạo một flow ESTABLISHED. | Trạng thái lần lượt `NEW`, `HANDSHAKE`, `ESTABLISHED`; một flow, `handshake_observed` là `true`. | ĐẠT (13/13) |
| [T08 Bidirectional flow](t08_bidirectional_flow/README.md) | Hai chiều của cùng 5-tuple có cùng `flow_id` và đúng chiều. | 6 gói một `flow_id`; chiều client → server là `forward` dù IP client lớn hơn; forward 4 gói, backward 2 gói. | ĐẠT (17/17) |
| [T09 TCP close](t09_tcp_connection_close/README.md) | FIN/ACK đóng kết nối, RST ngắt kết nối. | Kết nối 1: `CLOSING` → `CLOSED` (`tcp_closed`); kết nối 2: `RESET` (`tcp_reset`); bảng flow rỗng sau gói cuối. | ĐẠT (19/19) |
| [T10 UDP query/response](t10_udp_dns_flow/README.md) | DNS qua UDP hai chiều thành một flow, đếm đúng gói và byte. | 1 flow UDP: 2 gói, 184 byte (forward 76, backward 108); `state` và bộ đếm cờ TCP là `null`. | ĐẠT (18/18) |
| [T11 Concurrent flows](t11_concurrent_flows/README.md) | Nhiều phiên xen kẽ không bị gộp nhầm. | 4 flow riêng: khác port, khác IP, và TCP/UDP cùng IP/port; mỗi flow TCP 3 gói, flow UDP 2 gói. | ĐẠT (17/17) |
| [T12 Idle timeout](t12_flow_idle_timeout/README.md) | Flow quá thời gian chờ bị đóng và xóa khỏi bảng. | Flow UDP im lặng 7,9 giây bị đóng (`idle_timeout`), gói mới cùng 5-tuple mở flow mới; số flow trong bảng `[1, 1, 2, 2, 2, 3, 3, 3, 1]`. | ĐẠT (16/16) |
| [T13 Statistics](t13_flow_statistics/README.md) | Đếm gói, byte, cờ và duration của một phiên đầy đủ. | 10 gói, 767 byte (forward 6 gói/479 byte, backward 4 gói/288 byte); SYN 2, ACK 9, FIN 2, RST 0; duration 0,32 giây; `CLOSED`. | ĐẠT (21/21) |
| [T14 Malformed event](t14_malformed_event/README.md) | Event hỏng hoặc chưa hỗ trợ không làm dừng chương trình, có trạng thái và lý do phù hợp. | 12 dòng đều có event: dữ liệu sai `invalid`/`skip`, ICMP và SCTP `partial`/`skip`, mỗi event có `reason`; dòng hợp lệ cuối vẫn vào đúng flow. | ĐẠT (29/29) |
