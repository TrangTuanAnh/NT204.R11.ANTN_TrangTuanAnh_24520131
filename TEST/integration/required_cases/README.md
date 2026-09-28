# Tổng hợp phần kiểm thử

Thư mục này tổng hợp các ca kiểm thử bắt buộc theo yêu cầu của từng task. Các phần test phát sinh ngoài yêu cầu của task sẽ được lưu ở thư mục khác

## Kết quả các ca kiểm thử task 1

- Các PCAP trong bộ này là dữ liệu tổng hợp (dựng bằng Scapy rồi lưu ra PCAP, không phải packet bắt trực tiếp từ card mạng) và được đọc offline
- Script tạo các packet Ethernet/IP/TCP/UDP/DNS/HTTP/SMTP rồi gọi wrpcap() để ghi file; result.json cũng lưu phiên bản Scapy đã dùng.

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
