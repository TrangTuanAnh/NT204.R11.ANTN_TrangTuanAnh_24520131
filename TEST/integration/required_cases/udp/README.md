# UDP

**Yêu cầu:** Phân tích UDP packet.

## Dữ liệu đầu vào

Một UDP datagram từ port `40000` tới port `9000`, mang 5 byte 'hello'. Dữ liệu được tạo tổng hợp; **lệnh kiểm thử đọc PCAP offline**, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/udp/input.pcap --output TEST/integration/required_cases/udp/rerun.jsonl
```

> File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `1`; đối chiếu đạt: `11/11`.
- Ý nghĩa: UDP length bằng 8 byte header cộng 5 byte payload; ứng dụng chưa nhận diện được là expected.

Quan sát trong `events.jsonl`:

- Packet 1: `transport.protocol` = `"UDP"`, `transport.src_port` = `40000`, `transport.dst_port` = `9000`, `transport.length` = `13`, `transport.payload_length` = `5`, `status` = `"unknown"`

Đối chiếu sai:

> Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
