# TCP handshake

**Yêu cầu của đề:** Nhận diện SYN, SYN/ACK, ACK.

## Dữ liệu đầu vào

Ba packet TCP theo thứ tự SYN, SYN/ACK, ACK. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/tcp_handshake/input.pcap --output TEST/integration/required_cases/tcp_handshake/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `3`; đối chiếu đạt: `23/23`.
- Ý nghĩa: Cả ba cờ TCP phải đúng thứ tự. Trạng thái ứng dụng unknown là bình thường vì packet bắt tay không có payload ứng dụng.

Quan sát trong `events.jsonl`:

- Packet 1: `transport.protocol` = `"TCP"`, `transport.flags` = `"S"`, `transport.src_port` = `50000`, `status` = `"unknown"`
- Packet 2: `transport.protocol` = `"TCP"`, `transport.flags` = `"SA"`, `transport.src_port` = `80`, `status` = `"unknown"`
- Packet 3: `transport.protocol` = `"TCP"`, `transport.flags` = `"A"`, `transport.src_port` = `50000`, `status` = `"unknown"`

Đối chiếu sai:

Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
