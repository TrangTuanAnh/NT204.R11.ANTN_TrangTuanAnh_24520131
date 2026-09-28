# Malformed packet

**Yêu cầu:** Packet không hợp lệ không làm chương trình crash.

## Dữ liệu đầu vào

Packet IPv4 có IHL=4 (sai), sau đó là TCP SYN hợp lệ. Dữ liệu được tạo tổng hợp; lệnh kiểm thử đọc PCAP offline, không gửi packet ra mạng.

## Cách chạy lại

Từ thư mục gốc repo:

```powershell
python main.py --pcap TEST/integration/required_cases/malformed_packet/input.pcap --output TEST/integration/required_cases/malformed_packet/rerun.jsonl
```

File đầu ra được ghi nối tiếp. Dùng tên `rerun.jsonl` mới cho mỗi lần chạy lại để không trộn kết quả cũ.

## Kết quả đã chạy

- Kết luận: **ĐẠT**.
- Mã thoát CLI: `0`; số event: `2`; đối chiếu đạt: `13/13`.
- Ý nghĩa: Packet đầu phải mang status malformed và có lỗi; packet sau vẫn được ghi, chứng tỏ lỗi đầu không chặn pipeline.

Quan sát trong `events.jsonl`:

- Packet 1: `status` = `"malformed"`, `errors_nonempty` = `true`
- Packet 2: `transport.protocol` = `"TCP"`, `transport.flags` = `"S"`, `status` = `"unknown"`

Đối chiếu sai:

Không có trường nào sai so với giá trị mong đợi.

## Artifact

- `input.pcap`: packet đầu vào.
- `expected.json`: các trường phải có theo yêu cầu.
- `events.jsonl`: từng event do chương trình tạo ra.
- `result.json`: mã thoát, từng giá trị thực tế và kết luận đối chiếu.
