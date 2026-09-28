# Kiểm thử live capture trên Wi-Fi

## Mục tiêu

Kiểm tra chương trình mở được network interface thật bằng Npcap, nhận packet ngay trong lúc bắt, đưa packet qua parser chung và ghi event có `source` là `live`.

## Môi trường và thao tác đã chạy

- Interface: `Wi-Fi` - Intel(R) Wi-Fi 6 AX201 160MHz, trạng thái `Up`.
- Npcap service: `Running`.
- Máy thử: `10.0.224.199`; gateway nội bộ: `10.0.0.1`.
- Bắt packet trong 8 giây trên Wi-Fi, đồng thời gửi 2 ping tới gateway bằng `ping.exe -n 2 -w 1000 10.0.0.1`.
- Kết quả ping: gửi 2, nhận 2, mất 0. Lệnh capture kết thúc với mã `0`.

## Kết quả

- Capture nhận 1467 packet trong thời gian chạy, bao gồm traffic nền của máy. `events.jsonl` chỉ giữ lại 4 event ICMP tương ứng với 2 request và 2 reply của ping; các `packet_id` được giữ nguyên từ lần chạy thật nên có khoảng trống. File raw có traffic không liên quan đã không được giữ lại.

Trong các event đã lưu:

- `source` là `live`.
- IPv4 protocol là `1` (ICMP), địa chỉ hai chiều là máy thử và gateway.
- `status` là `unknown`, đúng với phạm vi hiện tại vì parser chưa phân tích ICMP thành protocol ứng dụng.
- Mỗi dòng là JSON hợp lệ.

Kết luận: **ĐẠT - đã bắt packet trên card Wi-Fi thật và ghi event qua live pipeline.**

## Chạy lại

Chạy lệnh đầu trong Terminal 1, rồi chạy ping trong Terminal 2 khi capture còn hoạt động. Dùng tên output mới vì chương trình ghi file theo chế độ append.

Terminal 1:

```powershell
python main.py --interface "Wi-Fi" --timeout 8 --output TEST/integration/live_capture/rerun.jsonl
```

Terminal 2:

```powershell
ping.exe -n 2 -w 1000 10.0.0.1
```

Để thử trên máy khác, thay `Wi-Fi` bằng tên interface từ `python main.py --list-interfaces` và ping gateway phù hợp với mạng đang kết nối. Live capture cần Npcap và quyền bắt packet tương ứng.
