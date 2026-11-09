# Bộ traffic lớn

Các ca bắt buộc trong [BT1](../../BT1/README.md), [BT2](../../BT2/README.md), [BT3](../../BT3/README.md) mỗi ca chỉ có vài gói để tách riêng từng yêu cầu của đề. Thư mục này bổ sung hai bộ traffic tổng hợp **khoảng 2.000 gói mỗi bộ**, trong đó nhiều phiên giao tiếp xen kẽ nhau theo thời gian, để kiểm tra chương trình khi có khối lượng thật: nhiều flow cùng tồn tại, nhiều giao thức, flow hết hạn giữa chừng, và rule khớp trên nhiều gói.

| Bộ traffic | Nội dung | Gói | Flow | Detection Event | Đối chiếu |
| --- | --- | --- | --- | --- | --- |
| [office_day](office_day/README.md) | Một ngày làm việc: web, thư SMTP, DNS, SSH, luồng UDP của nhiều máy, kèm ICMP/ARP/IP phân mảnh và vài tấn công. Thời gian chờ mặc định. | 2130 | 236 | 53 | ĐẠT (18/18) |
| [scan_and_attack](scan_and_attack/README.md) | Quét 101 port, SYN flood 150 gói, 50 lần dò mật khẩu, 25 tấn công web lẫn traffic nền. Thời gian chờ ngắn (TCP 30 s, UDP 10 s). | 2013 | 489 | 444 | ĐẠT (18/18) |

## Vì sao kết quả đối chiếu đáng tin

Nếu lấy chính kết quả của chương trình làm đáp án thì bài test không chứng minh được gì. Ở đây `expected.json` được tính **độc lập với chương trình**, ngay từ lúc dựng traffic:

- **Từng flow:** mỗi phiên dựng ra tương ứng đúng một flow. Số gói, số byte, số cờ SYN/ACK/FIN/RST và chiều đi (forward/backward) được **đếm thẳng từ các gói Scapy**. Trạng thái cuối và lý do kết thúc lấy từ cách dựng phiên: phiên đóng bằng FIN phải là `CLOSED`, phiên bị RST phải là `RESET`, phiên mở lại cùng 5-tuple đang mở phải kết thúc vì `new_connection`. Phiên không tự kết thúc thì hết hạn (`idle_timeout`) nếu thời điểm cuối của cả bộ traffic vượt `last_seen` cộng thời gian chờ, ngược lại còn mở lúc hết dữ liệu (`end_of_input`).
- **Từng Detection Event:** điều kiện khớp của mỗi rule được viết lại bằng Python, không dùng code của engine, rồi áp lên từng gói để biết gói nào phải khớp rule nào.
- **Ghép flow:** mỗi flow mong đợi được ghép với flow thật cùng 5-tuple (theo thứ tự thời gian nếu một 5-tuple được dùng lại) và so từng trường. Hai trường thời gian cho phép lệch dưới 10 micro giây vì PCAP chỉ lưu tới micro giây.
- **Kiểm tra chéo giữa các file:** mọi gói được đưa vào đúng một event; mọi event có flow đều trỏ tới flow có thật; tổng số gói của các flow bằng số event được theo dõi; không có event `invalid` hay lỗi không lường trước; engine không báo lỗi và chỉ mục rule thật sự giúp bỏ bớt lượt xét.

Để chắc bài đối chiếu **bắt được sai lệch chứ không đạt cho có**, hai bộ traffic được thiết kế để nhạy với cấu hình: có phiên dùng lại cùng port sau khi hết hạn, và có kết nối TCP/UDP im lặng quanh mốc thời gian chờ. Khi cho chương trình chạy với thời gian chờ khác cấu hình của bộ (ví dụ `tcp_idle_timeout` 30 → 15, hay UDP 30 → 100), bài đối chiếu báo ngay các flow bị lệch. Bài kiểm thử tự động cũng kiểm tra các bộ traffic còn đủ đa dạng này.

## Các file

| File | Nội dung |
| --- | --- |
| [scenarios.py](scenarios.py) | Dựng traffic từ seed cố định, tính kết quả mong đợi và điều kiện khớp rule |
| [run_scenarios.py](run_scenarios.py) | Tạo đầu vào, chạy `main.py`, đối chiếu và lưu kết quả |
| [test_mixed_traffic.py](test_mixed_traffic.py) | Kiểm tra bằng pytest |
| `office_day/`, `scan_and_attack/` | Kết quả đã lưu: `input.pcap`, `input.rules`, `config.json`, `expected.json`, `flows.jsonl`, `detections.jsonl`, `rule_report.json`, `result.json`, `README.md` |

`events.jsonl` **không được lưu** vì mỗi bộ có hơn hai nghìn event, rất nặng; script chỉ ghi nó vào thư mục tạm để đối chiếu. Muốn xem, chạy lệnh trong README của từng bộ, file sẽ nằm trong `output/`.

## Chạy

```powershell
python -m pytest TEST/extra/mixed_traffic                                   # kiểm tra, không ghi đè kết quả đã lưu
python TEST/extra/mixed_traffic/run_scenarios.py --scenario office_day --overwrite   # tạo lại một bộ
python TEST/extra/mixed_traffic/run_scenarios.py --overwrite                          # tạo lại cả hai bộ
```

Traffic sinh từ seed cố định và chỉ dùng `random()` của Python nên lần nào cũng ra đúng cùng một dãy gói. Đổi seed hay đổi thành phần trong `scenarios.py` sẽ cho ra bộ traffic khác, khi đó cần chạy lại script với `--overwrite`. Địa chỉ IP thuộc dải dành cho tài liệu (RFC 5737) và mạng riêng, không phải traffic thật nên không chứa thông tin cá nhân.

[Về README phần mở rộng](../README.md)
