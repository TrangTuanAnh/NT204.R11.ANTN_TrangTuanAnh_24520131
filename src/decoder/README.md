# Decoder - Giải mã dữ liệu ứng dụng

Decoder nhận event do [parser](../parser/README.md) tạo ra, kèm byte gốc của phần dữ liệu ứng dụng (payload) nếu có, rồi chuyển dữ liệu đang ở dạng mã hóa sang dạng đọc được. Decoder **không sửa các trường của parser**: kết quả giải mã nằm trong trường mới `decoded`, nên luôn so được dữ liệu gốc với dữ liệu đã giải mã.

## Các file và cách gọi

| File | Nội dung |
| --- | --- |
| `event.py` | `decode_event(event, payload, config)`: chọn cách giải mã theo `application.protocol`, ghi kết quả vào event |
| `http.py` | Giải mã `%XX` trong URI và tham số, đọc form, đọc body theo bảng mã và đổi thực thể HTML |
| `mime.py` | Giải mã thư SMTP: header dạng `=?utf-8?b?...?=`, Base64, Quoted-Printable, từng phần MIME |
| `text.py` | `DecodeReport` (ghi kết quả và lỗi), `decode_text` (đổi byte thành chữ theo bảng mã), `limit_bytes` |

```python
from src.config import Config
from src.decoder import decode_event

decode_event(event, payload, Config())  # payload là bytes; event đọc từ file thì truyền None
print(event["decoded"], event["decode_status"], event["decode_errors"])
```

Hàm sửa trực tiếp trên `event` và **không bao giờ ném lỗi ra ngoài**: lỗi không lường trước chỉ làm event đó có `decode_status` là `error`, chương trình vẫn chạy tiếp.

## Chọn cách giải mã

| Phần ứng dụng của event | Việc decoder làm |
| --- | --- |
| HTTP | Giải mã URI, tham số sau dấu `?`, body (theo bảng mã), form nếu body là `application/x-www-form-urlencoded`, thực thể HTML nếu body là chữ |
| SMTP, `message_type` là `data` (nội dung thư sau lệnh DATA) | Giải mã header và từng phần MIME theo `Content-Transfer-Encoding` |
| DNS | Không cần giải mã (parser đã đọc tên miền và bản ghi): `not_applicable` |
| Giao thức khác hoặc lệnh/phản hồi SMTP, có payload | Đọc cả payload thành chữ (`decoded.text`) để kiểm tra bảng mã |
| Không có payload | Không có gì để giải mã: `not_applicable` |

Khi có byte gốc của gói, decoder ưu tiên dùng byte gốc vì chuỗi chữ của parser đã thay byte lỗi bằng ký tự `�`, không còn biết byte nào sai. Event đọc từ file (`--events`) không có byte gốc thì decoder dùng các trường chữ mà parser để lại (`uri`, `headers`, `body`).

## Cấu trúc `decoded`

Mọi event đều có đủ các khóa dưới đây; khóa không dùng tới có giá trị `null`, `[]` hoặc `{}`.

| Khóa | Nội dung | Ví dụ |
| --- | --- | --- |
| `uri` | URI HTTP sau khi giải mã `%XX` một lượt | `/search?q=' OR 1=1` |
| `query` | Các cặp `[tên, giá trị]` sau dấu `?` của URI | `[["q", "' OR 1=1"]]` |
| `form` | Các cặp `[tên, giá trị]` trong body dạng form | `[["user", "admin'--"]]` |
| `body` | Body HTTP dạng chữ; với thư SMTP là phần chữ của thư (nối các phần text) | `<script>alert(1)</script>` |
| `headers` | Header của thư SMTP đã giải mã, tên viết thường | `{"subject": "Báo cáo IDS"}` |
| `mime_parts` | Từng phần của thư: `content_type`, `charset`, `transfer_encoding`, `filename`, `size`, `body`, `status` | |
| `text` | Toàn bộ payload đọc thành chữ (gói chưa rõ giao thức, lệnh SMTP) | `hello` |

## Trạng thái giải mã

| `decode_status` | Ý nghĩa |
| --- | --- |
| `ok` | Giải mã được và không gặp lỗi |
| `partial` | Có kết quả nhưng gặp lỗi ở một số chỗ, ví dụ byte không hợp lệ đã được thay bằng `�`, chuỗi `%` sai dạng, dữ liệu vượt giới hạn, thư thiếu ranh giới kết thúc |
| `error` | Có lỗi và không giải mã được phần nào, ví dụ Base64 hỏng, body nén gzip |
| `not_applicable` | Không có gì cần giải mã |

`decode_errors` liệt kê từng lỗi, có ghi rõ phần nào bị lỗi và vị trí byte sai, ví dụ `Body HTTP: có byte không hợp lệ với bảng mã utf-8 (vị trí 4)`.

## Các quy tắc giải mã

- **Chỉ giải mã một lượt** để không đổi ý nghĩa dữ liệu: `%2527` thành `%27`, `&amp;lt;` thành `&lt;`.
- **Percent-encoding:** trong URI, dấu `+` giữ nguyên. Trong tham số và form, `+` là khoảng trắng còn `%2B` mới là dấu cộng (quy ước của form HTML). Chuỗi `%` không đúng dạng `%XX` được giữ nguyên và ghi lỗi.
- **Thực thể HTML** (`&lt;`, `&quot;`, `&#39;`, `&#x3C;`...) chỉ được đổi trong nội dung dạng chữ: `text/...`, `application/xhtml+xml`, `application/xml`, hoặc body không ghi `Content-Type`. JSON, form và dữ liệu nhị phân giữ nguyên vì thực thể HTML không thuộc các định dạng này.
- **Bảng mã:** đọc theo `charset` trong `Content-Type`, không ghi thì dùng UTF-8 (UTF-8 bao gồm ASCII). Bảng mã lạ thì tạm đọc theo UTF-8 và ghi lỗi. Byte không hợp lệ được thay bằng `�` và ghi lỗi, chương trình không dừng.
- **MIME:** cách giải mã của từng phần lấy theo header `Content-Transfer-Encoding`, không tự đoán. Base64 thiếu dấu `=` ở cuối được tự thêm; Base64 có ký tự lạ là lỗi. Quoted-Printable có dấu `=` sai dạng thì giữ nguyên chỗ đó và ghi lỗi. Phần dạng chữ được đổi ra chữ (`text/html` còn được đổi thực thể HTML); file đính kèm chỉ ghi kích thước sau giải mã.
- **Dấu hiệu của SMTP** được bỏ trước khi đọc thư: lệnh `DATA` nằm chung gói, dòng `.` báo hết thư, dấu chấm SMTP chèn thêm vào đầu dòng.
- **Giới hạn** (đặt trong [cấu hình](../../README.md#cấu-hình)): chỉ đọc tối đa `max_payload_bytes` byte mỗi gói và `max_mime_parts` phần mỗi thư; vượt giới hạn thì ghi lỗi và đánh dấu `partial`.

## Giới hạn hiện tại

- Chỉ giải mã dữ liệu nằm trong **một gói**. HTTP hoặc thư trải trên nhiều gói chỉ được giải mã phần có trong gói đó (thường bị đánh dấu `partial`).
- Chưa giải nén body `gzip`/`deflate`, chưa ghép body dạng `chunked`, không giải mã TLS/HTTPS.
- Header HTTP được dùng như parser đã đọc, không giải mã thêm.

[Quay lại kiến trúc chung](../../README.md)
