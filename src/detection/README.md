# Detection - Đánh giá event theo rule

Module này nhận event đã chuẩn hóa từ [Preprocessor](../preprocessor/README.md), thông tin flow từ [Flow Tracker](../flow/README.md) và kho rule từ module [rules](../rules/README.md), rồi sinh Detection Event khi có rule khớp. Module **không đọc gói Scapy** và **không in cảnh báo**.

```text
Event đã chuẩn hóa + thông tin flow → Evaluation Engine → Repository/Indexer → Matching Engine → Detection Event
```

## Các file và cách gọi

| File | Nội dung |
| --- | --- |
| `evaluator.py` | **Rule Evaluation Engine:** lấy các rule cần xét cho một gói, gọi so khớp từng rule, giữ các bộ đếm |
| `matcher.py` | **Rule Matching Engine:** trả lời một rule có khớp với một gói không |
| `generator.py` | **Detection Event Generator:** tạo bản ghi thống nhất khi rule khớp |

```python
from src.detection.evaluator import RuleEvaluator
from src.detection.generator import build_detection_event

evaluator = RuleEvaluator(rule_set.repository)
for rule, result in evaluator.evaluate(event, flow_context, payload):
    detection = build_detection_event(rule, result, event, flow_context)
```

[Pipeline](../pipeline.py) gọi đúng các bước này sau Flow Tracker. Kết quả được giữ riêng, không ghi vào event, nên file event vẫn đúng dạng của các bài trước.

## Rule Evaluation Engine

- Chỉ đánh giá event có địa chỉ IP đọc được, không bị đánh dấu `invalid` và không bị bỏ theo cấu hình. Gói ICMP hay gói phân mảnh không được theo dõi flow nhưng vẫn được đánh giá, vì rule `ip` có thể khớp với chúng; rule có `flow` thì không.
- Xét mọi rule được chỉ mục chọn và **không dừng ở rule khớp đầu tiên**, nên một gói có thể sinh nhiều Detection Event.
- Lỗi không lường trước khi xét một rule chỉ được đếm vào `errors`, các rule còn lại vẫn được xét.

Các bộ đếm trong `stats`, được ghi vào mục `engine` của file báo cáo:

| Bộ đếm | Ý nghĩa |
| --- | --- |
| `rules_in_repository` | Số rule trong kho |
| `events_seen`, `events_evaluated`, `events_skipped` | Số event được đưa vào, được đánh giá, bị bỏ qua |
| `candidate_rules` | Tổng số lượt rule phải xét. So với `events_evaluated × rules_in_repository` để thấy chỉ mục đã loại được bao nhiêu |
| `content_checks` | Số lần một rule đi tới bước tìm content, là bước tốn công nhất |
| `matches` | Số lần rule khớp |
| `rejected` | Số lần rule bị loại ở từng bước: `header`, `flow`, `packet`, `content` |
| `errors` | Số lỗi không lường trước |

## Rule Matching Engine

`match_rule(rule, packet)` kiểm tra lần lượt, phần rẻ trước và dừng ngay khi có bước không thỏa. `PacketView` gom dữ liệu của một gói để dùng chung cho nhiều rule.

| Bước | Kiểm tra | Bị loại ghi vào |
| --- | --- | --- |
| Header | Giao thức, IP, port, chiều. Rule `<>` khớp cả chiều ngược và ghi `reversed_direction` là `true` | `header` |
| Flow | `to_server`, `to_client`, `established`, `not_established` theo thông tin của Flow Tracker | `flow` |
| Gói tin | `flags`, `dsize` | `packet` |
| Content | Tìm các chuỗi trong dữ liệu của gói | `content` |

Kết quả là `MatchResult`: `verdict` (`MATCH` hoặc `NO_MATCH`), `sid`, `failed_at` (bước bị loại) và `matched` (thông tin khớp).

### Flow

- `to_server` nghĩa là gói đi từ bên mở kết nối, tức `direction` là `forward`; `to_client` là `backward`.
- `established` đúng từ gói ACK cuối của bắt tay trở đi và **vẫn đúng khi kết nối đang đóng** (`CLOSING`, `CLOSED`, `RESET`), vì một bên vẫn có thể gửi dữ liệu trong lúc đó.
- UDP không có kết nối nên `established` luôn sai, `not_established` luôn đúng, theo mô tả của Snort manual.
- Gói không được theo dõi flow thì không khớp rule có keyword `flow`.

### flags và dsize

| Viết trong rule | Ý nghĩa |
| --- | --- |
| `flags:SA` | Có đúng các cờ này, không thừa không thiếu |
| `flags:+A` | Có đủ các cờ này, được có thêm cờ khác |
| `flags:*FR` | Có ít nhất một trong các cờ này |
| `flags:!R` | Không có cờ nào trong số này |
| `flags:0` | Không có cờ nào |
| `flags:S,CE` | Như `flags:S` nhưng bỏ qua hai cờ C và E |
| `dsize:5`, `dsize:>100`, `dsize:<10` | Dữ liệu đúng 5 byte, hơn 100 byte, dưới 10 byte |
| `dsize:300<>400` | Dữ liệu từ 300 đến 400 byte, tính cả hai đầu |

Gói không phải TCP không khớp rule có `flags`. `dsize` lấy từ `transport.payload_length`.

### Content

Engine tìm trên hai vùng dữ liệu, lần lượt, và mọi `content` của rule phải được tìm thấy **trong cùng một vùng**:

| Vùng (`buffer`) | Nội dung | Khi nào có |
| --- | --- | --- |
| `payload` | Byte gốc của gói, sau header TCP/UDP | Khi đọc từ card mạng hoặc PCAP |
| `application` | Dữ liệu dựng lại từ các trường đã phân tích và giải mã: dòng đầu với URI đã giải mã, header và body HTTP; lệnh, phản hồi và nội dung thư SMTP đã giải mã; tên miền và dữ liệu DNS | Khi gói có dữ liệu ứng dụng, kể cả event đọc từ file |

Vùng `application` giúp phát hiện chuỗi bị che bằng mã hóa, ví dụ `GET /..%2f..%2fetc` không có `../` trong byte gốc nhưng có sau khi giải mã. Trường `uri_normalized` không được dùng để tìm, vì Preprocessor đã bỏ các đoạn `../` khỏi trường này.

Cách tính vùng được phép chứa chuỗi cần tìm:

| Keyword | Ý nghĩa | Vùng tìm |
| --- | --- | --- |
| `offset` | Bắt đầu tìm từ byte thứ mấy, tính từ đầu dữ liệu | Từ `offset` tới hết |
| `depth` | Chỉ tìm trong bấy nhiêu byte tính từ điểm bắt đầu | Từ `offset` tới `offset + depth` |
| `distance` | Bỏ qua bấy nhiêu byte tính từ cuối chuỗi vừa tìm thấy; có thể âm | Từ `cuối chuỗi trước + distance` tới hết |
| `within` | Chuỗi phải nằm trọn trong bấy nhiêu byte tính từ điểm bắt đầu | Từ điểm bắt đầu tới `điểm bắt đầu + within` |

- Chuỗi phải nằm **trọn** trong vùng. Với dữ liệu `GET /index`, `content:"index"; depth:5;` không khớp vì vùng chỉ là 5 byte đầu.
- `content` không có `distance`/`within` luôn tìm từ đầu dữ liệu, không phụ thuộc `content` đứng trước.
- Nếu `content` sau không thỏa thì quay lại thử chỗ xuất hiện tiếp theo của `content` trước. Ví dụ `content:"ABC"; content:"DEF"; within:3;` khớp với `ABCxxABCDEF`. Số lần thử có giới hạn, để dữ liệu lặp lại có chủ đích không làm chương trình chạy quá lâu.
- `content:!"..."` nghĩa là chuỗi không được có trong vùng tìm; content này không làm dịch vị trí cho `content` sau.
- `nocase` so sánh không phân biệt hoa thường với chữ cái tiếng Anh.
- Rule có `content` không khớp với gói không có dữ liệu.

## Detection Event Generator

`build_detection_event` tạo một bản ghi JSON cho mỗi lần rule khớp. Các trường được mô tả trong [README chung](../../README.md#file-detection-event).

[Quay lại kiến trúc chung](../../README.md)
