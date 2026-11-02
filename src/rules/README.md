# Rules - Nạp, phân tích và lưu rule

Module này đọc các file `.rules`, đổi từng dòng rule thành đối tượng `Rule` và lưu vào một kho có chỉ mục. Module **không biết gì về event hay gói tin**; việc đánh giá gói tin nằm ở module [detection](../detection/README.md).

```text
file .rules → Loader → Parser & Validator → Repository
```

## Các file và cách gọi

| File | Nội dung |
| --- | --- |
| `loader.py` | **Rule Loader:** đọc file, bỏ dòng trống và comment, ghép rule viết trên nhiều dòng, bỏ qua file bị tắt |
| `parser.py` | **Rule Parser & Validator:** tách header và tùy chọn, kết luận `valid` / `invalid` / `unsupported` kèm lý do |
| `header.py` | Đọc phần header: hành động, giao thức, IP, port, chiều |
| `options.py` | Đọc phần tùy chọn: các keyword trong phạm vi |
| `model.py` | **Internal Rule Object:** `Rule` và các phần của nó |
| `repository.py` | **Rule Repository / Indexer:** lưu rule và chọn các rule cần xét cho một gói |
| `rule_set.py` | Nối ba bước trên và tạo báo cáo nạp rule |

```python
from src.config import Config
from src.rules.rule_set import load_rule_set

rule_set = load_rule_set(Config(rule_files=["rules/community.rules"]))
print(rule_set.report["summary"])
candidates = rule_set.repository.candidates("TCP", 40000, 80)   # giao thức, port nguồn, port đích
```

## Rule Loader

- Đọc một hoặc nhiều file `.rules` theo thứ tự trong cấu hình và tham số `--rules`.
- Dòng trống và dòng bắt đầu bằng `#` không được chuyển sang bước phân tích. Rule đã bị comment do đó cũng không được nạp.
- Dòng kết thúc bằng dấu `\` được nối với dòng sau, vì Snort cho phép viết một rule trên nhiều dòng.
- Tắt cả file bằng `disabled_rule_files` (tên file hoặc đường dẫn), tắt từng rule bằng `disabled_sids` trong [cấu hình](../../README.md#cấu-hình). Bỏ tên khỏi danh sách là bật lại.
- File không tồn tại là lỗi tham số: chương trình báo lỗi và thoát với mã `2` trước khi tạo file kết quả. Một rule sai thì không làm dừng việc nạp, chỉ sinh cảnh báo.

## Rule Parser & Validator

| Kết luận | Khi nào | Được dùng để so khớp? |
| --- | --- | --- |
| `valid` | Đúng cú pháp và mọi thành phần đều trong phạm vi | Có |
| `invalid` | Sai cú pháp, sai kiểu dữ liệu, thiếu `msg` hoặc `sid`, sid trùng rule khác, biến chưa khai báo | Không |
| `unsupported` | Đúng cú pháp nhưng có thành phần ngoài phạm vi | Không, cả rule bị bỏ |
| `disabled` | Rule bị tắt bằng `disabled_sids` | Không |

Rule có cả lỗi cú pháp và keyword ngoài phạm vi được báo `invalid`.

**Vì sao bỏ cả rule khi có keyword ngoài phạm vi?** Nếu chỉ bỏ riêng keyword đó rồi vẫn so khớp, rule sẽ khớp rộng hơn ý định của người viết. Ví dụ rule `content:"GET"; pcre:"/secret/";` sẽ khớp mọi gói có `GET`.

### Phạm vi hỗ trợ

| Nhóm | Thành phần |
| --- | --- |
| Header | Hành động `alert`; giao thức `tcp`, `udp`, `ip`; IP: `any`, IPv4, CIDR; port: `any`, port đơn, khoảng `a:b`, `:b`, `a:`; chiều `->`, `<>` |
| Viết gọn trong header | Biến `$TEN`, danh sách `[a,b]`, phủ định `!a`. Bộ rule của Snort dùng các dạng này nên chúng được đọc. Giá trị biến đặt trong `rule_variables` |
| Định danh | `msg`, `sid`, `rev` |
| Nội dung | `content` (gồm dạng hex `\|00 01\|` và phủ định `!`), `nocase`, `offset`, `depth`, `distance`, `within` |
| Gói tin | `flags`, `dsize` |
| Flow | `flow`: `to_server`, `to_client`, `established`, `not_established` |
| Phân loại | `classtype`, `priority` |

Thành phần ngoài phạm vi, ví dụ `pcre`, `byte_test`, `metadata`, `reference`, `http_uri`, `flow:from_client`, hành động `drop`, giao thức `icmp`, làm rule thành `unsupported`.

### Các quy tắc kiểm tra

Theo Snort manual (phiên bản 2.9):

- Trong `content`, các ký tự `;`, `\`, `"` phải viết có dấu `\` đứng trước. Phần hex nằm giữa hai dấu `|`.
- `nocase`, `offset`, `depth`, `distance`, `within` phải đứng sau một `content` và áp dụng cho `content` đó.
- `depth` và `within` phải lớn hơn hoặc bằng độ dài chuỗi cần tìm, lớn nhất là 65535. `offset` và `distance` được phép âm.

Do bài làm quy định, manual không nói rõ:

- `msg` và `sid` là bắt buộc, vì Detection Event cần hai trường này; `rev` không bắt buộc.
- Không dùng chung `offset`/`depth` với `distance`/`within` trên cùng một `content`, vì một nhóm tính từ đầu dữ liệu còn nhóm kia tính từ chuỗi vừa tìm thấy.
- Tùy chọn cuối có thể không có dấu `;` như các ví dụ trong bài giảng.

## Internal Rule Object

`Rule` gồm `action`, `protocol`, `source`, `source_ports`, `direction`, `destination`, `destination_ports`, `sid`, `msg`, `rev`, `classtype`, `priority`, `contents`, `flags`, `dsize`, `flow`, cùng `file` và `line` cho biết rule nằm ở đâu.

`AddressSet` và `PortSet` biểu diễn một đầu của header bằng hai danh sách: `include` (được nhận, rỗng nghĩa là mọi giá trị) và `exclude` (bị loại). Hai danh sách đều rỗng chính là `any`. Hàm `describe()` trả dạng JSON, được ghi vào file báo cáo.

## Rule Repository / Indexer

Mỗi rule được xếp theo giao thức, rồi theo các port đơn lẻ của phía đích (phía đích không có port đơn lẻ thì dùng phía nguồn). Rule dùng `any`, khoảng port hoặc phủ định nằm ở danh sách chung của nhóm giao thức.

Khi tra cứu cho một gói:

1. Gói TCP xét nhóm `tcp` và `ip`; gói UDP xét nhóm `udp` và `ip`; gói khác chỉ xét nhóm `ip`.
2. Lấy danh sách chung và các rule có port trùng port nguồn hoặc port đích của gói. Xét cả hai port nên rule `<>` không cần xử lý riêng.
3. Kiểm tra port chính xác, rồi trả kết quả theo thứ tự lúc nạp.

Nhờ vậy không phải duyệt toàn bộ rule cho mỗi gói. IP không nằm trong chỉ mục; bước so khớp kiểm tra IP.

## Báo cáo nạp rule

`load_rule_set` tạo báo cáo gồm `summary` (số dòng comment, dòng trống, số rule theo từng kết luận), `unsupported_keywords` (keyword nào làm bao nhiêu rule bị bỏ), `files` và `rules` (kết luận và lý do của từng rule; rule `valid` có thêm Internal Rule Object). `main.py` in cảnh báo ra màn hình, tối đa 20 rule đầu, và ghi đầy đủ vào file `--rule-report`.

[Quay lại kiến trúc chung](../../README.md)
