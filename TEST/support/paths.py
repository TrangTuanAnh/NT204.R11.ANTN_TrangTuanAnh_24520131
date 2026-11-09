"""Đường dẫn dùng chung cho các bài kiểm thử và script chạy ca.

Tính một lần ở đây để file nào cũng không phải đếm số cấp thư mục theo vị trí của mình.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_DIR = REPO_ROOT / "TEST"

# Kết quả các ca bắt buộc của từng bài tập.
BT1_DIR = TEST_DIR / "BT1"
BT2_DIR = TEST_DIR / "BT2"
BT3_DIR = TEST_DIR / "BT3"

# Các phần mở rộng, ngoài danh sách ca bắt buộc của đề.
EXTRA_DIR = TEST_DIR / "extra"
