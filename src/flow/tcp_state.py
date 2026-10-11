"""Theo dõi trạng thái của một kết nối TCP dựa trên các cờ SYN, ACK, FIN, RST."""

from __future__ import annotations

# Các trạng thái kết nối TCP mà hệ thống theo dõi.
NEW = "NEW"                  # mới thấy gói SYN, đang chờ phía kia trả lời
HANDSHAKE = "HANDSHAKE"      # phía kia đã trả SYN/ACK, chờ gói ACK cuối của bắt tay
ESTABLISHED = "ESTABLISHED"  # kết nối đã thông, đang trao đổi dữ liệu
CLOSING = "CLOSING"          # đã có bên gửi FIN, kết nối đang đóng
CLOSED = "CLOSED"            # hai bên đều đã gửi FIN và FIN cuối đã được xác nhận
RESET = "RESET"              # có gói RST, kết nối bị ngắt ngang

# Hai trạng thái kết thúc: flow được xuất ra và xóa khỏi bảng ngay.
FINISHED_STATES = (CLOSED, RESET)


class TcpConnection:
    """Trạng thái của một kết nối TCP.

    Chỉ dựa vào cờ và chiều đi của từng gói, không so khớp số sequence/
    acknowledgment, nên vẫn đúng với gói tự dựng có các số này bằng 0.
    """

    def __init__(self) -> None:
        """Kết nối mới tạo ở trạng thái NEW, chưa thấy cờ nào."""
        self.state = NEW
        self.handshake_observed = False  # đã thấy đủ ba bước SYN → SYN/ACK → ACK
        self._saw_syn = False
        self._saw_syn_ack = False
        self._fin_directions: set[str] = set()  # các chiều đã gửi FIN
        self._last_fin_direction: str | None = None

    def update(self, flags: str, direction: str) -> None:
        """Cập nhật trạng thái theo cờ của một gói; direction là "forward" hoặc "backward"."""
        syn, ack, fin, rst = ("S" in flags), ("A" in flags), ("F" in flags), ("R" in flags)
        if rst:
            self.state = RESET
        elif fin:
            self._fin_directions.add(direction)
            self._last_fin_direction = direction
            self.state = CLOSING
        elif self.state == CLOSING:
            # Hai bên đều đã gửi FIN: gói ACK từ phía còn lại xác nhận FIN cuối cùng.
            if ack and len(self._fin_directions) == 2 and direction != self._last_fin_direction:
                self.state = CLOSED
        elif syn and not ack:
            self._saw_syn = True  # gói SYN mở kết nối (hoặc gửi lại SYN), vẫn chờ trả lời
        elif syn and ack:
            self._saw_syn_ack = True
            if self.state == NEW:
                self.state = HANDSHAKE
        elif ack and self.state in (NEW, HANDSHAKE):
            # ACK cuối của bắt tay, hoặc bắt gặp một kết nối đang chạy dở (không thấy bắt tay).
            self.handshake_observed = self._saw_syn and self._saw_syn_ack and direction == "forward"
            self.state = ESTABLISHED

    def starts_new_connection(self, flags: str) -> bool:
        """Gói SYN (không kèm ACK) đến khi kết nối cũ đã qua bắt tay nghĩa là một kết nối mới."""
        return "S" in flags and "A" not in flags and self.state in (ESTABLISHED, CLOSING)
