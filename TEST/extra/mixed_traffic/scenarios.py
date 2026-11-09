"""Sinh hai bộ traffic tổng hợp lớn (khoảng 2.000 gói mỗi bộ) cùng kết quả mong đợi của từng bộ.

Mỗi bộ gồm nhiều phiên giao tiếp (HTTP, DNS, SMTP, SSH, UDP...) xen kẽ nhau theo thời gian, cộng thêm
một số gói chương trình chưa hỗ trợ (ICMP, ARP, IP phân mảnh) và một số tấn công cho rule bắt.

Kết quả mong đợi KHÔNG lấy từ kết quả của chương trình. Nó được tính từ chính các gói Scapy vừa dựng
(đếm gói, byte, cờ, chiều đi) và từ cách dựng từng loại phiên (phiên đóng bằng FIN thì phải CLOSED,
phiên bị RST thì phải RESET...). Điều kiện khớp của từng rule cũng được viết lại độc lập bằng Python,
không dùng code của engine, nên đây là một lần kiểm tra chéo thật sự.

Traffic sinh từ một seed cố định, chỉ dùng random() nên cho ra đúng cùng một dãy gói ở mọi lần chạy.
"""

from __future__ import annotations

import base64
import quopri
import random
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import unquote_to_bytes

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Raw, fragment

from src.config import Config
from TEST.support.builders import BASE_TIME, frame, http_message, tcp, udp

# Seed của từng bộ traffic. Đổi seed là ra một bộ traffic khác hẳn, nên chỉ đổi khi thật cần.
OFFICE_SEED = 20261101
SCAN_SEED = 20261103

WEB_SERVER = "192.0.2.80"
MAIL_SERVER = "198.51.100.25"
DNS_SERVER = "192.0.2.53"
GAME_SERVER = "192.0.2.90"
SSH_SERVER = "192.0.2.22"

# Nội dung các trang web và đường dẫn dùng cho traffic bình thường.
BENIGN_PATHS = ["/", "/index.html", "/products?id=%d", "/static/app.js", "/images/logo.png",
                "/api/items?limit=20&page=%d", "/about", "/contact", "/search?q=network+security"]
DOMAINS = ["www.example.test", "mail.example.test", "cdn.example.test", "api.example.test",
           "login.example.test", "static.example.test", "docs.example.test", "update.example.test"]
WORDS = ["network", "security", "traffic", "flow", "packet", "server", "client", "session", "alert", "rule"]


class Rng:
    """Bộ sinh số ngẫu nhiên có seed cố định.

    Chỉ dùng random() của thư viện chuẩn, vì dãy số của hàm này không đổi giữa các phiên bản Python
    (các hàm như randint hay choice thì có thể đổi cách tính).
    """

    def __init__(self, seed: int) -> None:
        """Tạo bộ sinh với seed cho trước."""
        self._random = random.Random(seed)

    def real(self) -> float:
        """Số thực trong khoảng [0, 1)."""
        return self._random.random()

    def below(self, count: int) -> int:
        """Số nguyên từ 0 đến count - 1."""
        return int(self.real() * count)

    def between(self, low: int, high: int) -> int:
        """Số nguyên từ low đến high, tính cả hai đầu."""
        return low + self.below(high - low + 1)

    def pick(self, items: list[Any]) -> Any:
        """Chọn một phần tử của danh sách."""
        return items[self.below(len(items))]

    def moment(self, window: float) -> float:
        """Một thời điểm ngẫu nhiên trong [0, window) giây, làm tròn tới mili giây."""
        return round(self.real() * window, 3)

    def binary(self, length: int) -> bytes:
        """Dữ liệu nhị phân ngẫu nhiên, giả làm dữ liệu đã mã hóa."""
        return bytes(self.below(256) for _ in range(length))

    def text(self, length: int) -> bytes:
        """Chuỗi chữ thường và khoảng trắng ngẫu nhiên đúng độ dài cho trước."""
        out = b""
        while len(out) < length:
            out += self.pick(WORDS).encode() + b" "
        return out[:length]


class PortPool:
    """Cấp port tạm (ephemeral) không trùng nhau cho từng máy client."""

    def __init__(self) -> None:
        """Bắt đầu với chưa cấp port nào."""
        self._next: dict[str, int] = {}

    def take(self, ip: str) -> int:
        """Port tạm kế tiếp của máy có địa chỉ ip."""
        port = self._next.get(ip, 32768)
        self._next[ip] = port + 1
        return port


class Conn:
    """Một kết nối TCP đang được dựng: tự giữ số sequence và đồng hồ, gói nào cũng có thời điểm tăng dần."""

    def __init__(self, rng: Rng, start: float, client: tuple[str, int], server: tuple[str, int]) -> None:
        """Bắt đầu kết nối tại thời điểm start (giây tính từ BASE_TIME), chưa có gói nào."""
        self.rng, self.t = rng, start
        self.client, self.server = client, server
        self.seq = {"c": 1000 + rng.below(900_000), "s": 5000 + rng.below(900_000)}
        self.packets: list[Any] = []

    def send(self, side: str, flags: str, data: bytes = b"") -> None:
        """Một bên ("c" client hoặc "s" server) gửi một gói với cờ và dữ liệu cho trước."""
        src, dst = (self.client, self.server) if side == "c" else (self.server, self.client)
        other = "s" if side == "c" else "c"
        self.t = round(self.t + 0.001 + self.rng.real() * 0.02, 3)
        ack = self.seq[other] if "A" in flags else 0
        self.packets.append(tcp(self.t, src[0], src[1], dst[0], dst[1], flags, data, seq=self.seq[side], ack=ack))
        # SYN và FIN mỗi cờ chiếm một số sequence, dữ liệu chiếm đúng số byte của nó.
        self.seq[side] += len(data) + ("S" in flags) + ("F" in flags)

    def handshake(self) -> None:
        """Bắt tay ba bước: SYN, SYN/ACK, ACK."""
        self.send("c", "S")
        self.send("s", "SA")
        self.send("c", "A")

    def pause(self, seconds: float) -> None:
        """Im lặng một lúc, ví dụ lúc người dùng đọc trang web."""
        self.t = round(self.t + seconds, 3)

    def say(self, side: str, data: bytes, segment: int = 1400) -> None:
        """Một bên gửi dữ liệu (cắt thành nhiều gói nếu dài hơn segment), rồi bên kia gửi ACK."""
        for offset in range(0, len(data), segment):
            self.send(side, "PA", data[offset:offset + segment])
        self.send("s" if side == "c" else "c", "A")

    def close(self) -> None:
        """Đóng kết nối bốn bước: client FIN/ACK, server ACK, server FIN/ACK, client ACK."""
        self.send("c", "FA")
        self.send("s", "A")
        self.send("s", "FA")
        self.send("c", "A")

    def reset(self, side: str) -> None:
        """Một bên ngắt kết nối ngang bằng gói RST."""
        self.send(side, "RA" if side == "s" else "R")


@dataclass
class Session:
    """Một phiên giao tiếp, sẽ thành đúng một flow trong kết quả của chương trình."""

    kind: str                  # loại phiên, dùng để thống kê thành phần của bộ traffic
    packets: list[Any]
    state: str | None          # trạng thái TCP cuối cùng mà phiên phải đạt; UDP không có trạng thái
    ends: str                  # cách kết thúc: close, reset, timeout hoặc new_connection
    handshake: bool = False    # có bắt tay ba bước đủ không
    application: str | None = None  # giao thức ứng dụng mà flow phải nhận diện

    @property
    def protocol(self) -> str:
        """TCP hoặc UDP."""
        return "TCP" if self.packets[0].haslayer(TCP) else "UDP"

    @property
    def last_offset(self) -> float:
        """Thời điểm gói cuối của phiên, tính bằng giây từ BASE_TIME."""
        return round(float(self.packets[-1].time) - BASE_TIME, 3)


@dataclass(frozen=True)
class RuleSpec:
    """Một rule: dòng viết vào file .rules và điều kiện khớp viết độc lập với engine."""

    sid: int
    text: str
    matches: Callable[[Any], bool]


@dataclass
class Scenario:
    """Một bộ traffic hoàn chỉnh cùng cấu hình, rule và các thành phần để tính kết quả mong đợi."""

    name: str
    title: str
    description: str
    seed: int
    config: dict[str, Any]
    rules: list[RuleSpec]
    sessions: list[Session]
    noise: list[Any]           # gói không thuộc phiên nào: ICMP, ARP, IP phân mảnh
    packets: list[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Gộp mọi gói và xếp theo thời gian; gói cùng thời điểm giữ nguyên thứ tự dựng."""
        everything = [packet for session in self.sessions for packet in session.packets] + self.noise
        self.packets = sorted(everything, key=lambda packet: float(packet.time))

    def rule_text(self) -> str:
        """Nội dung file .rules của bộ traffic."""
        return "\n".join(rule.text for rule in self.rules) + "\n"

    def composition(self) -> dict[str, dict[str, int]]:
        """Số phiên và số gói của từng loại phiên, cộng nhóm gói chưa hỗ trợ."""
        table: dict[str, dict[str, int]] = {}
        for session in self.sessions:
            row = table.setdefault(session.kind, {"sessions": 0, "packets": 0})
            row["sessions"] += 1
            row["packets"] += len(session.packets)
        if self.noise:
            table["unsupported"] = {"sessions": 0, "packets": len(self.noise)}
        return dict(sorted(table.items()))

    def expected(self) -> dict[str, Any]:
        """Kết quả mong đợi của cả bộ: flow của từng phiên và Detection Event của từng gói."""
        settings = Config(**self.config)
        timeouts = {"TCP": settings.tcp_idle_timeout, "UDP": settings.udp_idle_timeout}
        last_time = max(float(packet.time) for packet in self.packets)
        flows = [expected_flow(session, last_time, timeouts) for session in self.sessions]
        flows.sort(key=flow_order)
        by_packet: dict[str, list[int]] = {}
        by_sid: dict[str, int] = {}
        for number, packet in enumerate(self.packets, start=1):
            sids = sorted(rule.sid for rule in self.rules if rule.matches(packet))
            if sids:
                by_packet[str(number)] = sids
            for sid in sids:
                by_sid[str(sid)] = by_sid.get(str(sid), 0) + 1
        return {
            "packets": len(self.packets),
            "skipped": len(self.noise),
            "last_time": round(last_time, 6),
            "timeouts": {"tcp_idle_timeout": timeouts["TCP"], "udp_idle_timeout": timeouts["UDP"]},
            "rules": len(self.rules),
            "flows": flows,
            "detections": {"total": sum(by_sid.values()), "by_sid": dict(sorted(by_sid.items())),
                           "by_packet": by_packet},
        }


def flow_order(flow: dict[str, Any]) -> tuple:
    """Khóa sắp xếp flow để ghép flow mong đợi với flow thật: theo 5-tuple rồi theo thời điểm bắt đầu."""
    a, b = flow["endpoint_a"], flow["endpoint_b"]
    return flow["protocol"], a["ip"], a["port"], b["ip"], b["port"], flow["start_time"]


def expected_flow(session: Session, last_time: float, timeouts: dict[str, float]) -> dict[str, Any]:
    """Bản tổng kết flow mà chương trình phải ghi ra cho một phiên.

    Số gói, số byte, số cờ và chiều đi đếm thẳng từ các gói Scapy. Trạng thái và lý do kết thúc
    lấy từ cách dựng phiên; riêng phiên không tự kết thúc thì hết hạn nếu thời điểm cuối của cả
    bộ traffic đã vượt last_seen cộng thời gian chờ.
    """
    layer = TCP if session.protocol == "TCP" else UDP
    first = session.packets[0]
    a = (first[IP].src, first[layer].sport)
    b = (first[IP].dst, first[layer].dport)
    sides = {"forward": [0, 0], "backward": [0, 0]}
    flags = {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0}
    for packet in session.packets:
        side = "forward" if (packet[IP].src, packet[layer].sport) == a else "backward"
        sides[side][0] += 1
        sides[side][1] += len(bytes(packet))
        if layer is TCP:
            letters = str(packet[TCP].flags)
            for name, letter in (("SYN", "S"), ("ACK", "A"), ("FIN", "F"), ("RST", "R")):
                flags[name] += letter in letters
    times = [round(float(packet.time), 6) for packet in session.packets]
    start, last = min(times), max(times)
    reasons = {"close": "tcp_closed", "reset": "tcp_reset", "new_connection": "new_connection"}
    if session.ends in reasons:
        reason = reasons[session.ends]
    else:
        deadline = last + timeouts[session.protocol]
        if abs(last_time - deadline) < 0.01:
            raise ValueError("Mốc hết hạn trùng thời điểm cuối của bộ traffic, kết quả sẽ không rõ ràng")
        reason = "idle_timeout" if last_time >= deadline else "end_of_input"
    is_tcp = layer is TCP
    return {
        "kind": session.kind,
        "protocol": session.protocol,
        "application_protocol": session.application,
        "endpoint_a": {"ip": a[0], "port": a[1]},
        "endpoint_b": {"ip": b[0], "port": b[1]},
        "start_time": start,
        "last_seen": last,
        "packet_count": len(session.packets),
        "byte_count": sides["forward"][1] + sides["backward"][1],
        "forward_packet_count": sides["forward"][0],
        "forward_byte_count": sides["forward"][1],
        "backward_packet_count": sides["backward"][0],
        "backward_byte_count": sides["backward"][1],
        **{f"{name}_count": (count if is_tcp else None) for name, count in flags.items()},
        "state": session.state,
        "handshake_observed": session.handshake if is_tcp else None,
        "end_reason": reason,
    }


# ---------------------------------------------------------------- dựng từng loại phiên

def http_exchange(rng: Rng, conn: Conn, method: str, path: str, body: bytes = b"", status: int = 200) -> None:
    """Một lượt request và response HTTP; response dài hơn 1400 byte được cắt thành nhiều gói."""
    headers = {"Host": "www.example.test", "User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    if body:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.say("c", http_message(f"{method} {path} HTTP/1.1", headers, body))
    conn.pause(round(0.002 + rng.real() * 0.05, 3))
    page = b"<p>" + rng.text(rng.between(60, 1800)) + b" &lt;end&gt;</p>"
    reason = {200: "OK", 401: "Unauthorized", 404: "Not Found"}[status]
    conn.say("s", http_message(f"HTTP/1.1 {status} {reason}",
                               {"Content-Type": "text/html; charset=utf-8", "Server": "nginx"}, page))


def http_session(rng: Rng, start: float, client: str, cport: int, requests: list[tuple[str, str, bytes]],
                 ends: str = "close", status: int = 200) -> Session:
    """Một kết nối HTTP tới WEB_SERVER: bắt tay, các lượt request/response, rồi đóng (close), bị reset hoặc để mở (open)."""
    conn = Conn(rng, start, (client, cport), (WEB_SERVER, 80))
    conn.handshake()
    for method, path, body in requests:
        conn.pause(round(rng.real() * 0.5, 3))
        http_exchange(rng, conn, method, path, body, status)
    if ends == "close":
        conn.close()
        return Session("http", conn.packets, "CLOSED", "close", True, "HTTP")
    if ends == "open":  # kết nối giữ mở: chỉ kết thúc khi hết thời gian chờ hoặc hết dữ liệu
        return Session("http_open", conn.packets, "ESTABLISHED", "timeout", True, "HTTP")
    conn.reset("s")
    return Session("http_reset", conn.packets, "RESET", "reset", True, "HTTP")


def benign_requests(rng: Rng) -> list[tuple[str, str, bytes]]:
    """Một đến ba request bình thường, thỉnh thoảng có POST form."""
    requests = []
    for _ in range(rng.between(1, 3)):
        path = rng.pick(BENIGN_PATHS)
        path = path % rng.between(1, 99) if "%d" in path else path
        if rng.below(6) == 0:
            requests.append(("POST", "/contact", b"name=an&message=hello+there"))
        else:
            requests.append(("GET", path, b""))
    return requests


def attack_request(rng: Rng, kind: str) -> tuple[str, str, bytes]:
    """Một request tấn công: traversal (chữ thường hoặc mã hóa %2f) hoặc SQL injection (mã hóa %XX)."""
    if kind == "traversal":
        path = rng.pick(["/download?file=../../../../etc/passwd", "/files/..%2f..%2f..%2fetc/passwd",
                         "/static/../../../windows/win.ini"])
    else:
        path = rng.pick(["/products?id=1%27%20OR%201%3D1--", "/search?q=%27%20or%201%3D1%20--",
                         "/login?user=admin%27%20OR%201%3D1"])
    return "GET", path, b""


def mail_message(rng: Rng, attachment: str | None) -> bytes:
    """Nội dung một thư gửi sau lệnh DATA: phần chữ mã hóa Base64 hoặc Quoted-Printable, có thể kèm file."""
    boundary = f"part-{rng.below(10 ** 6)}"
    text = "Xin chào, đây là báo cáo số liệu mạng.\r\n".encode("utf-8")
    if rng.below(2):
        text_part = ["Content-Transfer-Encoding: base64", "", base64.b64encode(text).decode()]
    else:
        text_part = ["Content-Transfer-Encoding: quoted-printable", "", quopri.encodestring(text).decode().strip()]
    lines = ["From: alice@example.test", "To: bob@example.test", "Subject: Bao cao so lieu",
             "MIME-Version: 1.0", f'Content-Type: multipart/mixed; boundary="{boundary}"', "",
             f"--{boundary}", "Content-Type: text/plain; charset=utf-8", *text_part]
    if attachment:
        lines += [f"--{boundary}", f'Content-Type: application/octet-stream; name="{attachment}"',
                  "Content-Transfer-Encoding: base64", f'Content-Disposition: attachment; filename="{attachment}"',
                  "", base64.b64encode(rng.binary(150)).decode()]
    lines += [f"--{boundary}--", ".", ""]
    return "\r\n".join(lines).encode("utf-8")


def smtp_session(rng: Rng, start: float, client: str, cport: int, attachment: str | None = None) -> Session:
    """Một lần gửi thư qua SMTP: lời chào, lệnh MAIL/RCPT/DATA, nội dung thư, QUIT rồi đóng kết nối."""
    conn = Conn(rng, start, (client, cport), (MAIL_SERVER, 25))
    conn.handshake()
    for side, line in [("s", "220 mail.example.test ESMTP ready"), ("c", "EHLO client.example.test"),
                       ("s", "250 mail.example.test"), ("c", "MAIL FROM:<alice@example.test>"),
                       ("s", "250 OK"), ("c", "RCPT TO:<bob@example.test>"), ("s", "250 OK"),
                       ("c", "DATA"), ("s", "354 End data with <CR><LF>.<CR><LF>")]:
        conn.pause(round(rng.real() * 0.05, 3))
        conn.say(side, (line + "\r\n").encode())
    conn.say("c", mail_message(rng, attachment))
    for side, line in [("s", "250 Queued"), ("c", "QUIT"), ("s", "221 Bye")]:
        conn.say(side, (line + "\r\n").encode())
    conn.close()
    return Session("smtp", conn.packets, "CLOSED", "close", True, "SMTP")


def ssh_session(rng: Rng, start: float, client: str, cport: int, exchanges: int, ends: str = "timeout") -> Session:
    """Một kết nối SSH giả: hai bên trao đổi lời chào rồi dữ liệu nhị phân, không đóng kết nối."""
    conn = Conn(rng, start, (client, cport), (SSH_SERVER, 22))
    conn.handshake()
    conn.say("c", b"SSH-2.0-OpenSSH_9.6\r\n")
    conn.say("s", b"SSH-2.0-OpenSSH_8.9\r\n")
    for _ in range(exchanges):
        conn.pause(round(0.05 + rng.real() * 1.5, 3))
        conn.say("c", rng.binary(rng.between(48, 400)))
        conn.say("s", rng.binary(rng.between(48, 400)))
    return Session("ssh", conn.packets, "ESTABLISHED", ends, True, None)


def dns_exchange(rng: Rng, start: float, client: str, cport: int, name: str, answered: bool = True) -> Session:
    """Một truy vấn DNS qua UDP và câu trả lời của nó (hoặc NXDOMAIN nếu answered là False)."""
    ident = rng.below(65536)
    query = udp(start, client, cport, DNS_SERVER, 53, DNS(id=ident, rd=1, qd=DNSQR(qname=name)))
    at = round(start + 0.002 + rng.real() * 0.05, 3)
    if answered:
        answer = DNSRR(rrname=name, type="A", rdata=f"192.0.2.{rng.between(1, 250)}", ttl=300)
        reply = DNS(id=ident, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=answer)
    else:
        reply = DNS(id=ident, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=name))
    return Session("dns", [query, udp(at, DNS_SERVER, 53, client, cport, reply)], None, "timeout", False, "DNS")


def game_session(rng: Rng, start: float, client: str, cport: int, bursts: int) -> Session:
    """Một luồng UDP không phải DNS (port 5000): client gửi, server trả lời, lặp lại vài lượt."""
    packets, t = [], start
    for _ in range(bursts):
        t = round(t + 0.02 + rng.real() * 0.1, 3)
        packets.append(udp(t, client, cport, GAME_SERVER, 5000, rng.text(rng.between(40, 260))))
        t = round(t + 0.005 + rng.real() * 0.03, 3)
        packets.append(udp(t, GAME_SERVER, 5000, client, cport, rng.text(rng.between(30, 120))))
    return Session("udp_game", packets, None, "timeout", False, None)


def scan_probe(rng: Rng, start: float, attacker: str, aport: int, victim: str, port: int, outcome: str) -> Session:
    """Một lần thăm dò port: closed (server trả RST), open (SYN/ACK rồi attacker RST) hoặc filtered (im lặng)."""
    seq = rng.below(2 ** 31)
    syn = tcp(start, attacker, aport, victim, port, "S", seq=seq)
    if outcome == "filtered":
        return Session("scan_filtered", [syn], "NEW", "timeout")
    if outcome == "closed":
        rst = tcp(round(start + 0.001 + rng.real() * 0.01, 3), victim, port, attacker, aport, "RA", ack=seq + 1)
        return Session("scan_closed", [syn, rst], "RESET", "reset")
    at = round(start + 0.001 + rng.real() * 0.01, 3)
    synack = tcp(at, victim, port, attacker, aport, "SA", seq=7000, ack=seq + 1)
    rst = tcp(round(at + 0.001 + rng.real() * 0.01, 3), attacker, aport, victim, port, "R", seq=seq + 1)
    return Session("scan_open", [syn, synack, rst], "RESET", "reset")


def unsupported_traffic(rng: Rng, window: float, icmp_pairs: int, arp_pairs: int, datagrams: int) -> list[Any]:
    """Gói chương trình chưa hỗ trợ: ICMP, ARP và datagram UDP bị IP phân mảnh thành ba mảnh."""
    packets = []
    for _ in range(icmp_pairs):
        a, b, t = f"10.1.0.{rng.between(10, 60)}", f"192.0.2.{rng.between(1, 99)}", rng.moment(window)
        ident = rng.below(65536)
        packets.append(frame(IP(src=a, dst=b) / ICMP(type=8, id=ident, seq=1) / Raw(b"abcdefgh" * 4), t))
        packets.append(frame(IP(src=b, dst=a) / ICMP(type=0, id=ident, seq=1) / Raw(b"abcdefgh" * 4),
                             round(t + 0.003, 3)))
    for _ in range(arp_pairs):
        a, b, t = f"10.1.0.{rng.between(10, 60)}", "10.1.0.1", rng.moment(window)
        packets.append(frame(ARP(op=1, hwsrc="02:00:00:00:10:01", psrc=a, pdst=b), t))
        packets.append(frame(ARP(op=2, hwsrc="02:00:00:00:00:01", psrc=b, hwdst="02:00:00:00:10:01", pdst=a),
                             round(t + 0.001, 3)))
    for _ in range(datagrams):
        t = rng.moment(window)
        datagram = IP(src=f"10.1.0.{rng.between(10, 60)}", dst=GAME_SERVER, id=rng.below(65535)) / UDP(
            sport=40000, dport=9) / Raw(rng.text(3000))
        for index, piece in enumerate(fragment(datagram, fragsize=1480)):
            packets.append(frame(piece, round(t + index * 0.001, 3)))
    return packets


# ---------------------------------------------------------------- điều kiện khớp rule viết độc lập với engine

def _data(packet: Any, layer: Any, port: int) -> bytes | None:
    """Dữ liệu của gói nếu gói thuộc lớp layer và đi tới port đích đó; ngược lại None."""
    part = packet.getlayer(layer)
    return bytes(part.payload) if part is not None and part.dport == port else None


def _hidden(data: bytes) -> bytes:
    """Dữ liệu sau khi giải mã %XX, vì engine tìm cả trên dữ liệu đã giải mã."""
    return unquote_to_bytes(data)


def _traversal(packet: Any) -> bool:
    """Request HTTP có "../", viết thẳng hoặc bị che bằng %2f."""
    data = _data(packet, TCP, 80)
    return data is not None and (b"../" in data or b"../" in _hidden(data))


def _sql_injection(packet: Any) -> bool:
    """Request HTTP có "' OR 1=1" không phân biệt hoa thường, viết thẳng hoặc mã hóa %XX."""
    data = _data(packet, TCP, 80)
    return data is not None and (b"' or 1=1" in data.lower() or b"' or 1=1" in _hidden(data).lower())


def _dns_c2(packet: Any) -> bool:
    """Truy vấn DNS có tên miền chứa "c2-update"."""
    data = _data(packet, UDP, 53)
    return data is not None and b"c2-update" in data.lower()


def _exe_attachment(packet: Any) -> bool:
    """Gói gửi tới port SMTP có tên file "invoice.exe"."""
    data = _data(packet, TCP, 25)
    return data is not None and b"invoice.exe" in data.lower()


def _ssh_banner(packet: Any) -> bool:
    """Gói gửi tới port SSH mở đầu bằng "SSH-"."""
    data = _data(packet, TCP, 22)
    return data is not None and data[:4] == b"SSH-"


def _large_game_packet(packet: Any) -> bool:
    """Gói UDP tới port 5000 mang hơn 150 byte dữ liệu."""
    data = _data(packet, UDP, 5000)
    return data is not None and len(data) > 150


def _syn_probe(packet: Any) -> bool:
    """Gói chỉ có cờ SYN tới port 7000-7100."""
    part = packet.getlayer(TCP)
    return part is not None and str(part.flags) == "S" and 7000 <= part.dport <= 7100


def _syn_to_web(packet: Any) -> bool:
    """Gói chỉ có cờ SYN tới port 80."""
    part = packet.getlayer(TCP)
    return part is not None and str(part.flags) == "S" and part.dport == 80


def _login_attempt(packet: Any) -> bool:
    """Gói gửi tới port 80 mở đầu bằng "POST /login"."""
    data = _data(packet, TCP, 80)
    return data is not None and data[:11] == b"POST /login"


TRAVERSAL = RuleSpec(3000001, 'alert tcp any any -> any 80 (msg:"Directory traversal"; flow:to_server,established; '
                              'content:"../"; classtype:web-application-attack; priority:1; sid:3000001; rev:1;)',
                     _traversal)
SQL_INJECTION = RuleSpec(3000002, 'alert tcp any any -> any 80 (msg:"SQL injection attempt"; '
                                  'flow:to_server,established; content:"\' OR 1=1"; nocase; '
                                  'classtype:web-application-attack; priority:1; sid:3000002; rev:1;)',
                         _sql_injection)
DNS_C2 = RuleSpec(3000003, 'alert udp any any -> any 53 (msg:"DNS query to suspicious domain"; content:"c2-update"; '
                           'nocase; classtype:trojan-activity; priority:2; sid:3000003; rev:1;)', _dns_c2)
EXE_ATTACHMENT = RuleSpec(3000004, 'alert tcp any any -> any 25 (msg:"Executable attachment in mail"; '
                                   'flow:to_server,established; content:"invoice.exe"; nocase; '
                                   'classtype:policy-violation; priority:3; sid:3000004; rev:1;)', _exe_attachment)
SSH_BANNER = RuleSpec(3000005, 'alert tcp any any -> any 22 (msg:"SSH banner"; flow:to_server,established; '
                               'content:"SSH-"; offset:0; depth:4; sid:3000005; rev:1;)', _ssh_banner)
LARGE_GAME_PACKET = RuleSpec(3000006, 'alert udp any any -> any 5000 (msg:"Large game packet"; dsize:>150; '
                                      'sid:3000006; rev:1;)', _large_game_packet)
SYN_PROBE = RuleSpec(3100001, 'alert tcp any any -> any 7000:7100 (msg:"SYN probe on service ports"; flags:S; '
                              'classtype:attempted-recon; priority:2; sid:3100001; rev:1;)', _syn_probe)
SYN_TO_WEB = RuleSpec(3100002, 'alert tcp any any -> any 80 (msg:"SYN to web server"; flags:S; sid:3100002; rev:1;)',
                      _syn_to_web)
LOGIN_ATTEMPT = RuleSpec(3100003, 'alert tcp any any -> any 80 (msg:"Login attempt"; flow:to_server,established; '
                                  'content:"POST /login"; offset:0; depth:11; sid:3100003; rev:1;)', _login_attempt)


# ---------------------------------------------------------------- hai bộ traffic

def after(session: Session, gap: float) -> float:
    """Thời điểm bắt đầu một phiên mới, cách gói cuối của phiên cũ gap giây."""
    return round(session.last_offset + gap, 3)


def build_office_day() -> Scenario:
    """Một ngày làm việc: web, thư, DNS, SSH, UDP lẫn vài tấn công; thời gian chờ mặc định (TCP 120 s, UDP 30 s)."""
    rng, ports, window = Rng(OFFICE_SEED), PortPool(), 540.0
    sessions: list[Session] = []

    def office_client() -> str:
        """Địa chỉ một máy trong mạng văn phòng."""
        return f"10.1.0.{rng.between(10, 60)}"

    for _ in range(42):
        client = office_client()
        sessions.append(http_session(rng, rng.moment(window), client, ports.take(client), benign_requests(rng)))
    for _ in range(6):  # kết nối bị server reset giữa chừng
        client = office_client()
        sessions.append(http_session(rng, rng.moment(window), client, ports.take(client), benign_requests(rng)[:1],
                                     ends="reset"))
    for _ in range(3):  # cùng client và port mở lại kết nối sau khi kết nối cũ đã đóng: phải là flow mới
        client = office_client()
        port = ports.take(client)
        first = http_session(rng, rng.moment(window), client, port, benign_requests(rng))
        sessions += [first, http_session(rng, after(first, 5.0), client, port, benign_requests(rng))]
    for kind, count in (("traversal", 6), ("sql_injection", 4)):
        for _ in range(count):
            sessions.append(http_session(rng, rng.moment(window), "203.0.113.50", ports.take("203.0.113.50"),
                                         [attack_request(rng, kind)]))
    for index in range(15):
        client = f"10.1.1.{rng.between(10, 60)}"
        sessions.append(smtp_session(rng, rng.moment(window), client, ports.take(client),
                                     "invoice.exe" if index < 3 else rng.pick([None, "report.pdf"])))
    for index in range(130):
        client = office_client()
        name = "c2-update.evil.test" if index < 4 else rng.pick(DOMAINS)
        sessions.append(dns_exchange(rng, rng.moment(window), client, ports.take(client), name,
                                     answered=index % 17 != 16))
    for _ in range(3):  # cùng client và port hỏi lại sau hơn 30 giây: flow cũ đã hết hạn nên phải là flow mới
        client = office_client()
        port = ports.take(client)
        first = dns_exchange(rng, rng.moment(200.0), client, port, rng.pick(DOMAINS))
        sessions += [first, dns_exchange(rng, after(first, 45.0), client, port, rng.pick(DOMAINS))]
    for _ in range(8):
        client = office_client()
        sessions.append(game_session(rng, rng.moment(window), client, ports.take(client), rng.between(3, 6)))
    for start in [rng.moment(window) for _ in range(8)] + [400.0, 430.0, 460.0]:
        # ba phiên cuối cố ý đặt gần cuối: khoảng im lặng tới hết traffic nằm quanh thời gian chờ TCP mặc định
        client = office_client()
        sessions.append(ssh_session(rng, start, client, ports.take(client), rng.between(3, 8)))
    client = office_client()  # SYN mới trên kết nối còn đang mở: flow cũ kết thúc vì new_connection
    port = ports.take(client)
    old = ssh_session(rng, rng.moment(200.0), client, port, 3, ends="new_connection")
    sessions += [old, ssh_session(rng, after(old, 3.0), client, port, 4)]
    return Scenario(
        "office_day", "Một ngày làm việc của văn phòng",
        "Web, thư, DNS, SSH và luồng UDP của nhiều máy xen kẽ nhau trong 9 phút, thêm gói ICMP, ARP, IP phân mảnh "
        "và một số tấn công (directory traversal, SQL injection, truy vấn DNS tới tên miền lạ, thư kèm file .exe). "
        "Thời gian chờ để mặc định.",
        OFFICE_SEED, {}, [TRAVERSAL, SQL_INJECTION, DNS_C2, EXE_ATTACHMENT, SSH_BANNER, LARGE_GAME_PACKET],
        sessions, unsupported_traffic(rng, window, icmp_pairs=10, arp_pairs=6, datagrams=2))


def build_scan_and_attack() -> Scenario:
    """Một kẻ tấn công quét port, một đợt SYN flood và dò mật khẩu giữa traffic nền; thời gian chờ ngắn."""
    rng, ports, window = Rng(SCAN_SEED), PortPool(), 270.0
    sessions: list[Session] = []
    scanner, flooder, brute, attacker = "203.0.113.66", "203.0.113.77", "203.0.113.99", "203.0.113.50"

    for _ in range(32):
        client = f"10.2.0.{rng.between(10, 60)}"
        sessions.append(http_session(rng, rng.moment(window), client, ports.take(client), benign_requests(rng)))
    for _ in range(5):
        client = f"10.2.0.{rng.between(10, 60)}"
        sessions.append(http_session(rng, rng.moment(window), client, ports.take(client), benign_requests(rng)[:1],
                                     ends="reset"))
    for start in (170.0, 185.0, 200.0, 215.0, 230.0, 245.0):
        # Kết nối web giữ mở, cố ý đặt để khoảng im lặng tới hết traffic (khoảng 23-98 giây) nằm quanh thời gian
        # chờ TCP 30 giây: một phần hết hạn, một phần còn mở. Nếu chương trình dùng nhầm thời gian chờ mặc định
        # 120 giây thì không flow nào hết hạn, và bài đối chiếu sẽ báo lệch.
        client = f"10.2.0.{rng.between(10, 60)}"
        sessions.append(http_session(rng, start, client, ports.take(client), benign_requests(rng)[:1], ends="open"))
    for _ in range(120):
        client = f"10.2.0.{rng.between(10, 60)}"
        sessions.append(dns_exchange(rng, rng.moment(window), client, ports.take(client), rng.pick(DOMAINS)))

    # Quét port 7000-7100: phần lớn đóng, vài port mở, vài port không trả lời.
    t = 60.0
    open_ports = {7000 + rng.between(0, 100) for _ in range(3)}
    filtered_ports = {7000 + rng.between(0, 100) for _ in range(4)} - open_ports
    for port in range(7000, 7101):
        outcome = "open" if port in open_ports else "filtered" if port in filtered_ports else "closed"
        t = round(t + 0.05 + rng.real() * 0.25, 3)
        sessions.append(scan_probe(rng, t, scanner, ports.take(scanner), WEB_SERVER, port, outcome))

    # SYN flood tới web server: mỗi gói SYN từ một cặp địa chỉ/port nguồn khác nhau, không được trả lời.
    t = 120.0
    for index in range(150):
        t = round(t + 0.05 + rng.real() * 0.2, 3)
        source_ip = f"198.51.100.{1 + index % 250}"
        sessions.append(Session("syn_flood", [tcp(t, source_ip, 20000 + index, WEB_SERVER, 80, "S",
                                                  seq=rng.below(2 ** 31))], "NEW", "timeout"))

    # Dò mật khẩu: nhiều phiên ngắn lặp lại POST /login, bị từ chối.
    t = 150.0
    for _ in range(50):
        t = round(t + 0.5 + rng.real() * 1.5, 3)
        body = b"user=admin&pass=" + rng.text(8).replace(b" ", b"_")
        sessions.append(http_session(rng, t, brute, ports.take(brute), [("POST", "/login", body)], status=401))

    for kind, count in (("traversal", 14), ("sql_injection", 11)):
        for _ in range(count):
            sessions.append(http_session(rng, rng.moment(window), attacker, ports.take(attacker),
                                         [attack_request(rng, kind)]))
    return Scenario(
        "scan_and_attack", "Quét port, SYN flood và dò mật khẩu",
        "Một máy quét 101 port, một đợt SYN flood 150 gói từ nhiều nguồn, 50 lần dò mật khẩu vào /login và 25 "
        "tấn công web, lẫn trong traffic nền gồm web và DNS. Thời gian chờ được đặt ngắn (TCP 30 s, UDP 10 s) để "
        "nhiều flow hết hạn ngay trong lúc chạy.",
        SCAN_SEED, {"tcp_idle_timeout": 30, "udp_idle_timeout": 10},
        [SYN_PROBE, SYN_TO_WEB, LOGIN_ATTEMPT, TRAVERSAL, SQL_INJECTION], sessions, [])


SCENARIOS: dict[str, Callable[[], Scenario]] = {
    "office_day": build_office_day,
    "scan_and_attack": build_scan_and_attack,
}
