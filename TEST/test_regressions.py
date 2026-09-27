import json

import pytest
from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR

import main
from src import capture
from src.parser import parse_packet


@pytest.mark.parametrize('flags', ['S', 'SA', 'A'])
def test_handshake(flags):
    """Kiểm tra các cờ SYN, SYN/ACK và ACK được giữ lại."""
    event = parse_packet(IP()/TCP(flags=flags), 1, 1.0, 'pcap')
    assert event['transport']['flags'] == flags


@pytest.mark.parametrize('body,status', [(b'hello', 'ok'), (b'he', 'partial')])
def test_post_body(body, status):
    """Kiểm tra body HTTP POST đầy đủ hoặc bị thiếu được phân loại đúng."""
    packet = IP()/TCP(dport=8080)/Raw(b'POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n'+body)
    event = parse_packet(packet, 1, 1.0, 'pcap')
    assert event['status'] == status
    assert event['application']['body'] == body.decode()


def test_incomplete_headers():
    """Kiểm tra HTTP thiếu phần kết thúc header được đánh dấu partial."""
    event = parse_packet(IP()/TCP()/Raw(b'GET / HTTP/1.1\r\nHost: example'), 1, 1.0, 'pcap')
    assert event['status'] == 'partial'


def test_smtp_port_is_not_proof():
    """Kiểm tra dữ liệu lạ trên port SMTP không bị nhận nhầm là SMTP."""
    event = parse_packet(IP()/TCP(dport=465)/Raw(b'opaque data'), 1, 1.0, 'pcap')
    assert event['application']['protocol'] is None


def test_fragment_is_partial():
    """Kiểm tra IPv4 bị chia mảnh được đánh dấu chưa đầy đủ."""
    event = parse_packet(IP(flags='MF')/UDP()/Raw(b'abc'), 1, 1.0, 'pcap')
    assert event['status'] == 'partial'


def test_dns_tcp():
    """Kiểm tra truy vấn DNS đầy đủ trong TCP được phân tích."""
    wire = bytes(DNS(id=123, qd=DNSQR(qname='example.test')))
    packet = IP()/TCP(dport=53)/Raw(len(wire).to_bytes(2, 'big')+wire)
    event = parse_packet(packet, 1, 1.0, 'pcap')
    assert event['application']['transaction_id'] == 123
    assert event['application']['questions'][0]['name'] == 'example.test'


def test_live_writes_before_capture_returns(tmp_path, monkeypatch):
    """Kiểm tra packet live được ghi trước khi thao tác bắt kết thúc."""
    output = tmp_path/'live.jsonl'
    def fake_sniff(**kwargs):
        """Gửi packet mẫu qua callback để kiểm tra file ngay lập tức."""
        assert kwargs['store'] is False
        kwargs['prn'](IP()/TCP(flags='S'))
        assert json.loads(output.read_text())['transport']['flags'] == 'S'
    monkeypatch.setattr(capture, 'sniff', fake_sniff)
    monkeypatch.setattr(capture, 'list_interfaces', lambda: ['test'])
    assert main.main(['--interface', 'test', '--output', str(output)]) == 0


def test_interrupt_preserves_output(tmp_path, monkeypatch):
    """Kiểm tra Ctrl+C đóng file nhưng vẫn giữ event đã ghi."""
    output = tmp_path/'live.jsonl'
    def fake_sniff(**kwargs):
        """Ghi một packet mẫu rồi giả lập thao tác bị ngắt."""
        kwargs['prn'](IP()/TCP())
        raise KeyboardInterrupt
    monkeypatch.setattr(capture, 'sniff', fake_sniff)
    monkeypatch.setattr(capture, 'list_interfaces', lambda: ['test'])
    assert main.main(['--interface', 'test', '--output', str(output)]) == 130
    assert json.loads(output.read_text())['packet_id'] == 1


def test_sources_share_parser(tmp_path, monkeypatch):
    """Kiểm tra live và PCAP tạo cùng nội dung event cho một packet."""
    packet = IP()/TCP()/Raw(b'GET / HTTP/1.1\r\n\r\n')
    packet.time = 1.0
    monkeypatch.setattr(main, 'iter_pcap', lambda _: [(packet, 1.0)])
    monkeypatch.setattr(capture, 'list_interfaces', lambda: ['test'])
    monkeypatch.setattr(capture, 'sniff', lambda **kw: kw['prn'](packet))
    paths = [tmp_path/'offline.jsonl', tmp_path/'live.jsonl']
    assert main.main(['--pcap', 'mock.pcap', '--output', str(paths[0])]) == 0
    assert main.main(['--interface', 'test', '--output', str(paths[1])]) == 0
    events = [json.loads(path.read_text()) for path in paths]
    assert events[0].pop('source') == 'pcap'
    assert events[1].pop('source') == 'live'
    assert events[0] == events[1]


def test_unknown_interface(tmp_path, monkeypatch):
    """Kiểm tra interface không có trong danh sách bị báo lỗi."""
    monkeypatch.setattr(capture, 'list_interfaces', lambda: [])
    assert main.main(['--interface', 'missing', '--output', str(tmp_path/'out')]) == 1


@pytest.mark.parametrize('args', [['--count', '-1'], ['--timeout', '0']])
def test_invalid_limits(args):
    """Kiểm tra giới hạn bắt packet không hợp lệ bị từ chối."""
    assert main.main(['--interface', 'test']+args) == 2


def test_append_keeps_prior_events(tmp_path):
    """Kiểm tra ghi nối tiếp không xóa các event cũ trong file."""
    from src.output import JsonLinesWriter
    path = tmp_path/'events'
    for number in [1, 2]:
        with JsonLinesWriter(path) as writer:
            writer.write({'packet_id': number})
    assert [json.loads(line)['packet_id'] for line in path.read_text().splitlines()] == [1, 2]
