# tests/integration/test_imap_append_limits.py
import socket, ssl, pytest

IMAP_PORT = 2143
ALL_PORTS = [2525, 2587, 2143, 2993]

def recv_until(s, marker, timeout=5):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data

IMPLICIT_TLS_PORTS = {2993}

def assert_server_alive():
    for port in ALL_PORTS:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            if port in IMPLICIT_TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname="localhost")

            s.settimeout(5)
            assert s.recv(1024), f"port {port} accepted but sent no greeting, server may be down"

@pytest.fixture
def imap_session(jams_server):
    # Plaintext LOGIN is refused, so upgrade with STARTTLS first
    raw = socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5)
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n")
    recv_until(raw, b"t1 ")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")

    s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n")
    reply = recv_until(s, b"a1 ")

    if b"a1 OK" not in reply:
        s.close()
        pytest.skip("no seeded test user available to log in with")

    yield s
    s.close()

def test_capability_advertises_appendlimit(jams_server):
    with socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"c1 CAPABILITY\r\n")
        assert b"APPENDLIMIT=" in recv_until(s, b"c1 ")

def test_huge_literal_is_refused_not_fatal(imap_session):
    imap_session.sendall(b"b1 APPEND INBOX {99999999999999}\r\n")
    reply = recv_until(imap_session, b"b1 ")

    assert b"b1 NO" in reply and b"TOOBIG" in reply, f"oversized APPEND should be refused, got {reply!r}"
    assert b"+ " not in reply, "server asked for the literal instead of refusing it"

    # The session itself must still work, and so must every other listener
    imap_session.sendall(b"b2 NOOP\r\n")
    assert b"b2 OK" in recv_until(imap_session, b"b2 ")
    assert_server_alive()

def test_literal_size_overflow_is_rejected(imap_session):
    imap_session.sendall(b"b3 APPEND INBOX {999999999999999999999999}\r\n")
    assert b"b3 BAD" in recv_until(imap_session, b"b3 ")
    assert_server_alive()

def test_empty_literal_does_not_hang(imap_session):
    imap_session.sendall(b"b4 APPEND INBOX {0}\r\n")
    assert b"b4 NO" in recv_until(imap_session, b"b4 ", timeout=3)

def test_oversized_nonsync_literal_closes_without_running_payload(imap_session):
    # With LITERAL+ the client sends the data straight away. Those bytes must
    # never be parsed as commands once the APPEND has been refused.
    imap_session.sendall(b"b5 APPEND INBOX {99999999999999+}\r\nzz1 CREATE smuggled\r\n")
    reply = recv_until(imap_session, b"b5 ", timeout=3)

    assert b"b5 BAD" in reply and b"TOOBIG" in reply, f"oversized LITERAL+ should be rejected, got {reply!r}"
    assert b"zz1" not in recv_until(imap_session, b"zz1", timeout=2), "bytes after a refused LITERAL+ were run as a command"
    assert_server_alive()

def test_normal_append_still_works(imap_session):
    message = b"Subject: hello\r\n\r\nnormal sized message\r\n"
    imap_session.sendall(f"b6 APPEND INBOX {{{len(message)}}}\r\n".encode())
    assert b"+ " in recv_until(imap_session, b"+ ")

    imap_session.sendall(message + b"\r\n")
    assert b"b6 OK" in recv_until(imap_session, b"b6 ")
