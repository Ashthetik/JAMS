# tests/integration/test_message_size.py
import base64, socket, ssl, pytest

SMTP_PORT = 2525
SUBMISSION_PORT = 2587
LIMIT = 52428800  # advertised as SIZE in EHLO
TOO_BIG = b"Subject: big\r\n\r\n" + (b"x" * 998 + b"\r\n") * (LIMIT // 1000 + 1024)

def recv_line(s, timeout=10):
    s.settimeout(timeout)
    data = b""
    try:
        while not data.endswith(b"\r\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data

def ehlo(s):
    s.sendall(b"EHLO test.local\r\n")
    reply = b""
    while b"250 " not in reply:
        chunk = recv_line(s, timeout=5)
        if not chunk:
            break
        reply += chunk
    return reply

def port25():
    s = socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=10)
    recv_line(s)
    ehlo(s)
    return s

def send(s, body, mail_from=b"MAIL FROM:<sender@example.com>", rcpt=b"RCPT TO:<ci-test-user@test.local>"):
    for line in (mail_from, rcpt, b"DATA"):
        s.sendall(line + b"\r\n")
        reply = recv_line(s)
        if not reply[:1] in (b"2", b"3"):
            return reply
    # A Debug + ASan build reads a 50 MB upload slowly, give it room
    s.settimeout(300)
    s.sendall(body + b"\r\n.\r\n")
    return recv_line(s, timeout=300)

def test_ehlo_advertises_the_limit(jams_server):
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=10) as s:
        recv_line(s)
        assert f"SIZE {LIMIT}".encode() in ehlo(s)

def test_oversized_message_on_port_25_is_refused(jams_server):
    with port25() as s:
        reply = send(s, TOO_BIG)
        assert reply.startswith(b"552"), f"a {len(TOO_BIG)} byte message got {reply!r}"

        # And the connection is back in command mode afterwards
        s.sendall(b"NOOP\r\n")
        assert recv_line(s).startswith(b"250")

def test_declared_size_over_the_limit_is_refused_up_front(jams_server):
    with port25() as s:
        s.sendall(f"MAIL FROM:<sender@example.com> SIZE={LIMIT + 1}\r\n".encode())
        assert recv_line(s).startswith(b"552"), "MAIL FROM with SIZE= over the limit should be refused before any data is sent"

        s.sendall(b"MAIL FROM:<sender@example.com> SIZE=1000\r\n")
        assert recv_line(s).startswith(b"250"), "a declared size under the limit should be fine"

def test_normal_message_still_goes_through(jams_server):
    with port25() as s:
        assert send(s, b"Subject: small\r\n\r\nhello\r\n").startswith(b"250")

def test_oversized_message_on_587_is_refused(jams_server):
    raw = socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=10)
    recv_line(raw)
    ehlo(raw)
    raw.sendall(b"STARTTLS\r\n"); recv_line(raw)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    try:
        ehlo(s)
        s.sendall(b"AUTH PLAIN " + base64.b64encode(b"\0ci-test-user\0ci-test-password") + b"\r\n")
        if b"235" not in recv_line(s):
            pytest.skip("no seeded test user available to log in with")

        reply = send(s, b"From: <ci-test-user@test.local>\r\n" + TOO_BIG,
                     mail_from=b"MAIL FROM:<ci-test-user@test.local>")
        assert reply.startswith(b"552"), f"587 accepted a message over the limit: {reply!r}"
    finally:
        s.close()
