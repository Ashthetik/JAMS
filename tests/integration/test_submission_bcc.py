# tests/integration/test_submission_bcc.py
import socket, ssl, base64, uuid, pytest

def recv_until(s, marker, timeout=5):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ssl.SSLError):
        pass
    return data

def tls(raw):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname="localhost")

def submit(message):
    raw = socket.create_connection(("127.0.0.1", 2587), timeout=5)
    recv_until(raw, b"\r\n")
    raw.sendall(b"EHLO client.test\r\n"); recv_until(raw, b"250 ")
    raw.sendall(b"STARTTLS\r\n"); recv_until(raw, b"220")

    with tls(raw) as s:
        s.sendall(b"EHLO client.test\r\n"); recv_until(s, b"250 ")
        s.sendall(b"AUTH PLAIN " + base64.b64encode(b"\0ci-test-user\0ci-test-password") + b"\r\n")
        if b"235" not in recv_until(s, b"\r\n"):
            pytest.skip("no seeded test user available to log in with")

        s.sendall(b"MAIL FROM:<ci-test-user@test.local>\r\n"); recv_until(s, b"\r\n")
        s.sendall(b"RCPT TO:<ci-test-user@test.local>\r\n"); recv_until(s, b"\r\n")
        s.sendall(b"DATA\r\n"); recv_until(s, b"354")
        s.sendall(message + b"\r\n.\r\n")
        return recv_until(s, b"\r\n", timeout=10)

def fetch_message_containing(marker):
    # Read back over IMAP; in CI the Maildirs belong to root and aren't readable directly
    raw = socket.create_connection(("127.0.0.1", 2143), timeout=5)
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n"); recv_until(raw, b"t1 ")

    with tls(raw) as s:
        s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n")
        assert b"a1 OK" in recv_until(s, b"a1 ")
        s.sendall(b"a2 SELECT INBOX\r\n"); recv_until(s, b"a2 ")
        s.sendall(b"a3 FETCH 1:* BODY[]\r\n")
        everything = recv_until(s, b"a3 ")

    for part in everything.split(b"* "):
        if marker in part:
            return part
    return None

def test_bcc_header_is_not_delivered_and_body_is_untouched(jams_server):
    marker = f"bcc-test-{uuid.uuid4().hex}".encode()
    message = (b"From: ci-test-user@test.local\r\nTo: ci-test-user@test.local\r\n"
               b"Bcc: secret-recipient@example.com,\r\n another-secret@example.com\r\n"
               b"Subject: " + marker + b"\r\n\r\n"
               b"Hello there.\r\nBcc: this line is part of the body and must survive\r\n")

    assert submit(message).startswith(b"250")

    delivered = fetch_message_containing(marker)
    assert delivered is not None, "message was not delivered"

    headers, _, body = delivered.partition(b"\r\n\r\n")
    assert b"secret-recipient" not in delivered and b"another-secret" not in delivered, "Bcc recipients leaked into the delivered copy"
    assert b"Bcc: this line is part of the body and must survive" in body, "a body line was removed by Bcc stripping"
