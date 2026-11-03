# tests/integration/test_smtp_bcc_body.py
import socket, ssl, uuid

SMTP_PORT = 2525

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

def deliver_inbound(message):
    # Plain port 25, the way another mail server would hand us a message
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=10) as s:
        recv_until(s, b"\r\n")
        s.sendall(b"EHLO relay.elsewhere.test\r\n"); recv_until(s, b"250 ")
        s.sendall(b"MAIL FROM:<sender@elsewhere.test>\r\n"); recv_until(s, b"\r\n")
        s.sendall(b"RCPT TO:<ci-test-user@test.local>\r\n")
        if b"250" not in recv_until(s, b"\r\n"):
            return b""
        s.sendall(b"DATA\r\n"); recv_until(s, b"354")
        s.sendall(message + b"\r\n.\r\n")
        return recv_until(s, b"\r\n", timeout=15)

def fetch_message_containing(marker):
    # Read it back over IMAP; in CI the server runs as root and Maildirs are 0700
    raw = socket.create_connection(("127.0.0.1", 2143), timeout=5)
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n"); recv_until(raw, b"t1 ")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with ctx.wrap_socket(raw, server_hostname="localhost") as s:
        s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n")
        assert b"a1 OK" in recv_until(s, b"a1 "), "test user could not log in to check its inbox"
        s.sendall(b"a2 SELECT INBOX\r\n"); recv_until(s, b"a2 ")
        s.sendall(b"a3 FETCH 1:* BODY[]\r\n")
        everything = recv_until(s, b"a3 ", timeout=10)

    for part in everything.split(b"* "):
        if marker in part:
            return part
    return None

def test_inbound_body_keeps_header_looking_lines(jams_server):
    # A quoted reply or a forwarded message routinely carries header-looking lines in
    # the body. Port 25 must not edit them: anything the sender DKIM-signed breaks if
    # it does. The real Bcc header above still has to go (RFC 5322 3.6.3).
    marker = f"inbound-bcc-{uuid.uuid4().hex}".encode()
    message = (
        b"From: sender@elsewhere.test\r\n"
        b"To: ci-test-user@test.local\r\n"
        b"Bcc: real-header-secret@example.com,\r\n hidden-too@example.com\r\n"
        b"Subject: " + marker + b"\r\n"
        b"\r\n"
        b"Forwarding the original below.\r\n"
        b"Bcc: accounting@example.net,\r\n"
        b"\tpayroll@example.net\r\n"
        b"That was the end of the quoted block.\r\n"
    )

    assert deliver_inbound(message).startswith(b"250"), "inbound message was not accepted"

    delivered = fetch_message_containing(marker)
    assert delivered is not None, "message was not delivered"

    _, sep, body = delivered.partition(b"\r\n\r\n")
    assert sep, "delivered message has no header/body separator"

    # The body survives byte for byte, folded continuations included
    assert b"Bcc: accounting@example.net," in body, "body Bcc line was deleted"
    assert b"payroll@example.net" in body, "folded continuation under a body Bcc line was deleted"
    assert b"That was the end of the quoted block." in body

    # ...and the genuine Bcc header is still stripped
    assert b"real-header-secret" not in delivered, "Bcc header leaked to the recipient"
    assert b"hidden-too" not in delivered, "folded Bcc header continuation leaked to the recipient"
