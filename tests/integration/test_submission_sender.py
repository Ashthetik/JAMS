# tests/integration/test_submission_sender.py
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

@pytest.fixture
def session(jams_server):
    raw = socket.create_connection(("127.0.0.1", 2587), timeout=5)
    recv_until(raw, b"\r\n")
    raw.sendall(b"EHLO client.test\r\n"); recv_until(raw, b"250 ")
    raw.sendall(b"STARTTLS\r\n"); recv_until(raw, b"220")

    s = tls(raw)
    s.sendall(b"EHLO client.test\r\n"); recv_until(s, b"250 ")
    s.sendall(b"AUTH PLAIN " + base64.b64encode(b"\0ci-test-user\0ci-test-password") + b"\r\n")
    if b"235" not in recv_until(s, b"\r\n"):
        s.close()
        pytest.skip("no seeded test user available to log in with")

    yield s
    s.close()

def command(s, line):
    s.sendall(line.encode() + b"\r\n")
    return recv_until(s, b"\r\n")

def send_message(s, mail_from, from_header, subject):
    assert command(s, f"MAIL FROM:<{mail_from}>").startswith(b"250")
    assert command(s, "RCPT TO:<ci-test-user@test.local>").startswith(b"250")
    assert command(s, "DATA").startswith(b"354")
    s.sendall(f"From: {from_header}\r\nTo: ci-test-user@test.local\r\nSubject: {subject}\r\n\r\nbody\r\n.\r\n".encode())
    return recv_until(s, b"\r\n", timeout=10)

def inbox_subjects():
    raw = socket.create_connection(("127.0.0.1", 2143), timeout=5)
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n"); recv_until(raw, b"t1 ")
    with tls(raw) as s:
        s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n"); recv_until(s, b"a1 ")
        s.sendall(b"a2 SELECT INBOX\r\n"); recv_until(s, b"a2 ")
        s.sendall(b"a3 FETCH 1:* BODY[]\r\n")
        return recv_until(s, b"a3 ")

@pytest.mark.parametrize("sender", ["ceo@bigbank.example", "traversal-victim@test.local", ""], ids=["foreign", "other-local-user", "null-sender"])
def test_envelope_sender_must_be_owned(session, sender):
    reply = command(session, f"MAIL FROM:<{sender}>")
    assert reply.startswith(b"550") and b"5.7.1" in reply, f"MAIL FROM:<{sender}> should be refused, got {reply!r}"

def test_own_address_is_accepted_case_insensitively(session):
    assert command(session, "MAIL FROM:<CI-Test-User@TEST.LOCAL>").startswith(b"250")

def test_short_mail_command_is_a_syntax_error(session):
    assert command(session, "MAIL X").startswith(b"501")

def test_spoofed_from_header_is_refused_and_not_delivered(session):
    subject = f"spoof-{uuid.uuid4().hex}"
    reply = send_message(session, "ci-test-user@test.local", "Big Bank <security@bigbank.example>", subject)
    assert reply.startswith(b"550"), f"spoofed From header should be refused, got {reply!r}"
    assert subject.encode() not in inbox_subjects()

def test_display_name_with_comma_is_fine(session):
    subject = f"comma-{uuid.uuid4().hex}"
    reply = send_message(session, "ci-test-user@test.local", '"User, CI" <ci-test-user@test.local>', subject)
    assert reply.startswith(b"250"), reply
    assert subject.encode() in inbox_subjects()

def test_session_can_send_more_than_one_message(session):
    first, second = f"first-{uuid.uuid4().hex}", f"second-{uuid.uuid4().hex}"
    assert send_message(session, "ci-test-user@test.local", "ci-test-user@test.local", first).startswith(b"250")
    assert send_message(session, "ci-test-user@test.local", "ci-test-user@test.local", second).startswith(b"250")

    subjects = inbox_subjects()
    assert first.encode() in subjects and second.encode() in subjects

def test_session_recovers_after_a_refused_message(session):
    refused = send_message(session, "ci-test-user@test.local", "someone@else.example", "nope")
    assert refused.startswith(b"550")

    # The connection must be back in command mode, not still swallowing DATA
    assert command(session, "NOOP").startswith(b"250")
    assert send_message(session, "ci-test-user@test.local", "ci-test-user@test.local", f"after-{uuid.uuid4().hex}").startswith(b"250")
