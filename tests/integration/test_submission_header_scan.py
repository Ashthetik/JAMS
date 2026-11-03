# tests/integration/test_submission_header_scan.py
#
# Covers the header block scan that SubmissionServer::deliver() runs over a
# submitted message to pick up Cc/Bcc recipients.
import socket, ssl, base64, uuid, pytest

SUBMISSION_PORT = 2587
IMAP_PORT = 2143
ALL_PORTS = {"smtp": 2525, "submission": 2587, "imap4": 2143, "imap4s": 2993}

VICTIM_USER = "traversal-victim"
VICTIM_PASSWORD = "victim-password"


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


def submit(message, rcpts=(b"ci-test-user@test.local",)):
    raw = socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=5)
    recv_until(raw, b"\r\n")
    raw.sendall(b"EHLO client.test\r\n"); recv_until(raw, b"250 ")
    raw.sendall(b"STARTTLS\r\n"); recv_until(raw, b"220")

    with tls(raw) as s:
        s.sendall(b"EHLO client.test\r\n"); recv_until(s, b"250 ")
        s.sendall(b"AUTH PLAIN " + base64.b64encode(b"\0ci-test-user\0ci-test-password") + b"\r\n")
        if b"235" not in recv_until(s, b"\r\n"):
            pytest.skip("no seeded test user available to log in with")

        s.sendall(b"MAIL FROM:<ci-test-user@test.local>\r\n"); recv_until(s, b"\r\n")
        for rcpt in rcpts:
            s.sendall(b"RCPT TO:<" + rcpt + b">\r\n"); recv_until(s, b"\r\n")
        s.sendall(b"DATA\r\n"); recv_until(s, b"354")
        s.sendall(message + b"\r\n.\r\n")
        return recv_until(s, b"\r\n", timeout=10)


def fetch_message_containing(marker, user, password):
    # In CI the server runs as root and Maildirs are 0700, so read mail back over IMAP
    raw = socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5)
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n"); recv_until(raw, b"t1 ")

    with tls(raw) as s:
        s.sendall(b"a1 LOGIN " + user.encode() + b" " + password.encode() + b"\r\n")
        assert b"a1 OK" in recv_until(s, b"a1 "), f"could not log in as {user}"
        s.sendall(b"a2 SELECT INBOX\r\n"); recv_until(s, b"a2 ")
        s.sendall(b"a3 FETCH 1:* BODY[]\r\n")
        everything = recv_until(s, b"a3 ", timeout=10)

    for part in everything.split(b"* "):
        if marker in part:
            return part
    return None


def test_bare_lf_blank_line_in_body_does_not_kill_the_server(jams_server):
    """N1: the header scan called back() on an empty line.

    A long line leaves the getline buffer on the heap; the bare-LF empty line
    right after it is then read one byte before that allocation, which aborts a
    build with libstdc++ assertions or ASan on. Every port dies with the process,
    so the assertions below check the whole server, not just this one reply.
    """
    marker = f"bare-lf-{uuid.uuid4().hex}".encode()
    message = (
        b"From: ci-test-user@test.local\r\n"
        b"To: ci-test-user@test.local\r\n"
        b"Subject: " + marker + b"\r\n"
        b"\r\n"
        + b"A" * 120 + b"\n"   # long enough that getline's buffer is heap allocated
        b"\n"                  # bare-LF empty line: this is the one that read out of bounds
        b"tail of the body\r\n"
    )

    reply = submit(message)
    assert reply.startswith(b"250"), f"submission should be accepted, got {reply!r}"

    # The abort takes the whole process down, so every listener has to be checked,
    # not just the one the message came in on
    for name, port in ALL_PORTS.items():
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=5)
            # imap4s is implicit TLS, so there is no banner before the handshake
            s = tls(raw) if name == "imap4s" else raw
            with s:
                s.settimeout(5)
                assert s.recv(64), f"{name} port {port} accepted but sent no banner"
        except (OSError, ssl.SSLError) as e:
            pytest.fail(f"{name} port {port} stopped serving after the message: {e}")

    # A banner only proves something is listening; a full transaction proves it still works
    followup = f"still-alive-{uuid.uuid4().hex}".encode()
    after = submit(
        b"From: ci-test-user@test.local\r\nTo: ci-test-user@test.local\r\n"
        b"Subject: " + followup + b"\r\n\r\nStill serving.\r\n"
    )
    assert after.startswith(b"250"), f"server stopped accepting mail after the message, got {after!r}"
    assert fetch_message_containing(followup, "ci-test-user", "ci-test-password") is not None, \
        "server accepted the follow-up message but stopped delivering"


def test_cc_header_delivers_to_a_local_account_not_in_rcpt(jams_server):
    """N2: the header scan never stopped at the blank line and kept the CR.

    Every collected address ended in "\\r", so the local-domain comparison in
    deliver() always failed and the Cc recipient was silently dropped.
    """
    marker = f"cc-test-{uuid.uuid4().hex}".encode()
    message = (
        b"From: ci-test-user@test.local\r\n"
        b"To: ci-test-user@test.local\r\n"
        b"Cc: " + VICTIM_USER.encode() + b"@test.local\r\n"
        b"Subject: " + marker + b"\r\n"
        b"\r\n"
        b"The Cc recipient is not in any RCPT TO.\r\n"
    )

    # Only the sender is in the envelope; the Cc recipient has to come from the header
    reply = submit(message, rcpts=(b"ci-test-user@test.local",))
    assert reply.startswith(b"250"), f"submission should be accepted, got {reply!r}"

    assert fetch_message_containing(marker, "ci-test-user", "ci-test-password") is not None, \
        "the envelope recipient did not get the message"

    delivered = fetch_message_containing(marker, VICTIM_USER, VICTIM_PASSWORD)
    assert delivered is not None, "the Cc recipient never got a copy"


def test_cc_header_in_the_body_is_not_collected(jams_server):
    """N2: with the CR stripped, the scan must stop at the end of the headers.

    A "Cc:" line sitting in the message body is text, not a recipient.
    """
    marker = f"body-cc-{uuid.uuid4().hex}".encode()
    message = (
        b"From: ci-test-user@test.local\r\n"
        b"To: ci-test-user@test.local\r\n"
        b"Subject: " + marker + b"\r\n"
        b"\r\n"
        b"Quoting an old message below:\r\n"
        b"Cc: " + VICTIM_USER.encode() + b"@test.local\r\n"
    )

    reply = submit(message, rcpts=(b"ci-test-user@test.local",))
    assert reply.startswith(b"250"), f"submission should be accepted, got {reply!r}"

    assert fetch_message_containing(marker, "ci-test-user", "ci-test-password") is not None, \
        "the envelope recipient did not get the message"

    leaked = fetch_message_containing(marker, VICTIM_USER, VICTIM_PASSWORD)
    assert leaked is None, "a Cc: line in the body was treated as a header and delivered"
