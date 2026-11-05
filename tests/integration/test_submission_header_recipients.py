# tests/integration/test_submission_header_recipients.py
#
# N13: the Cc/Bcc recipients that SubmissionServer::deliver() collects out of the
# header block never pass through cmd_rcpt, so none of the recipient checks that
# live there ran on them. An authenticated user could name any local address in a
# Cc and the server created a brand new Maildir for it.
import socket, ssl, base64, os, uuid, pytest

SUBMISSION_PORT = 2587
IMAP_PORT = 2143
MAILROOT = "/tmp/jams/mail"

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
        return recv_until(s, b"\r\n", timeout=15)


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
        everything = recv_until(s, b"a3 ", timeout=15)

    for part in everything.split(b"* "):
        if marker in part:
            return part
    return None


def test_cc_to_an_account_that_does_not_exist_creates_no_mailbox(jams_server):
    """N13: a Cc naming a local address with no account behind it made a Maildir.

    deliver() resolved the alias, path-checked the local part and handed it to
    Storage::MailDir, whose ensure_dirs() creates whatever is missing. Nothing on
    that path ever asked whether the user exists.
    """
    ghost = f"ghost-cc-{uuid.uuid4().hex[:12]}"
    marker = f"n13-{uuid.uuid4().hex}".encode()
    message = (
        b"From: ci-test-user@test.local\r\n"
        b"To: ci-test-user@test.local\r\n"
        b"Cc: " + ghost.encode() + b"@test.local\r\n"
        b"Subject: " + marker + b"\r\n"
        b"\r\n"
        b"The Cc names nobody.\r\n"
    )

    reply = submit(message, rcpts=(b"ci-test-user@test.local",))

    assert not os.path.exists(os.path.join(MAILROOT, ghost)), \
        f"a Cc header conjured a mailbox for {ghost}, who has no account"

    # The undeliverable Cc is not a reason to fail the message, the envelope
    # recipient already has it. A 4xx here only makes the client send it again.
    assert reply.startswith(b"250"), f"the message should still be accepted, got {reply!r}"
    assert b"header recipient" in reply, \
        f"the sender was never told the Cc address was dropped: {reply!r}"

    assert fetch_message_containing(marker, "ci-test-user", "ci-test-password") is not None, \
        "the envelope recipient did not get the message"


def test_cc_to_a_real_local_user_still_delivers(jams_server):
    """The point of #100: a Cc to an account that does exist is still a recipient."""
    marker = f"n13-real-{uuid.uuid4().hex}".encode()
    message = (
        b"From: ci-test-user@test.local\r\n"
        b"To: ci-test-user@test.local\r\n"
        b"Cc: " + VICTIM_USER.encode() + b"@test.local\r\n"
        b"Subject: " + marker + b"\r\n"
        b"\r\n"
        b"The Cc names a real account.\r\n"
    )

    reply = submit(message, rcpts=(b"ci-test-user@test.local",))
    assert reply.startswith(b"250"), f"submission should be accepted, got {reply!r}"
    assert b"header recipient" not in reply, \
        f"a deliverable Cc was reported as dropped: {reply!r}"

    assert fetch_message_containing(marker, VICTIM_USER, VICTIM_PASSWORD) is not None, \
        "the Cc recipient never got a copy"
    assert fetch_message_containing(marker, "ci-test-user", "ci-test-password") is not None, \
        "the envelope recipient did not get the message"


def test_one_cc_line_of_ghosts_creates_no_mailboxes(jams_server):
    """N13 at scale: 300 addresses on one Cc line made 99 mailboxes in one message.

    The 100-recipient cap held, so the cap was never the bug: it only bounded how
    many accounts a single message could invent.
    """
    run = uuid.uuid4().hex[:8]
    ghosts = [f"ghost-many-{run}-{i}" for i in range(40)]
    marker = f"n13-many-{uuid.uuid4().hex}".encode()
    cc_line = ", ".join(f"{g}@test.local" for g in ghosts).encode()
    message = (
        b"From: ci-test-user@test.local\r\n"
        b"To: ci-test-user@test.local\r\n"
        b"Cc: " + cc_line + b"\r\n"
        b"Subject: " + marker + b"\r\n"
        b"\r\n"
        b"None of these exist.\r\n"
    )

    reply = submit(message, rcpts=(b"ci-test-user@test.local",))
    assert reply.startswith(b"250"), f"the message should still be accepted, got {reply!r}"

    created = [g for g in ghosts if os.path.exists(os.path.join(MAILROOT, g))]
    assert not created, f"one Cc line created {len(created)} mailboxes for accounts that do not exist: {created[:5]}"

    assert fetch_message_containing(marker, "ci-test-user", "ci-test-password") is not None, \
        "the envelope recipient did not get the message"
