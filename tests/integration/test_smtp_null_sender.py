# tests/integration/test_smtp_null_sender.py
#
# RFC 5321 4.5.5: the null reverse path "<>" must be accepted. Every bounce and
# every delivery status notification is sent with it, so refusing it means a user
# can never be told that a message of theirs failed.
import socket, ssl

SMTP_PORT = 2525
IMAP_PORT = 2143

BOUNCE_MARKER = "null-sender-bounce-marker-n11"


def recv_until(s, marker, timeout=10):
    # Multi-line SMTP replies arrive in one chunk, so look for the marker
    # anywhere in the buffer, never only at the start of a line.
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


def mail_from_reply(argument):
    """Send one raw `MAIL FROM` line on port 25 and return the server's reply."""
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n")
        recv_until(s, b"250 ")
        s.sendall(argument.encode() + b"\r\n")
        return s.recv(1024)


def rcpt_reply_from_null_sender(rcpt):
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n")
        recv_until(s, b"250 ")
        s.sendall(b"MAIL FROM:<>\r\n")
        s.recv(1024)
        s.sendall(f"RCPT TO:<{rcpt}>\r\n".encode())
        return s.recv(1024)


def fetch_inbox():
    # The server runs as root and Maildirs are 0700, so read the mailbox over
    # IMAP the way a user would instead of off disk. Plaintext LOGIN is refused,
    # so STARTTLS first.
    raw = socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5)
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n")
    recv_until(raw, b"t1 ")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with ctx.wrap_socket(raw, server_hostname="localhost") as s:
        s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n")
        assert b"a1 OK" in recv_until(s, b"a1 "), "test user could not log in to check its inbox"

        s.sendall(b"a2 SELECT INBOX\r\n")
        recv_until(s, b"a2 ")

        s.sendall(b"a3 FETCH 1:* BODY[]\r\n")
        return recv_until(s, b"a3 ")


def test_null_sender_accepted(jams_server):
    reply = mail_from_reply("MAIL FROM:<>")
    assert reply.startswith(b"250"), f"RFC 5321 4.5.5 null reverse path refused, got {reply!r}"


def test_null_sender_with_esmtp_parameters_accepted(jams_server):
    reply = mail_from_reply("MAIL FROM:<> SIZE=1000 BODY=8BITMIME")
    assert reply.startswith(b"250"), f"null reverse path with parameters refused, got {reply!r}"


def test_bounce_from_null_sender_is_delivered(jams_server):
    """A real, bounce-shaped DSN from <> must reach the mailbox and be readable."""
    body = (
        "From: Mail Delivery Subsystem <MAILER-DAEMON@relay.test>\r\n"
        "To: ci-test-user@test.local\r\n"
        "Subject: Undelivered Mail Returned to Sender\r\n"
        "Content-Type: multipart/report; report-type=delivery-status;\r\n"
        '\tboundary="n11boundary"\r\n'
        "\r\n"
        "--n11boundary\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
        f"{BOUNCE_MARKER}: your message could not be delivered.\r\n"
        "\r\n"
        "--n11boundary\r\n"
        "Content-Type: message/delivery-status\r\n"
        "\r\n"
        "Reporting-MTA: dns; relay.test\r\n"
        "Final-Recipient: rfc822; nobody@far.example\r\n"
        "Action: failed\r\n"
        "Status: 5.1.1\r\n"
        "\r\n"
        "--n11boundary--\r\n"
    )

    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=10) as s:
        s.recv(1024)
        s.sendall(b"EHLO relay.test\r\n")
        recv_until(s, b"250 ")

        s.sendall(b"MAIL FROM:<>\r\n")
        assert s.recv(1024).startswith(b"250"), "null reverse path refused, no bounce can ever arrive"

        s.sendall(b"RCPT TO:<ci-test-user@test.local>\r\n")
        assert s.recv(1024).startswith(b"250")

        s.sendall(b"DATA\r\n")
        assert s.recv(1024).startswith(b"354")

        s.sendall(body.encode() + b".\r\n")
        assert s.recv(1024).startswith(b"250"), "bounce was not accepted"

    inbox = fetch_inbox()
    assert BOUNCE_MARKER.encode() in inbox, "the bounce never reached the mailbox"

    # The trace header has to stay well formed with no sender: "from <>" is the
    # conventional spelling of the null reverse path, not an empty token.
    assert b"from <> for <ci-test-user@test.local>" in inbox, \
        "Received: header is malformed for the null sender"


def test_null_sender_does_not_bypass_recipient_checks(jams_server):
    # #86 refuses unknown local recipients on port 25. A bounce must not be a way around it.
    reply = rcpt_reply_from_null_sender("no-such-user-n11@test.local")
    assert reply.startswith(b"550") and b"5.1.1" in reply, \
        f"unknown recipient accepted from the null sender, got {reply!r}"


def test_null_sender_does_not_allow_relaying(jams_server):
    reply = rcpt_reply_from_null_sender("ci-test-user@gmail.com")
    assert reply.startswith(b"550") and b"5.7.1" in reply, \
        f"relaying allowed from the null sender, got {reply!r}"


def test_mail_from_with_no_argument_still_rejected(jams_server):
    reply = mail_from_reply("MAIL FROM:")
    assert reply.startswith(b"501"), f"a missing reverse path must stay an error, got {reply!r}"


def test_mail_from_with_only_whitespace_still_rejected(jams_server):
    reply = mail_from_reply("MAIL FROM:   ")
    assert reply.startswith(b"501"), f"a blank reverse path must stay an error, got {reply!r}"


def test_mail_with_no_from_keyword_still_rejected(jams_server):
    reply = mail_from_reply("MAIL")
    assert reply.startswith(b"501"), f"MAIL without FROM: must stay an error, got {reply!r}"


def test_missing_argument_after_null_sender_accepted(jams_server):
    # The two forms must not be confused in either direction within one session.
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n")
        recv_until(s, b"250 ")

        s.sendall(b"MAIL FROM:\r\n")
        assert s.recv(1024).startswith(b"501")

        s.sendall(b"MAIL FROM:<>\r\n")
        assert s.recv(1024).startswith(b"250")

        s.sendall(b"RSET\r\n")
        assert s.recv(1024).startswith(b"250")

        s.sendall(b"MAIL FROM:   \r\n")
        assert s.recv(1024).startswith(b"501")
