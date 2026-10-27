# tests/integration/test_smtp_recipients.py
import socket, os, glob

SMTP_PORT = 2525
MAILROOT = "/tmp/jams/mail"

def rcpt_reply(rcpt):
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n"); s.recv(1024)
        s.sendall(b"MAIL FROM:<sender@elsewhere.test>\r\n"); s.recv(1024)
        s.sendall(f"RCPT TO:<{rcpt}>\r\n".encode())
        return s.recv(1024)

def deliver(rcpt, body):
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n"); s.recv(1024)
        s.sendall(b"MAIL FROM:<sender@elsewhere.test>\r\n"); s.recv(1024)
        s.sendall(f"RCPT TO:<{rcpt}>\r\n".encode())
        if b"250" not in s.recv(1024):
            return False
        s.sendall(b"DATA\r\n"); s.recv(1024)
        s.sendall(f"Subject: recipients test\r\n\r\n{body}\r\n.\r\n".encode())
        return b"250" in s.recv(1024)

def mailbox_contains(user, marker):
    for path in glob.glob(os.path.join(MAILROOT, user, "new", "*")) + glob.glob(os.path.join(MAILROOT, user, "cur", "*")):
        with open(path, errors="ignore") as f:
            if marker in f.read():
                return True
    return False

def test_foreign_domain_is_relaying_denied(jams_server):
    reply = rcpt_reply("ci-test-user@gmail.com")
    assert reply.startswith(b"550") and b"5.7.1" in reply, f"foreign domain should be refused, got {reply!r}"

def test_foreign_domain_not_delivered_by_local_part(jams_server):
    # bob@gmail.com must never land in local bob's inbox
    assert not deliver("ci-test-user@gmail.com", "should-not-arrive-foreign")
    assert not mailbox_contains("ci-test-user", "should-not-arrive-foreign")

def test_unknown_local_user_is_refused(jams_server):
    reply = rcpt_reply("no-such-user-42@test.local")
    assert reply.startswith(b"550") and b"5.1.1" in reply, f"unknown user should be refused, got {reply!r}"
    assert not os.path.exists(os.path.join(MAILROOT, "no-such-user-42")), "a Maildir was created for an unknown recipient"

def test_known_user_still_receives(jams_server):
    assert deliver("ci-test-user@test.local", "known-user-delivery-marker")
    assert mailbox_contains("ci-test-user", "known-user-delivery-marker")

def test_domain_match_is_case_insensitive(jams_server):
    assert rcpt_reply("ci-test-user@TEST.Local").startswith(b"250")

def test_bare_local_part_is_treated_as_local(jams_server):
    assert rcpt_reply("ci-test-user").startswith(b"250")

def test_multiple_at_signs_rejected(jams_server):
    assert rcpt_reply("ci-test-user@evil.test@test.local").startswith(b"501")
