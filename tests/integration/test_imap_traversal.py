# tests/integration/test_imap_traversal.py
import socket, os, pytest

IMAP_PORT = 2143
SMTP_PORT = 2525
MAILROOT = "/tmp/jams/mail"
VICTIM = "traversal-victim"

def recv_until(s, marker, timeout=5):
    s.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def deliver_to_victim():
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n"); s.recv(1024)
        s.sendall(b"MAIL FROM:<sender@test.local>\r\n"); s.recv(1024)
        s.sendall(f"RCPT TO:<{VICTIM}@test.local>\r\n".encode()); s.recv(1024)
        s.sendall(b"DATA\r\n"); s.recv(1024)
        s.sendall(b"Subject: private\r\n\r\nvictim-only-secret\r\n.\r\n"); s.recv(1024)

@pytest.fixture
def imap_session(jams_server):
    s = socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5)
    s.recv(1024)
    s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n")
    reply = recv_until(s, b"a1 ")

    if b"a1 OK" not in reply:
        s.close()
        pytest.skip("no seeded test user available to log in with")

    yield s
    s.close()

@pytest.mark.parametrize("mailbox", [
    f"/../{VICTIM}",
    f"./../{VICTIM}",
    f"../{VICTIM}",
    "..",
    "cur",
])
def test_select_cannot_escape_own_mailbox(imap_session, mailbox):
    deliver_to_victim()

    imap_session.sendall(f'b1 SELECT "{mailbox}"\r\n'.encode())
    reply = recv_until(imap_session, b"b1 ")

    assert b"b1 NO" in reply, f"SELECT {mailbox!r} should be refused, got {reply!r}"

    imap_session.sendall(b"b2 FETCH 1 BODY[]\r\n")
    reply = recv_until(imap_session, b"b2 ")
    assert b"victim-only-secret" not in reply, "read another user's mail through SELECT traversal"

def test_append_cannot_plant_in_other_mailbox(imap_session):
    deliver_to_victim()
    before = set(os.listdir(os.path.join(MAILROOT, VICTIM, "cur"))) if os.path.isdir(os.path.join(MAILROOT, VICTIM, "cur")) else set()

    message = b"Subject: planted\r\n\r\nplanted\r\n"
    imap_session.sendall(f'c1 APPEND "/../{VICTIM}" {{{len(message)}}}\r\n'.encode())
    reply = recv_until(imap_session, b"c1 ", timeout=3)

    # The server must refuse before asking for the literal
    assert b"c1 NO" in reply and b"+ " not in reply, f"APPEND traversal should be refused, got {reply!r}"

    after = set(os.listdir(os.path.join(MAILROOT, VICTIM, "cur"))) if os.path.isdir(os.path.join(MAILROOT, VICTIM, "cur")) else set()
    assert after == before, "a message was planted in another user's mailbox"

def test_create_cannot_escape_mailroot(imap_session):
    probe = "jams-traversal-probe"

    imap_session.sendall(f'd1 CREATE "/../../{probe}"\r\n'.encode())
    reply = recv_until(imap_session, b"d1 ")

    assert b"d1 NO" in reply, f"CREATE traversal should be refused, got {reply!r}"
    assert not os.path.exists(os.path.join(os.path.dirname(MAILROOT), probe)), "CREATE made a directory outside the mail root"

def test_normal_folders_still_work(imap_session):
    imap_session.sendall(b'e1 CREATE "Receipts 2026"\r\n')
    assert b"e1 OK" in recv_until(imap_session, b"e1 ")

    imap_session.sendall(b'e2 SELECT "Receipts 2026"\r\n')
    assert b"e2 OK" in recv_until(imap_session, b"e2 ")

    imap_session.sendall(b"e3 SELECT inbox\r\n")
    assert b"e3 OK" in recv_until(imap_session, b"e3 ")
