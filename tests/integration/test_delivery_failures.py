# tests/integration/test_delivery_failures.py
import base64, os, re, socket, ssl, subprocess, pytest

SMTP_PORT = 2525
SUBMISSION_PORT = 2587
BLOCKED_USER = "delivery-fail-user"
ALIAS = "failing-alias@test.local"

def mailroot():
    text = open(os.environ["JAMS_CONFIG"]).read()
    return re.search(r'^\s*mailroot\s*=\s*"([^"]+)"', text, re.M).group(1).rstrip("/")

def db_path():
    text = open(os.environ["JAMS_CONFIG"]).read()
    return re.search(r'^\s*dbpath\s*=\s*"([^"]+)"', text, re.M).group(1)

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

def send_port25(rcpt):
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=10) as s:
        recv_line(s)
        s.sendall(b"EHLO test.local\r\n")
        ehlo = b""
        while b"250 " not in ehlo:
            chunk = recv_line(s, timeout=5)
            if not chunk:
                break
            ehlo += chunk
        for line in (b"MAIL FROM:<sender@example.com>", f"RCPT TO:<{rcpt}>".encode(), b"DATA"):
            s.sendall(line + b"\r\n")
            reply = recv_line(s)
            assert reply[:1] in (b"2", b"3"), f"{line!r} was refused: {reply!r}"
        s.sendall(b"Subject: delivery failure test\r\n\r\nhello\r\n.\r\n")
        return recv_line(s)

@pytest.fixture
def blocked_mailbox(jams_server):
    # A regular file where the user's Maildir should be: creating cur/new/tmp under it
    # fails even for root, which is how the server runs in CI
    path = os.path.join(mailroot(), BLOCKED_USER)
    if os.path.isdir(path):
        pytest.skip(f"{path} already exists as a real mailbox")
    with open(path, "w") as f:
        f.write("not a maildir\n")
    yield path
    os.remove(path)

def test_failed_delivery_on_port_25_is_not_a_250(blocked_mailbox):
    reply = send_port25(f"{BLOCKED_USER}@test.local")
    assert not reply.startswith(b"250"), "the message wasn't stored, but the sender was told it was"
    assert reply.startswith(b"4"), f"a storage failure should be a temporary failure: {reply!r}"

def test_failed_delivery_on_587_is_not_a_250(blocked_mailbox):
    raw = socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=10)
    recv_line(raw)
    raw.sendall(b"EHLO client.test\r\n"); raw.recv(4096)
    raw.sendall(b"STARTTLS\r\n"); recv_line(raw)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    try:
        s.sendall(b"EHLO client.test\r\n"); s.recv(4096)
        s.sendall(b"AUTH PLAIN " + base64.b64encode(b"\0ci-test-user\0ci-test-password") + b"\r\n")
        if b"235" not in recv_line(s):
            pytest.skip("no seeded test user available to log in with")

        s.sendall(b"MAIL FROM:<ci-test-user@test.local>\r\n"); recv_line(s)
        s.sendall(f"RCPT TO:<{BLOCKED_USER}@test.local>\r\n".encode())
        assert recv_line(s).startswith(b"250")
        s.sendall(b"DATA\r\n"); recv_line(s)
        s.sendall(b"From: <ci-test-user@test.local>\r\nSubject: x\r\n\r\nhello\r\n.\r\n")
        reply = recv_line(s)
        assert reply.startswith(b"4"), f"the message wasn't stored, but 587 answered {reply!r}"
    finally:
        s.close()

def test_failed_delivery_through_an_alias(blocked_mailbox):
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        pytest.skip("needs passwordless sudo to add an alias to the server's database")

    add_alias(ALIAS, BLOCKED_USER)

    reply = send_port25(ALIAS)
    assert reply.startswith(b"4"), f"delivery through an alias to a broken mailbox answered {reply!r}"

    # And nothing fell over on the way (the alias purge used to get a path that was never stored)
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=5) as s:
        assert recv_line(s).startswith(b"220")

def test_normal_delivery_still_works(jams_server):
    assert send_port25("ci-test-user@test.local").startswith(b"250")

def add_alias(alias, username):
    insert = (
        "import sqlite3, sys, time; db = sqlite3.connect(sys.argv[1]); "
        "db.execute('INSERT OR REPLACE INTO aliases (alias, username, active, created_at) VALUES (?, ?, 1, ?)', "
        "(sys.argv[2], sys.argv[3], int(time.time()))); db.commit()"
    )
    subprocess.run(["sudo", "-n", "python3", "-c", insert, db_path(), alias, username], check=True)

def inbox_count(user, password):
    raw = socket.create_connection(("127.0.0.1", 2143), timeout=10)
    recv_line(raw)
    raw.sendall(b"t1 STARTTLS\r\n"); recv_line(raw)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    try:
        s.sendall(f"a1 LOGIN {user} {password}\r\n".encode())
        if b"a1 OK" not in recv_line(s):
            pytest.skip(f"couldn't log in as {user}")
        s.sendall(b"a2 SELECT INBOX\r\n")
        data = b""
        while b"a2 " not in data:
            chunk = recv_line(s)
            if not chunk:
                break
            data += chunk
        return int(re.search(rb"\* (\d+) EXISTS", data).group(1))
    finally:
        s.close()

def test_alias_delivers_to_its_own_target(jams_server):
    # Port 25 used to cut the resolved username at the position of '@' in the alias,
    # so "ci@test.local" -> "ci-test-user" was delivered to a mailbox called "ci"
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        pytest.skip("needs passwordless sudo to add an alias to the server's database")

    add_alias("ci@test.local", "ci-test-user")
    before = inbox_count("ci-test-user", "ci-test-password")

    assert send_port25("ci@test.local").startswith(b"250")
    assert inbox_count("ci-test-user", "ci-test-password") == before + 1, "the alias's mail went to some other mailbox"

def test_session_carries_on_after_a_failed_delivery(blocked_mailbox):
    # After the 452 the session must be back in command mode, not still reading message text
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=10) as s:
        recv_line(s)
        s.sendall(b"EHLO test.local\r\n")
        ehlo = b""
        while b"250 " not in ehlo:
            chunk = recv_line(s, timeout=5)
            if not chunk:
                break
            ehlo += chunk

        for line in (b"MAIL FROM:<sender@example.com>", f"RCPT TO:<{BLOCKED_USER}@test.local>".encode(), b"DATA"):
            s.sendall(line + b"\r\n"); recv_line(s)
        s.sendall(b"Subject: x\r\n\r\nhello\r\n.\r\n")
        assert recv_line(s).startswith(b"4")

        s.sendall(b"NOOP\r\n")
        assert recv_line(s).startswith(b"250"), "after a failed delivery the session was still in DATA mode"
