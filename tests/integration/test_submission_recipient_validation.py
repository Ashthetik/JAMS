# tests/integration/test_submission_recipient_validation.py
import base64, os, re, socket, ssl, subprocess, uuid, pytest

SUBMISSION_PORT = 2587

def mailroot():
    text = open(os.environ["JAMS_CONFIG"]).read()
    return re.search(r'^\s*mailroot\s*=\s*"([^"]+)"', text, re.M).group(1).rstrip("/")

def db_path():
    text = open(os.environ["JAMS_CONFIG"]).read()
    return re.search(r'^\s*dbpath\s*=\s*"([^"]+)"', text, re.M).group(1)

def recv_until(s, marker, timeout=10):
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

def submission_session():
    raw = socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=10)
    recv_until(raw, b"\r\n")
    raw.sendall(b"EHLO client.test\r\n"); recv_until(raw, b"250 ")
    raw.sendall(b"STARTTLS\r\n"); recv_until(raw, b"220")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    s.sendall(b"EHLO client.test\r\n"); recv_until(s, b"250 ")
    s.sendall(b"AUTH PLAIN " + base64.b64encode(b"\0ci-test-user\0ci-test-password") + b"\r\n")

    if b"235" not in recv_until(s, b"\r\n"):
        s.close()
        pytest.skip("no seeded test user available to log in with")

    return s

def rcpt(s, address):
    """MAIL FROM + one RCPT TO. Stops there: nothing is ever dialed out."""
    s.sendall(b"MAIL FROM:<ci-test-user@test.local>\r\n"); recv_until(s, b"\r\n")
    s.sendall(f"RCPT TO:<{address}>\r\n".encode())
    return recv_until(s, b"\r\n")

def mailbox_exists(user):
    # The server runs as root and Maildirs are 0700, so ask root
    path = os.path.join(mailroot(), user)
    return subprocess.run(["sudo", "-n", "test", "-d", path], capture_output=True).returncode == 0

def add_alias(alias, username):
    insert = (
        "import sqlite3, sys, time; db = sqlite3.connect(sys.argv[1]); "
        "db.execute('INSERT OR REPLACE INTO aliases (alias, username, active, created_at) VALUES (?, ?, 1, ?)', "
        "(sys.argv[2], sys.argv[3], int(time.time()))); db.commit()"
    )
    subprocess.run(["sudo", "-n", "python3", "-c", insert, db_path(), alias, username], check=True)

def test_unknown_local_recipient_is_refused_and_gets_no_mailbox(jams_server):
    """
    Port 25 refuses a local address with no account (#86). Port 587 used to accept it
    and create a brand new Maildir for it, so a typo was swallowed with no bounce and
    any logged-in user could spray mailboxes onto the disk.
    """
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        pytest.skip("needs passwordless sudo to look inside root-owned Maildirs")

    ghost = "ghostuser42-" + uuid.uuid4().hex[:8]
    assert not mailbox_exists(ghost), "test picked a name that already has a mailbox"

    with submission_session() as s:
        reply = rcpt(s, f"{ghost}@test.local")

        # If the recipient was accepted, finish the message so the mailbox it creates shows up
        if reply.startswith(b"250"):
            s.sendall(b"DATA\r\n"); recv_until(s, b"354")
            s.sendall(b"From: <ci-test-user@test.local>\r\nSubject: ghost\r\n\r\nhello\r\n.\r\n")
            recv_until(s, b"\r\n")

    created = mailbox_exists(ghost)

    assert reply.startswith(b"550"), (
        f"mail for a local user that does not exist was accepted: {reply!r} "
        f"(mailbox created on disk: {created})"
    )
    assert b"5.1.1" in reply, f"expected the same 5.1.1 port 25 sends, got {reply!r}"
    assert not created, f"a mailbox was created for {ghost}, who has no account"

@pytest.mark.parametrize("destination", [
    "127.0.0.2",      # dotted quad, the form the pentest used
    "127.1",          # short form, getaddrinfo() still reads this as 127.0.0.1
    "2130706433",     # the same address as a plain integer
    "0x7f000001",     # and as hex
])
def test_bare_ip_recipient_is_refused(jams_server, destination):
    """
    A bare IP as the recipient domain let an authenticated user choose which address
    the server opens a port 25 connection to, internal ones included.
    """
    with submission_session() as s:
        reply = rcpt(s, f"x@{destination}")

    assert reply.startswith(b"550"), f"RCPT TO:<x@{destination}> was accepted as a relay destination: {reply!r}"

@pytest.mark.parametrize("destination", [
    "[127.0.0.2]",    # RFC 5321 address literal
    "[IPv6:::1]",
    "::1",            # bare IPv6
])
def test_address_literal_recipient_is_refused(jams_server, destination):
    with submission_session() as s:
        reply = rcpt(s, f"x@{destination}")

    assert reply.startswith(b"550"), f"RCPT TO:<x@{destination}> was accepted as a relay destination: {reply!r}"

@pytest.mark.parametrize("destination", ["friend@example.com", "friend@localhost"])
def test_external_hostname_recipient_is_still_accepted(jams_server, destination):
    # The legitimate relay path from #88. "localhost" is a hostname, not an IP literal,
    # and the async relay tests rely on it resolving and relaying
    with submission_session() as s:
        reply = rcpt(s, destination)

    assert reply.startswith(b"250"), f"a real external recipient was refused: {reply!r}"

def test_existing_local_recipient_is_still_accepted(jams_server):
    with submission_session() as s:
        reply = rcpt(s, "ci-test-user@test.local")

    assert reply.startswith(b"250"), f"a real local recipient was refused: {reply!r}"

def test_alias_recipient_is_still_accepted(jams_server):
    # An alias has no user row of its own, so the existence check must not swallow it
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        pytest.skip("needs passwordless sudo to add an alias to the server's database")

    alias = "rcpt-validation-alias@test.local"
    add_alias(alias, "ci-test-user")

    with submission_session() as s:
        reply = rcpt(s, alias)

    assert reply.startswith(b"250"), f"an active alias was refused on 587: {reply!r}"
