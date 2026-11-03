# tests/integration/test_aliases.py
#
# A self-destructing alias used to spend its uses at RCPT, before any message
# existed, so anyone who knew the address could burn it without sending mail.
# These cover where the use is spent now: once, and only on a stored message.
import base64, os, re, socket, ssl, subprocess, pytest

SMTP_PORT = 2525
SUBMISSION_PORT = 2587
IMAP_PORT = 2143

TARGET_USER = "ci-test-user"
TARGET_PASS = "ci-test-password"
BLOCKED_USER = "delivery-fail-user"


def _config_value(key):
    text = open(os.environ["JAMS_CONFIG"]).read()
    return re.search(r'^\s*%s\s*=\s*"([^"]+)"' % key, text, re.M).group(1)


def mailroot():
    return _config_value("mailroot").rstrip("/")


def db_path():
    return _config_value("dbpath")


def need_sudo():
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        pytest.skip("needs passwordless sudo to reach the server's database")


_SEED = (
    "import sqlite3, sys, time\n"
    "db = sqlite3.connect(sys.argv[1], timeout=20)\n"
    "alias, user, max_uses = sys.argv[2], sys.argv[3], sys.argv[4]\n"
    "db.execute('DELETE FROM alias_allowed_domains WHERE alias = ?', (alias,))\n"
    "db.execute('DELETE FROM aliases WHERE alias = ?', (alias,))\n"
    "db.execute('INSERT INTO aliases (alias, username, active, max_uses, uses_count, expires_at, created_at)'\n"
    "           ' VALUES (?, ?, 1, ?, 0, NULL, ?)',\n"
    "           (alias, user, None if max_uses == 'none' else int(max_uses), int(time.time())))\n"
    "for domain in sys.argv[5:]:\n"
    "    db.execute('INSERT INTO alias_allowed_domains (alias, domain) VALUES (?, ?)', (alias, domain))\n"
    "db.commit()\n"
)

_READ = (
    "import sqlite3, sys\n"
    "db = sqlite3.connect(sys.argv[1], timeout=20)\n"
    "row = db.execute('SELECT active, max_uses, uses_count FROM aliases WHERE alias = ?', (sys.argv[2],)).fetchone()\n"
    "print(row[0], row[1], row[2])\n"
)


def seed_alias(alias, user=TARGET_USER, max_uses="none", allowed_domains=()):
    subprocess.run(
        ["sudo", "-n", "python3", "-c", _SEED, db_path(), alias, user, str(max_uses), *allowed_domains],
        check=True, capture_output=True, text=True
    )


def alias_row(alias):
    out = subprocess.run(
        ["sudo", "-n", "python3", "-c", _READ, db_path(), alias],
        check=True, capture_output=True, text=True
    ).stdout.split()
    return {"active": int(out[0]), "uses_count": int(out[2])}


def uses_of(alias):
    return alias_row(alias)["uses_count"]


def recv_line(s, timeout=10):
    s.settimeout(timeout)
    data = b""
    try:
        while not data.endswith(b"\r\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ssl.SSLError, OSError):
        pass
    return data


def read_ehlo(s):
    # Multi-line replies arrive in one chunk, so look for "250 " anywhere
    data = b""
    while b"250 " not in data:
        chunk = recv_line(s, timeout=5)
        if not chunk:
            break
        data += chunk
    return data


def port25_rcpt_then_quit(rcpt, sender="outsider@example.net"):
    """Name a recipient and hang up. No DATA, no message, ever."""
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=10) as s:
        recv_line(s)
        s.sendall(b"EHLO probe.test\r\n")
        read_ehlo(s)
        s.sendall(f"MAIL FROM:<{sender}>\r\n".encode())
        recv_line(s)
        s.sendall(f"RCPT TO:<{rcpt}>\r\n".encode())
        reply = recv_line(s)
        s.sendall(b"QUIT\r\n")
        recv_line(s)
        return reply


def port25_send(rcpts, sender="outsider@example.net", body="Subject: alias test\r\n\r\nhello"):
    if isinstance(rcpts, str):
        rcpts = [rcpts]
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=20) as s:
        recv_line(s)
        s.sendall(b"EHLO probe.test\r\n")
        read_ehlo(s)
        s.sendall(f"MAIL FROM:<{sender}>\r\n".encode())
        recv_line(s)
        for rcpt in rcpts:
            s.sendall(f"RCPT TO:<{rcpt}>\r\n".encode())
            reply = recv_line(s)
            if not reply.startswith(b"250"):
                return reply
        s.sendall(b"DATA\r\n")
        recv_line(s)
        s.sendall(body.encode() + b"\r\n.\r\n")
        return recv_line(s, timeout=20)


def submission_login():
    raw = socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=10)
    recv_line(raw)
    raw.sendall(b"EHLO client.test\r\n")
    raw.recv(4096)
    raw.sendall(b"STARTTLS\r\n")
    recv_line(raw)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    s.sendall(b"EHLO client.test\r\n")
    s.recv(4096)
    s.sendall(b"AUTH PLAIN " + base64.b64encode(b"\0%s\0%s" % (TARGET_USER.encode(), TARGET_PASS.encode())) + b"\r\n")
    if b"235" not in recv_line(s):
        s.close()
        pytest.skip("no seeded test user available to log in with")
    return s


def inbox_count(user, password):
    raw = socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=10)
    recv_line(raw)
    raw.sendall(b"t1 STARTTLS\r\n")
    recv_line(raw)
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


@pytest.fixture
def blocked_mailbox(jams_server):
    # A regular file where the Maildir should be: creating cur/new/tmp under it
    # fails even for root, which is how the server runs in CI
    path = os.path.join(mailroot(), BLOCKED_USER)
    if os.path.isdir(path):
        pytest.skip(f"{path} already exists as a real mailbox")
    with open(path, "w") as f:
        f.write("not a maildir\n")
    yield path
    os.remove(path)


# --------------------------------------------------------------- the bug itself

def test_rcpt_without_a_message_spends_nothing(jams_server):
    """N9: three RCPTs and three QUITs, no DATA. An unauthenticated stranger
    used to be able to burn every use of a one-time alias this way."""
    need_sudo()
    alias = "burn-me@test.local"
    seed_alias(alias, max_uses=3)

    for _ in range(3):
        assert port25_rcpt_then_quit(alias).startswith(b"250")

    row = alias_row(alias)
    assert row["uses_count"] == 0, "naming an alias as a recipient spent a use with no message"
    assert row["active"] == 1, "the alias was destroyed without a single message being sent"

    # And it still works afterwards
    assert port25_send(alias).startswith(b"250")
    assert uses_of(alias) == 1


def test_rcpt_without_a_message_spends_nothing_on_587(jams_server):
    """Same bug, submission port."""
    need_sudo()
    alias = "burn-me-587@test.local"
    seed_alias(alias, max_uses=3)

    s = submission_login()
    try:
        for _ in range(3):
            s.sendall(f"MAIL FROM:<{TARGET_USER}@test.local>\r\n".encode())
            recv_line(s)
            s.sendall(f"RCPT TO:<{alias}>\r\n".encode())
            assert recv_line(s).startswith(b"250")
            s.sendall(b"RSET\r\n")
            recv_line(s)
        s.sendall(b"QUIT\r\n")
        recv_line(s)
    finally:
        s.close()

    row = alias_row(alias)
    assert row["uses_count"] == 0, "587 spent a use at RCPT, before any message existed"
    assert row["active"] == 1


# --------------------------------------------------------------- what should spend

def test_a_delivered_message_spends_exactly_one_use(jams_server):
    need_sudo()
    alias = "spend-one@test.local"
    seed_alias(alias, max_uses=5)
    before = inbox_count(TARGET_USER, TARGET_PASS)

    assert port25_send(alias).startswith(b"250")

    assert inbox_count(TARGET_USER, TARGET_PASS) == before + 1, "the message never reached the mailbox"
    assert uses_of(alias) == 1


def test_the_same_alias_twice_in_one_message_spends_one_use(jams_server):
    need_sudo()
    alias = "spend-once@test.local"
    seed_alias(alias, max_uses=5)

    assert port25_send([alias, alias]).startswith(b"250")
    assert uses_of(alias) == 1, "one message named the alias twice and was charged twice"


def test_the_last_use_deactivates_the_alias(jams_server):
    need_sudo()
    alias = "one-shot@test.local"
    seed_alias(alias, max_uses=1)

    assert port25_send(alias).startswith(b"250")

    row = alias_row(alias)
    assert row["uses_count"] == 1
    assert row["active"] == 0, "the last use was spent but the alias stayed alive"

    assert port25_rcpt_then_quit(alias).startswith(b"550"), "a spent one-time alias still accepts mail"


def test_an_alias_with_no_limit_never_runs_out(jams_server):
    """NULL max_uses and NULL expires_at both mean unlimited."""
    need_sudo()
    alias = "unlimited@test.local"
    seed_alias(alias, max_uses="none")

    for expected in (1, 2, 3):
        assert port25_send(alias).startswith(b"250")
        assert uses_of(alias) == expected

    assert alias_row(alias)["active"] == 1, "an alias with no use limit was deactivated"


# --------------------------------------------------------------- refusals cost nothing

def test_a_failed_delivery_spends_no_use(blocked_mailbox):
    need_sudo()
    alias = "fails-to-store@test.local"
    seed_alias(alias, user=BLOCKED_USER, max_uses=3)

    reply = port25_send(alias)
    assert reply.startswith(b"4"), f"the message wasn't stored, but the sender was told {reply!r}"
    assert uses_of(alias) == 0, "a message that was never stored still cost the alias a use"
    assert alias_row(alias)["active"] == 1


def test_a_sender_the_allow_list_refuses_spends_no_use(jams_server):
    """H14's ordering half: the use used to be taken before is_domain_allowed ran,
    so a sender who was never allowed to write to the alias still burned it."""
    need_sudo()
    alias = "allow-listed@test.local"
    seed_alias(alias, max_uses=3, allowed_domains=("friends.example",))

    reply = port25_rcpt_then_quit(alias, sender="stranger@example.net")
    assert reply.startswith(b"550"), f"the allow-list let a stranger through: {reply!r}"
    assert uses_of(alias) == 0, "a recipient the allow-list refused still cost a use"

    # The allowed sender still gets through, and that one does spend
    assert port25_send(alias, sender="pal@friends.example").startswith(b"250")
    assert uses_of(alias) == 1
