# tests/integration/test_imap_store_flags.py
import re, socket, ssl, uuid, pytest

IMAP_PORT = 2143

# Mirrors the live proof: a few messages in a mailbox, then a loop of
# STORE 1:* +FLAGS with a multi-kilobyte payload that is not a flag.
ROUNDS = 20
JUNK_SIZE = 4000

def recv_until(s, marker, timeout=5):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data

class Imap:
    def __init__(self, sock):
        self.s = sock
        self.n = 0

    def cmd(self, line, timeout=15):
        self.n += 1
        tag = f"s{self.n:03d}"
        self.s.sendall(f"{tag} {line}\r\n".encode())
        return self.wait(tag, timeout)

    def wait(self, tag, timeout=15):
        done = re.compile(rb"(?:^|\r\n)" + tag.encode() + rb" (OK|NO|BAD)[^\r\n]*\r\n")
        self.s.settimeout(timeout)
        data = b""
        try:
            while not done.search(data):
                chunk = self.s.recv(65536)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data

    def append(self, mailbox, message):
        self.n += 1
        tag = f"s{self.n:03d}"
        self.s.sendall(f"{tag} APPEND {mailbox} {{{len(message)}}}\r\n".encode())
        assert b"+ " in recv_until(self.s, b"+ ")
        self.s.sendall(message + b"\r\n")
        assert f"{tag} OK".encode() in self.wait(tag)

    def select(self, mailbox):
        reply = self.cmd(f"SELECT {mailbox}")
        assert b" OK" in reply.splitlines()[-1], f"SELECT {mailbox} failed: {reply!r}"
        return reply

def open_session():
    # Plaintext LOGIN is refused, so upgrade with STARTTLS first
    raw = socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5)
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n")
    recv_until(raw, b"t1 ")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")

    s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n")
    if b"a1 OK" not in recv_until(s, b"a1 "):
        s.close()
        pytest.skip("no seeded test user available to log in with")

    return Imap(s)

def flags_of(imap, seq=1):
    reply = imap.cmd(f"FETCH {seq} (FLAGS)")
    m = re.search(rb"\* " + str(seq).encode() + rb" FETCH \(FLAGS \(([^)]*)\)\)", reply)
    assert m, f"no FLAGS in FETCH reply: {reply[:200]!r}"
    return m.group(1)

@pytest.fixture
def imap(jams_server):
    session = open_session()
    yield session
    session.s.close()

@pytest.fixture
def box(imap):
    # A private mailbox per test with three messages in it
    name = "store" + uuid.uuid4().hex[:10]

    # CREATE can't make a folder for an account that has never had mail, so make sure INBOX exists first
    imap.append("INBOX", b"Subject: seed\r\n\r\nseed\r\n")
    assert b" OK" in imap.cmd(f"CREATE {name}")
    for label in (b"first", b"second", b"third"):
        imap.append(name, b"Subject: " + label + b"\r\n\r\nbody-" + label + b"\r\n")
    imap.select(name)
    return name

def test_store_refuses_junk_flags_and_keeps_the_flag_string_bounded(imap, box):
    # Every round sends ~4 KB that is not a flag. The server must refuse it
    # instead of appending it to the message and reading it back out again.
    replies = []
    for n in range(ROUNDS):
        junk = f"junk{n:04d}" + "A" * JUNK_SIZE
        replies.append(imap.cmd(f"STORE 1:* +FLAGS ({junk})"))

    accepted = [n for n, r in enumerate(replies) if b" OK STORE completed" in r]
    first, last = len(replies[0]), len(replies[-1])
    stored = flags_of(imap, 1)

    assert not accepted, (
        f"server accepted junk as a flag in {len(accepted)} of {ROUNDS} rounds; "
        f"reply grew {first} -> {last} bytes and message 1 now carries {len(stored)} bytes of flags"
    )

    # Nothing was stored, so round N must not be meaningfully bigger than round 1
    assert last <= first + 256, f"STORE reply grew from {first} to {last} bytes over {ROUNDS} rounds"

    # And the flag string on disk stayed short
    assert len(stored) < 256, f"message 1 carries {len(stored)} bytes of flags: {stored[:120]!r}"

def test_store_still_accepts_real_flags(imap, box):
    # The fix must not break clients that send flags the way they are supposed to
    reply = imap.cmd("STORE 1 +FLAGS (\\Seen)")
    assert reply.splitlines()[-1].endswith(b"OK STORE completed"), f"plain \\Seen was refused: {reply!r}"
    assert b"\\Seen" in flags_of(imap, 1)

    # Several at once, a keyword, lowercase, and .SILENT
    assert b" OK" in imap.cmd("STORE 2 +FLAGS (\\Flagged \\answered $Forwarded)")
    second = flags_of(imap, 2)
    for expected in (b"\\Flagged", b"\\answered", b"$Forwarded"):
        assert expected in second, f"{expected!r} missing from {second!r}"

    assert b" OK" in imap.cmd("STORE 3 +FLAGS.SILENT (\\Deleted)")
    assert b"\\Deleted" in flags_of(imap, 3)

    # Replace and remove still work
    assert b" OK" in imap.cmd("STORE 1 FLAGS (\\Draft)")
    assert flags_of(imap, 1) == b"\\Draft"
    assert b" OK" in imap.cmd("STORE 1 -FLAGS (\\Draft)")
    assert flags_of(imap, 1) == b""
