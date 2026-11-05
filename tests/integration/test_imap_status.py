# tests/integration/test_imap_status.py
import re, socket, ssl, uuid, pytest

IMAP_PORT = 2143

def recv_until(s, marker, timeout=5):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = s.recv(4096)
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

    def cmd(self, line, timeout=5):
        self.n += 1
        tag = f"s{self.n:03d}"
        self.s.sendall(f"{tag} {line}\r\n".encode())
        return self.wait(tag, timeout)

    def wait(self, tag, timeout=5):
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

    def append(self, mailbox, message, flags=None):
        self.n += 1
        tag = f"s{self.n:03d}"
        prefix = f"{tag} APPEND {mailbox} "
        if flags:
            prefix += f"({flags}) "
        self.s.sendall((prefix + f"{{{len(message)}}}\r\n").encode())
        assert b"+ " in recv_until(self.s, b"+ ")
        self.s.sendall(message + b"\r\n")
        assert f"{tag} OK".encode() in self.wait(tag)

    def select(self, mailbox):
        reply = self.cmd(f"SELECT {mailbox}")
        assert b" OK" in reply.splitlines()[-1], f"SELECT {mailbox} failed: {reply!r}"
        return {
            "exists": int(re.search(rb"\* (\d+) EXISTS", reply).group(1)),
            "uidvalidity": int(re.search(rb"UIDVALIDITY (\d+)", reply).group(1)),
            "uidnext": int(re.search(rb"UIDNEXT (\d+)", reply).group(1)),
        }

    def uids(self):
        reply = self.cmd("FETCH 1:* (UID)")
        return {int(m.group(1)): int(m.group(2)) for m in re.finditer(rb"\* (\d+) FETCH \(UID (\d+)\)", reply)}

    def status(self, mailbox, items="(MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)"):
        reply = self.cmd(f"STATUS {mailbox} {items}")
        assert b" OK" in reply.splitlines()[-1], f"STATUS {mailbox} failed: {reply!r}"
        return parse_status(reply, mailbox), reply

def parse_status(reply, mailbox):
    m = re.search(rb"\* STATUS " + re.escape(mailbox.encode()) + rb" \(([^)]*)\)", reply)
    assert m, f"no untagged STATUS line for {mailbox} in {reply!r}"
    parts = m.group(1).split()
    assert len(parts) % 2 == 0, f"odd STATUS item list: {m.group(1)!r}"
    return {parts[i].decode(): int(parts[i + 1]) for i in range(0, len(parts), 2)}

def open_session():
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

@pytest.fixture
def imap(jams_server):
    session = open_session()
    yield session
    session.s.close()

def make_folder(imap, messages, seen=0):
    # A private mailbox per test, so the counts are exact rather than cumulative
    name = "st" + uuid.uuid4().hex[:10]

    # CREATE can't make a folder for an account that has never had mail, so touch INBOX first
    imap.append("INBOX", b"Subject: seed\r\n\r\nseed\r\n", flags="\\Seen")
    assert b" OK" in imap.cmd(f"CREATE {name}")

    for i in range(messages):
        imap.append(
            name,
            b"Subject: msg-" + str(i).encode() + b"\r\n\r\nbody-" + str(i).encode() + b"\r\n",
            flags="\\Seen" if i < seen else None,
        )

    return name

def test_status_reports_the_real_counts_of_the_folder_it_names(imap):
    # Three messages, the first of them already \Seen
    folder = make_folder(imap, messages=3, seen=1)

    # INBOX is shared with every other test in the session, so work from its own baseline
    baseline = imap.select("INBOX")["exists"]

    for i in range(2):
        imap.append("INBOX", b"Subject: inbox-" + str(i).encode() + b"\r\n\r\ninbox body\r\n")

    inbox, _ = imap.status("INBOX")
    assert inbox["MESSAGES"] == baseline + 2, f"STATUS INBOX reported {inbox}"

    other, _ = imap.status(folder)
    assert other["MESSAGES"] == 3, f"STATUS {folder} reported {other}"
    assert other["UNSEEN"] == 2, f"STATUS {folder} reported {other}"
    assert other["RECENT"] == 0, f"STATUS {folder} reported {other}"
    assert other["UIDVALIDITY"] > 0, f"STATUS {folder} reported {other}"

    # UIDNEXT has to sit above every UID handed out, and move when mail arrives
    assert other["UIDNEXT"] == 4, f"STATUS {folder} reported {other}"

    imap.append(folder, b"Subject: one-more\r\n\r\none more\r\n")

    after, _ = imap.status(folder)
    assert after["MESSAGES"] == 4, f"STATUS {folder} reported {after}"
    assert after["UNSEEN"] == 3, f"STATUS {folder} reported {after}"
    assert after["UIDNEXT"] == 5, f"STATUS {folder} reported {after}"
    assert after["UIDVALIDITY"] == other["UIDVALIDITY"], f"UIDVALIDITY moved: {other} -> {after}"

    # And STATUS has to agree with what SELECT then shows
    opened = imap.select(folder)
    assert opened["exists"] == after["MESSAGES"]
    assert opened["uidnext"] == after["UIDNEXT"]
    assert opened["uidvalidity"] == after["UIDVALIDITY"]

def test_status_on_another_folder_leaves_the_selected_one_alone(imap):
    folder = make_folder(imap, messages=2)

    marker = uuid.uuid4().hex
    imap.append("INBOX", b"Subject: marker-" + marker.encode() + b"\r\n\r\nmarker\r\n")

    before = imap.select("INBOX")
    uids_before = imap.uids()
    assert uids_before, "INBOX should hold at least the marker message"

    counts, reply = imap.status(folder)

    # The other folder's numbers, not the selected mailbox's
    assert counts["MESSAGES"] == 2, f"STATUS {folder} reported {counts} while INBOX was selected"

    # STATUS must not narrate the other folder as if it were open
    assert b"EXISTS" not in reply, f"STATUS emitted EXISTS: {reply!r}"
    assert not re.search(rb"\* \d+ (EXISTS|RECENT)", reply), f"STATUS renumbered the session: {reply!r}"

    # The selected mailbox is untouched: same messages, same UIDs, FETCH still answers
    assert imap.uids() == uids_before, "STATUS changed the selected mailbox's view"

    last_seq = max(uids_before)
    fetched = imap.cmd(f"FETCH {last_seq} (UID)")
    assert f"* {last_seq} FETCH".encode() in fetched, f"FETCH after STATUS broke: {fetched!r}"
    assert f"UID {uids_before[last_seq]}".encode() in fetched, f"FETCH after STATUS broke: {fetched!r}"

    again = imap.select("INBOX")
    assert again["exists"] == before["exists"]
    assert again["uidvalidity"] == before["uidvalidity"]

def test_status_returns_only_the_items_asked_for_in_order(imap):
    folder = make_folder(imap, messages=1)

    reply = imap.cmd(f"STATUS {folder} (UIDNEXT MESSAGES)")
    assert b" OK" in reply.splitlines()[-1], f"STATUS failed: {reply!r}"

    line = re.search(rb"\* STATUS " + folder.encode() + rb" \(([^)]*)\)", reply)
    assert line, f"no untagged STATUS line: {reply!r}"
    assert line.group(1) == b"UIDNEXT 2 MESSAGES 1", f"STATUS answered {line.group(1)!r}"

    bad_item = imap.cmd(f"STATUS {folder} (MESSAGES NOSUCHITEM)")
    assert b" BAD" in bad_item.splitlines()[-1], f"unknown STATUS item was accepted: {bad_item!r}"

def test_status_refuses_a_folder_that_does_not_exist(imap):
    make_folder(imap, messages=1)

    missing = "nope" + uuid.uuid4().hex[:10]
    reply = imap.cmd(f"STATUS {missing} (MESSAGES UIDNEXT)")
    assert b" NO" in reply.splitlines()[-1], f"STATUS on a missing folder answered {reply!r}"
    assert b"* STATUS" not in reply, f"STATUS on a missing folder still reported counts: {reply!r}"
