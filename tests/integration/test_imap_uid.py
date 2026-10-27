# tests/integration/test_imap_uid.py
import re, socket, ssl, time, uuid, pytest

IMAP_PORT = 2143
SMTP_PORT = 2525

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
        tag = f"u{self.n:03d}"
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

    def append(self, mailbox, message):
        self.n += 1
        tag = f"u{self.n:03d}"
        self.s.sendall(f"{tag} APPEND {mailbox} {{{len(message)}}}\r\n".encode())
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
        # sequence number -> UID, for every message in the selected mailbox
        reply = self.cmd("FETCH 1:* (UID)")
        return {int(m.group(1)): int(m.group(2)) for m in re.finditer(rb"\* (\d+) FETCH \(UID (\d+)\)", reply)}

def open_session():
    # Plaintext LOGIN is refused once implicit TLS lands, so upgrade with STARTTLS first
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

def deliver_to_inbox(body):
    with socket.create_connection(("127.0.0.1", SMTP_PORT), timeout=5) as s:
        s.recv(1024)
        for line in (b"EHLO test.local", b"MAIL FROM:<sender@example.com>", b"RCPT TO:<ci-test-user@test.local>", b"DATA"):
            s.sendall(line + b"\r\n")
            reply = recv_until(s, b"\r\n")
            assert reply[:1] in (b"2", b"3"), f"{line!r} was refused: {reply!r}"
            if line == b"EHLO test.local":
                recv_until(s, b"250 ", timeout=1)
        s.sendall(b"Subject: uid test\r\n\r\n" + body + b"\r\n.\r\n")
        assert recv_until(s, b"\r\n")[:3] == b"250"
        s.sendall(b"QUIT\r\n")

@pytest.fixture
def imap(jams_server):
    session = open_session()
    yield session
    session.s.close()

@pytest.fixture
def box(imap):
    # A private mailbox per test with three messages appended in the same second
    name = "uid" + uuid.uuid4().hex[:10]

    # CREATE can't make a folder for an account that has never had mail, so make sure INBOX exists first
    imap.append("INBOX", b"Subject: seed\r\n\r\nseed\r\n")
    assert b" OK" in imap.cmd(f"CREATE {name}")
    for label in (b"first", b"second", b"third"):
        imap.append(name, b"Subject: " + label + b"\r\n\r\nbody-" + label + b"\r\n")
    imap.select(name)
    return name

def test_uid_store_flags_the_message_it_names(imap, box):
    uids = imap.uids()
    assert sorted(uids) == [1, 2, 3]

    reply = imap.cmd(f"UID STORE {uids[1]} +FLAGS (\\Deleted)")
    assert reply.splitlines()[-1].endswith(b"OK STORE completed")

    flags = imap.cmd("FETCH 1:* (FLAGS)")
    deleted = [int(m.group(1)) for m in re.finditer(rb"\* (\d+) FETCH \(FLAGS \(([^)]*)\)\)", flags) if b"\\Deleted" in m.group(2)]
    assert deleted == [1], f"UID STORE on message 1's UID flagged messages {deleted}"

    imap.cmd("EXPUNGE")
    remaining = imap.cmd("FETCH 1:* (BODY[])")
    assert b"body-first" not in remaining
    assert b"body-second" in remaining and b"body-third" in remaining, "EXPUNGE removed the wrong message"

def test_uid_fetch_returns_the_message_asked_for(imap, box):
    uids = imap.uids()
    reply = imap.cmd(f"UID FETCH {uids[1]} (BODY[])")

    assert b"body-first" in reply, f"UID FETCH of message 1's UID returned something else: {reply!r}"
    assert b"body-third" not in reply
    assert f"UID {uids[1]}".encode() in reply, "UID FETCH responses must carry the UID (RFC 3501 6.4.8)"

def test_uid_store_response_carries_the_uid(imap, box):
    uids = imap.uids()
    reply = imap.cmd(f"UID STORE {uids[2]} +FLAGS (\\Flagged)")
    assert re.search(rb"\* 2 FETCH \(FLAGS \([^)]*\) UID " + str(uids[2]).encode() + rb"\)", reply), reply

def test_uids_are_unique_and_ascending(imap, box):
    uids = imap.uids()
    values = [uids[seq] for seq in sorted(uids)]
    assert len(set(values)) == 3, f"messages delivered in the same second share UIDs: {values}"
    assert values == sorted(values), f"UIDs must rise with sequence numbers: {values}"

def test_numbers_with_no_message_match_nothing(imap, box):
    uids = imap.uids()
    reply = imap.cmd(f"UID FETCH {max(uids.values()) + 1000} (FLAGS)")
    assert b"FETCH (" not in reply, f"a UID that doesn't exist was answered with a real message: {reply!r}"

    reply = imap.cmd("FETCH 99 (FLAGS)")
    assert b"FETCH (" not in reply, f"sequence number 99 of 3 was clamped onto a real message: {reply!r}"

    reply = imap.cmd(f"UID STORE {max(uids.values()) + 1000} +FLAGS (\\Deleted)")
    assert b"\\Deleted" not in imap.cmd("FETCH 1:* (FLAGS)"), "STORE on a missing UID flagged a real message"

def test_uid_range_ending_in_star_includes_the_last_message(imap, box):
    uids = imap.uids()
    reply = imap.cmd(f"UID FETCH {max(uids.values()) + 1000}:* (FLAGS)")
    found = re.findall(rb"\* (\d+) FETCH", reply)
    assert found == [b"3"], f"n:* past the last UID must still return the last message (RFC 3501 6.4.8), got {found}"

def test_huge_uid_range_answers_promptly(imap, box):
    start = time.monotonic()
    reply = imap.cmd("UID FETCH 1:4294967295 (FLAGS)", timeout=10)
    assert len(re.findall(rb"\* \d+ FETCH", reply)) == 3
    assert time.monotonic() - start < 2, "the range was walked number by number"

def test_uids_survive_reselect_and_are_never_reused(imap, box):
    before = imap.select(box)
    uids = imap.uids()

    imap.cmd(f"UID STORE {uids[3]} +FLAGS (\\Deleted)")
    imap.cmd("EXPUNGE")
    imap.append(box, b"Subject: fourth\r\n\r\nbody-fourth\r\n")

    after = imap.select(box)
    assert after["uidvalidity"] == before["uidvalidity"], "UIDVALIDITY changed although nothing was lost"

    new_uids = imap.uids()
    assert new_uids[1] == uids[1] and new_uids[2] == uids[2], "surviving messages changed UID"
    assert new_uids[3] > uids[3], f"the new message reused or undercut an expunged UID: {new_uids[3]} vs {uids[3]}"
    assert after["uidnext"] > new_uids[3]

    # A second connection sees the same UIDs
    other = open_session()
    try:
        assert other.select(box)["uidvalidity"] == after["uidvalidity"]
        assert other.uids() == new_uids
    finally:
        other.s.close()

def test_dates_still_come_from_the_delivery_time(imap, box):
    reply = imap.cmd("FETCH 1 (INTERNALDATE)")
    year = time.gmtime().tm_year
    assert f"-{year} ".encode() in reply, f"INTERNALDATE is not this year: {reply!r}"

    since_old = imap.cmd("UID SEARCH SINCE 1-Jan-2000")
    since_future = imap.cmd("UID SEARCH SINCE 1-Jan-2099")
    assert re.findall(rb"\d+", since_old.split(b"\r\n")[0]) and len(since_old.split(b"\r\n")[0].split()) == 5
    assert since_future.split(b"\r\n")[0].strip() == b"* SEARCH"

def test_noop_does_not_duplicate_mail_that_select_found_in_new(imap):
    deliver_to_inbox(b"fresh-" + uuid.uuid4().hex.encode())
    time.sleep(0.5)

    count = imap.select("INBOX")["exists"]
    imap.cmd("NOOP")

    uids = imap.uids()
    assert len(uids) == count, f"NOOP turned {count} messages into {len(uids)}"
    assert len(set(uids.values())) == count, "NOOP produced duplicate UIDs"

def test_noop_in_another_mailbox_leaves_inbox_mail_alone(imap, box):
    deliver_to_inbox(b"inbox-only-" + uuid.uuid4().hex.encode())
    time.sleep(0.5)

    imap.cmd("NOOP")
    assert len(imap.uids()) == 3, f"INBOX mail showed up in {box} after NOOP"
