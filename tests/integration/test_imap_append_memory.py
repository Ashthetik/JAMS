# tests/integration/test_imap_append_memory.py
import re, socket, ssl, subprocess, threading, time, uuid, pytest

IMAP_PORT = 2143

# Just under the 50 MB APPENDLIMIT, so one upload is unmistakable in the server's RSS
MESSAGE_SIZE = 40 * 1024 * 1024

# Connections that upload and then stay open. Retained memory must not scale with this
HELD_CONNECTIONS = 4

# Uploads on throwaway connections before the baseline is taken. Writing out tens of
# megabytes churns the allocator (under ASan, a quarantine that fills to a fixed
# ceiling), which is not what is being measured, so this settles it first.
WARMUP_UPLOADS = 4

# Half of what the held messages weigh: far under keeping them, far over the noise of writing them
MEMORY_BUDGET_KB = HELD_CONNECTIONS * MESSAGE_SIZE // 2048


def recv_until(s, marker, timeout=180):
    s.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


def open_session():
    # Plaintext LOGIN is refused, so upgrade with STARTTLS first
    raw = socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=30)
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n")
    recv_until(raw, b"t1 ", timeout=10)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")

    s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n")
    if b"a1 OK" not in recv_until(s, b"a1 ", timeout=30):
        s.close()
        pytest.skip("no seeded test user available to log in with")

    return s


def append(s, tag, mailbox, payload):
    s.sendall(f"{tag} APPEND {mailbox} {{{len(payload)}}}\r\n".encode())
    assert b"+ " in recv_until(s, b"+ ", timeout=30), f"{tag}: server never asked for the literal"

    # A Debug + ASan server takes its time over tens of megabytes, and several
    # uploads at once share one event loop, so this must not be a short wait
    s.settimeout(300)
    s.sendall(payload + b"\r\n")

    reply = recv_until(s, tag.encode() + b" ")
    assert tag.encode() + b" OK" in reply, f"{tag}: APPEND was not accepted: {reply[-200:]!r}"


def is_mailserver(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip() == "mailserver"
    except OSError:
        return False


def server_pid(proc):
    # The fixture starts the server under sudo, which may exec the binary in place
    # or keep it as a child depending on how sudo is configured
    if is_mailserver(proc.pid):
        return proc.pid

    out = subprocess.run(["pgrep", "-P", str(proc.pid)], capture_output=True, text=True)
    for child in out.stdout.split():
        if is_mailserver(child):
            return int(child)

    pytest.skip("could not find the mailserver process to measure")


def retained_kb(pid):
    # Swap counts too: a buffer nobody touches can be paged out without ever being released
    total = 0
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith(("VmRSS:", "VmSwap:")):
                total += int(re.search(r"(\d+)", line).group(1))

    return total


def test_append_buffer_is_not_held_for_the_life_of_the_connection(jams_server):
    """
    An uploaded message is written to disk, so nothing should still be holding a copy of
    it once APPEND has been answered. Retained memory must stay flat as more connections
    each upload and stay open, instead of growing by a message per connection.
    """
    pid = server_pid(jams_server)
    payload = b"Subject: append memory\r\n\r\n" + (b"x" * (MESSAGE_SIZE - 28)) + b"\r\n"
    assert len(payload) == MESSAGE_SIZE

    seed = open_session()
    # CREATE can't make a folder for an account that has never had mail, so make sure INBOX exists first
    append(seed, "s1", "INBOX", b"Subject: seed\r\n\r\nseed\r\n")

    # A mailbox of its own, so these large messages are not left in INBOX for other tests
    mailbox = "mem" + uuid.uuid4().hex[:10]
    seed.sendall(f"s2 CREATE {mailbox}\r\n".encode())
    assert b"s2 OK" in recv_until(seed, b"s2 ", timeout=30), f"CREATE {mailbox} failed"

    for _ in range(WARMUP_UPLOADS):
        warm = open_session()
        append(warm, "w1", mailbox, payload)
        warm.close()

    seed.close()
    time.sleep(1.0)

    baseline = retained_kb(pid)

    sessions = [open_session() for _ in range(HELD_CONNECTIONS)]
    errors = []

    def upload(index, s):
        try:
            append(s, f"m{index}", mailbox, payload)
        except Exception as e:  # a bare thread failure is invisible, collect it for the join
            errors.append(f"connection {index}: {e}")

    try:
        # All at once, so none of them sits idle long enough to be swept while the rest upload
        threads = [threading.Thread(target=upload, args=(i, s)) for i, s in enumerate(sessions)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert not errors, errors

        # Every connection is still open and still usable
        for i, s in enumerate(sessions):
            s.sendall(f"n{i} NOOP\r\n".encode())
            assert f"n{i} OK".encode() in recv_until(s, f"n{i} ".encode(), timeout=30)

        held = retained_kb(pid)
    finally:
        for s in sessions:
            s.close()

    time.sleep(1.0)
    released = retained_kb(pid)
    growth = held - baseline

    print(
        f"\nappend memory: baseline {baseline / 1024:.1f} MB, "
        f"{HELD_CONNECTIONS} x {MESSAGE_SIZE / 1048576:.0f} MB uploaded and held "
        f"{held / 1024:.1f} MB (+{growth / 1024:.1f} MB), "
        f"after disconnect {released / 1024:.1f} MB",
        flush=True
    )

    # Every upload really was stored, so this cannot pass by the server refusing them
    check = open_session()
    check.sendall(f"c1 SELECT {mailbox}\r\n".encode())
    reply = recv_until(check, b"c1 ", timeout=30)
    check.close()
    stored = int(re.search(rb"\* (\d+) EXISTS", reply).group(1))
    assert stored == WARMUP_UPLOADS + HELD_CONNECTIONS, f"expected every upload to be stored, got {stored}"

    assert growth < MEMORY_BUDGET_KB, (
        f"{HELD_CONNECTIONS} open connections that each uploaded "
        f"{MESSAGE_SIZE / 1048576:.0f} MB are still holding {growth / 1024:.1f} MB of it "
        f"(budget {MEMORY_BUDGET_KB / 1024:.1f} MB), so the upload buffer is kept for the "
        f"life of the connection"
    )
