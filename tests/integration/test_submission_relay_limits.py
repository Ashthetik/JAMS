# tests/integration/test_submission_relay_limits.py
#
# What the far end of a relay is allowed to do to us. JAMS dials out to whatever
# MX a recipient domain names, so a hostile receiving server is not an exotic
# case, it is one DNS record away. The relay pool is a handful of threads shared
# by every session, so a conversation that never ends is outbound mail that
# never works again, for everybody.
import base64, glob, os, socket, ssl, subprocess, threading, time, pytest

SUBMISSION_PORT = 2587
EVIL_MX = os.path.join(os.path.dirname(__file__), "..", "tools", "evil_mx.py")
FAKE_MX = os.path.join(os.path.dirname(__file__), "..", "tools", "fake_mx.py")

# Comfortably longer than a relay that gives up should ever need, far shorter
# than "forever". Every assertion below is really "does this finish at all"
REPLY_BUDGET = 45

# More messages than there are relay workers, so a pool that never frees one
# cannot serve all of them
MESSAGES = 6

def recv_until(s, marker, timeout=5):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ssl.SSLError, ConnectionResetError, OSError):
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

def relay_one(subject, budget=REPLY_BUDGET):
    """Submit one message to friend@localhost, whose MX is whatever holds
    127.0.0.1:25. Returns the reply to the final dot, or b"" if none arrived."""
    with submission_session() as s:
        s.sendall(b"MAIL FROM:<ci-test-user@test.local>\r\n"); recv_until(s, b"\r\n")
        s.sendall(b"RCPT TO:<friend@localhost>\r\n")
        if not recv_until(s, b"\r\n").startswith(b"250"):
            pytest.skip("the server would not accept an external recipient")
        s.sendall(b"DATA\r\n"); recv_until(s, b"354")
        s.sendall(b"From: <ci-test-user@test.local>\r\nTo: <friend@localhost>\r\nSubject: " +
                  subject + b"\r\n\r\nhello\r\n.\r\n")
        return recv_until(s, b"\r\n", timeout=budget)

def port_25_is_free(timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", 25)) != 0:
                return True
        time.sleep(0.25)
    return False

def start_mx(argv):
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        pytest.skip("needs passwordless sudo to listen on port 25")
    if not port_25_is_free():
        pytest.skip("something else is already listening on 127.0.0.1:25")

    # Its own session, so stop_mx can kill the whole group: sudo plus the python
    # it started. Deliberately no pkill anywhere here, its pattern matches
    # whatever else happens to be on a command line, including the test runner
    proc = subprocess.Popen(["sudo", "-n", "python3"] + argv, start_new_session=True)

    deadline = time.time() + 10
    while time.time() < deadline:
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", 25)) == 0:
                return proc
        if proc.poll() is not None:
            break
        time.sleep(0.2)
    pytest.skip("could not start a test MX on 127.0.0.1:25")

def stop_mx(proc):
    subprocess.run(["sudo", "-n", "kill", "-9", "--", f"-{proc.pid}"], capture_output=True)
    proc.wait(timeout=10)
    port_25_is_free()

def start_evil_mx(tmp_path, mode):
    os.chmod(tmp_path, 0o777)
    conn_log = str(tmp_path / "connections.log")
    proc = start_mx([EVIL_MX, "127.0.0.1", mode, conn_log, str(REPLY_BUDGET * 4)])
    return proc, conn_log

def accepted(conn_log):
    if not os.path.exists(conn_log):
        return 0
    return open(conn_log).read().count("accepted")

@pytest.fixture
def badcode_mx(tmp_path):
    proc, conn_log = start_evil_mx(tmp_path, "badcode")
    yield conn_log
    stop_mx(proc)

@pytest.fixture
def nocrlf_mx(tmp_path):
    proc, conn_log = start_evil_mx(tmp_path, "nocrlf")
    yield conn_log
    stop_mx(proc)

def test_a_malformed_reply_does_not_wedge_the_relay(jams_server, badcode_mx):
    # "250\r\n" has '\r' where a reply line carries ' ' or '-'. It is neither the
    # end of a reply nor a line with more to follow, so it is malformed and the
    # relay has to give up rather than read the next one forever
    reply = relay_one(b"malformed reply")
    assert reply, f"no reply within {REPLY_BUDGET}s, the relay is stuck on the hostile MX"
    assert reply[:1] in (b"4", b"5"), f"a relay that gave up should report a failure: {reply!r}"

def test_a_reply_with_no_line_ending_does_not_wedge_the_relay(jams_server, nocrlf_mx):
    # The far end streams bytes and never a CRLF. A reply line has a maximum
    # length, so this ends in a failure instead of a string that keeps growing
    reply = relay_one(b"endless line")
    assert reply, f"no reply within {REPLY_BUDGET}s, the relay is stuck reading one line"
    assert reply[:1] in (b"4", b"5"), f"a relay that gave up should report a failure: {reply!r}"

def test_a_hostile_mx_does_not_use_up_the_relay_pool(jams_server, badcode_mx):
    # What makes this serious is not one slow message, it is that the workers
    # never come back. More messages than workers, all in flight at once
    replies = {}

    def one(n):
        try:
            replies[n] = relay_one(b"pool %d" % n)
        except Exception as ex:
            replies[n] = f"{type(ex).__name__}: {ex}".encode()

    threads = [threading.Thread(target=one, args=(n,)) for n in range(MESSAGES)]
    for t in threads:
        t.start()
        time.sleep(0.2)
    for t in threads:
        t.join(timeout=REPLY_BUDGET + 30)

    stuck = [n for n in range(MESSAGES) if not replies.get(n, b"").startswith((b"4", b"5"))]
    assert not stuck, \
        f"{len(stuck)} of {MESSAGES} messages never got a reply: {({n: replies.get(n) for n in stuck})}"
    assert accepted(badcode_mx) >= MESSAGES, \
        f"only {accepted(badcode_mx)} of {MESSAGES} relays ever reached the MX, the pool ran out"

def test_relay_still_works_after_a_hostile_mx(jams_server, tmp_path):
    # The question behind all of the above: once the hostile server is gone, can
    # this server still send mail at all?
    proc, _ = start_evil_mx(tmp_path, "badcode")
    try:
        for n in range(MESSAGES):
            reply = relay_one(b"burn %d" % n)
            assert reply[:1] in (b"4", b"5"), f"message {n} to the hostile MX: {reply!r}"
    finally:
        stop_mx(proc)

    out_dir = tmp_path / "received"
    out_dir.mkdir()
    os.chmod(out_dir, 0o777)

    good = start_mx([FAKE_MX, "127.0.0.1", str(out_dir)])
    try:
        reply = relay_one(b"after the storm")
        assert reply.startswith(b"250"), f"a healthy relay after the hostile one: {reply!r}"
        assert glob.glob(str(out_dir / "*.eml")), "the relay never delivered once the MX was sane again"
    finally:
        stop_mx(good)
