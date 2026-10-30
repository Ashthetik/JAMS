# tests/integration/test_submission_async_relay.py
import base64, glob, os, socket, ssl, subprocess, threading, time, pytest

SUBMISSION_PORT = 2587
FAKE_MX = os.path.join(os.path.dirname(__file__), "..", "tools", "fake_mx.py")
MX_DELAY = 4  # seconds the slow MX holds back its greeting

def recv_until(s, marker, timeout=5):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ssl.SSLError, ConnectionResetError):
        pass
    return data

def submission_session():
    raw = socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=5)
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

def start_message(s, subject):
    # Everything up to (not including) the final dot, so callers choose what follows it
    s.sendall(b"MAIL FROM:<ci-test-user@test.local>\r\n"); recv_until(s, b"\r\n")
    s.sendall(b"RCPT TO:<friend@localhost>\r\n")
    assert recv_until(s, b"\r\n").startswith(b"250")
    s.sendall(b"DATA\r\n"); recv_until(s, b"354")
    s.sendall(b"From: <ci-test-user@test.local>\r\nTo: <friend@localhost>\r\nSubject: " + subject + b"\r\n\r\nhello\r\n")

def mx_fixture(tmp_path, delay):
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        pytest.skip("needs passwordless sudo to listen on port 25")

    out_dir = tmp_path / "received"
    out_dir.mkdir()
    os.chmod(out_dir, 0o777)

    proc = subprocess.Popen(["sudo", "-n", "python3", FAKE_MX, "127.0.0.1", str(out_dir), str(delay)])
    time.sleep(1)
    if proc.poll() is not None:
        pytest.skip("could not start the fake MX on 127.0.0.1:25")
    return proc, out_dir

def stop_mx(proc):
    subprocess.run(["sudo", "-n", "kill", str(proc.pid)], capture_output=True)
    subprocess.run(["sudo", "-n", "pkill", "-f", "fake_mx.py 127.0.0.1"], capture_output=True)

@pytest.fixture
def slow_mx(tmp_path):
    proc, out_dir = mx_fixture(tmp_path, MX_DELAY)
    yield out_dir
    stop_mx(proc)

def test_other_clients_are_served_during_a_slow_relay(jams_server, slow_mx):
    result = {}

    def sender():
        with submission_session() as s:
            start_message(s, b"slow one")
            s.sendall(b".\r\n")
            result["reply"] = recv_until(s, b"\r\n", timeout=MX_DELAY + 15)

    t = threading.Thread(target=sender)
    t.start()
    time.sleep(1.5)  # the relay is now waiting on the slow MX

    start = time.monotonic()
    with socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=10) as other:
        greeting = recv_until(other, b"\r\n", timeout=10)
        other.sendall(b"EHLO other.test\r\n")
        ehlo = recv_until(other, b"250 ", timeout=10)
    waited = time.monotonic() - start

    t.join()
    assert greeting.startswith(b"220") and b"250 " in ehlo
    assert waited < 1.5, f"another client waited {waited:.1f}s for 587 while one relay was stuck"
    assert result.get("reply", b"").startswith(b"250"), f"the slow relay's own reply: {result.get('reply')!r}"
    assert glob.glob(str(slow_mx / "*.eml")), "the slow relay never delivered"

def test_pipelined_commands_wait_for_the_relay(jams_server, slow_mx):
    # No QUIT here on purpose: this is about ordering, not about closing
    with submission_session() as s:
        start_message(s, b"pipelined")
        s.sendall(b".\r\nNOOP\r\nRSET\r\n")

        data = b""
        deadline = time.time() + MX_DELAY + 15
        while data.count(b"\r\n") < 3 and time.time() < deadline:
            data += recv_until(s, b"\r\n", timeout=1)

    lines = data.split(b"\r\n")
    assert lines[0].startswith(b"250 OK: Message Accepted"), f"the message's reply should come first: {data!r}"
    assert lines[1].startswith(b"250") and lines[2].startswith(b"250"), f"NOOP and RSET weren't answered after it: {data!r}"

def test_hanging_up_mid_relay_is_safe(jams_server, slow_mx):
    s = submission_session()
    start_message(s, b"abandoned")
    s.sendall(b".\r\n")
    s.close()  # gone before the relay finishes

    deadline = time.time() + MX_DELAY + 15
    while time.time() < deadline and not glob.glob(str(slow_mx / "*.eml")):
        time.sleep(0.5)
    assert glob.glob(str(slow_mx / "*.eml")), "the relay should still finish after the client left"

    # And the server is fine afterwards
    with socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=5) as other:
        assert recv_until(other, b"\r\n").startswith(b"220")

def test_failed_relay_answers_and_session_carries_on(jams_server):
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", 25)) == 0:
            pytest.skip("something is listening on 127.0.0.1:25, can't simulate a dead MX")

    with submission_session() as s:
        start_message(s, b"nowhere to go")
        s.sendall(b".\r\n")
        reply = recv_until(s, b"\r\n", timeout=40)
        assert reply.startswith(b"452"), f"a relay to a dead MX should be a temporary failure: {reply!r}"

        s.sendall(b"NOOP\r\n")
        assert recv_until(s, b"\r\n").startswith(b"250"), "the session didn't recover after a failed relay"
