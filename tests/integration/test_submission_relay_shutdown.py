# tests/integration/test_submission_relay_shutdown.py
#
# A relay worker runs a blocking SMTP conversation, so while it is parked in
# recv() against a slow remote server it cannot see a stop flag. Shutdown has to
# break its socket from the outside, or SIGTERM does nothing and the process has
# to be SIGKILLed.
#
# This test runs its own server on its own ports: the session-scoped jams_server
# is shared with the rest of the suite and must not be signalled.
import base64, os, socket, ssl, subprocess, time, pytest

JAMS_BIN = os.environ.get("JAMS_BIN")
FAKE_MX = os.path.join(os.path.dirname(__file__), "..", "tools", "fake_mx.py")

ROOT = "/tmp/jams-relay-shutdown"
SUBMISSION_PORT = 2689
PORTS = {"smtp": 2628, "submissions": SUBMISSION_PORT, "imap4": 2645, "imap4s": 2695}

MX_GREETING_DELAY = 60  # the remote never actually greets us within the test
EXIT_BUDGET = 10        # seconds SIGTERM gets before we call it a hang

CONFIG = f"""[server]
hostname = "test.local"
mailroot = "{ROOT}/mail"

[ports]
smtp = {PORTS["smtp"]}
imap4s = {PORTS["imap4s"]}
imap4 = {PORTS["imap4"]}
submissions = {PORTS["submissions"]}

[database]
dbpath = "{ROOT}/db/users.db"

[reporting]
ip_alert_mta = "traversal-victim@test.local"

[limits]
idle_timeout = 5
imap_idle_timeout = 15
"""


def have_sudo():
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


def wait_for_port(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def wait_for_port_free(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                time.sleep(0.2)
        except OSError:
            return True
    return False


def real_child_pid(wrapper_pid, name):
    """sudo sometimes execs the command in place and sometimes forks a monitor, so
    the Popen handle may or may not be the process we care about. Resolve it."""
    listing = subprocess.run(
        ["ps", "-o", "pid=,comm=", "--ppid", str(wrapper_pid)],
        capture_output=True, text=True
    ).stdout
    for line in listing.splitlines():
        pid, _, comm = line.strip().partition(" ")
        if comm.strip() == name:
            return int(pid)

    own = subprocess.run(
        ["ps", "-o", "comm=", "-p", str(wrapper_pid)], capture_output=True, text=True
    ).stdout.strip()
    return wrapper_pid if own == name else None


def proc_gone(pid):
    """A reaped-but-unwaited child still has a /proc entry, so a zombie counts as gone."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            state = f.read().rsplit(b")", 1)[1].split()[0].decode()
    except (FileNotFoundError, ProcessLookupError, IndexError):
        return True
    return state == "Z"


@pytest.fixture
def own_server():
    if not JAMS_BIN:
        pytest.skip("JAMS_BIN is not set")
    if not have_sudo():
        pytest.skip("needs passwordless sudo to run the server and bind port 25")

    subprocess.run(["sudo", "-n", "rm", "-rf", ROOT], capture_output=True)
    for sub in ("config", "db", "mail", "logs"):
        os.makedirs(f"{ROOT}/{sub}", exist_ok=True)
        os.chmod(f"{ROOT}/{sub}", 0o777)

    config_path = f"{ROOT}/config/server.toml"
    with open(config_path, "w") as f:
        f.write(CONFIG)

    env = dict(os.environ)
    env["JAMS_CONFIG"] = config_path
    env["JAMS_LOG_PATH"] = f"{ROOT}/logs/jams.txt"
    sudo = ["sudo", "--preserve-env=JAMS_PEPPER,JAMS_CONFIG,JAMS_LOG_PATH"]

    subprocess.run(
        sudo + [JAMS_BIN, "--add-user", "ci-test-user", "ci-test-password"],
        cwd=f"{ROOT}/config", env=env, timeout=60, capture_output=True
    )

    stderr_path = f"{ROOT}/logs/stderr.log"
    proc = subprocess.Popen(
        sudo + [JAMS_BIN],
        cwd=f"{ROOT}/config", env=env,
        stdout=open(f"{ROOT}/logs/stdout.log", "w"),
        stderr=open(stderr_path, "w")
    )

    for name, port in PORTS.items():
        if not wait_for_port(port):
            proc.kill()
            pytest.skip(f"own server's {name} port {port} never came up")

    pid = real_child_pid(proc.pid, "mailserver")
    assert pid, "could not find the mailserver process behind sudo"

    yield proc, pid, stderr_path

    if not proc_gone(pid):
        subprocess.run(["sudo", "-n", "kill", "-9", str(pid)], capture_output=True)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    subprocess.run(["sudo", "-n", "rm", "-rf", ROOT], capture_output=True)


@pytest.fixture
def stalled_mx(tmp_path):
    if not have_sudo():
        pytest.skip("needs passwordless sudo to listen on port 25")

    out_dir = tmp_path / "received"
    out_dir.mkdir()
    os.chmod(out_dir, 0o777)

    proc = subprocess.Popen(
        ["sudo", "-n", "python3", FAKE_MX, "127.0.0.1", str(out_dir), str(MX_GREETING_DELAY)]
    )
    time.sleep(1)
    if proc.poll() is not None or not wait_for_port(25, timeout=5):
        pytest.skip("could not start the stalled fake MX on 127.0.0.1:25")

    yield out_dir

    # Kill the python by pid, never by command-line pattern: a -f pattern here would
    # also match the sudo that carries it
    mx_pid = real_child_pid(proc.pid, "python3")
    if mx_pid:
        subprocess.run(["sudo", "-n", "kill", "-9", str(mx_pid)], capture_output=True)
    subprocess.run(["sudo", "-n", "kill", "-9", str(proc.pid)], capture_output=True)
    proc.wait(timeout=10)
    wait_for_port_free(25, timeout=10)


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


def test_sigterm_stops_the_server_while_a_relay_is_stuck(own_server, stalled_mx):
    proc, pid, stderr_path = own_server

    s = submission_session()
    s.sendall(b"MAIL FROM:<ci-test-user@test.local>\r\n"); recv_until(s, b"\r\n")
    s.sendall(b"RCPT TO:<friend@localhost>\r\n")
    assert recv_until(s, b"\r\n").startswith(b"250")
    s.sendall(b"DATA\r\n"); recv_until(s, b"354")
    s.sendall(
        b"From: <ci-test-user@test.local>\r\nTo: <friend@localhost>\r\n"
        b"Subject: stuck relay\r\n\r\nhello\r\n"
    )
    s.sendall(b".\r\n")

    # No reply yet means the relay really is out there, waiting on the stalled MX
    early = recv_until(s, b"\r\n", timeout=5)
    assert early == b"", f"the relay should still be waiting on the stalled MX, got {early!r}"

    subprocess.run(["sudo", "-n", "kill", "-TERM", str(pid)], capture_output=True)

    start = time.monotonic()
    deadline = start + EXIT_BUDGET
    while time.monotonic() < deadline and not proc_gone(pid):
        proc.poll()
        time.sleep(0.1)
    took = time.monotonic() - start

    s.close()

    assert proc_gone(pid), (
        f"the server was still running {took:.1f}s after SIGTERM with a relay in flight; "
        "a worker blocked on the remote server is holding shutdown open"
    )

    # The message was never handed over, so it must not disappear quietly
    with open(stderr_path, "rb") as f:
        log = f.read()
    assert b"was NOT delivered" in log, (
        f"shutdown dropped a message in flight without logging it: {log[-800:]!r}"
    )
