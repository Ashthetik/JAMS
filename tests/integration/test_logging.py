# tests/integration/test_logging.py
import base64, datetime, os, re, socket, ssl, time, pytest

LINE = re.compile(rb"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d{3} \[(DEBUG|INFO|WARN|ERROR)\] ", re.M)

def log_path():
    return os.environ.get("JAMS_LOG_PATH", "/tmp/jams/logs/jams.txt")

def read_log(wait_for=None, timeout=5):
    # The writer is asynchronous, so give it a moment
    deadline = time.time() + timeout
    data = b""
    while time.time() < deadline:
        try:
            data = open(log_path(), "rb").read()
        except FileNotFoundError:
            data = b""
        if data and (wait_for is None or wait_for in data):
            break
        time.sleep(0.2)
    return data

def tls_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def recv_line(s, timeout=5):
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

def imap_tls():
    raw = socket.create_connection(("127.0.0.1", 2143), timeout=5)
    recv_line(raw)
    raw.sendall(b"t1 STARTTLS\r\n"); recv_line(raw)
    return tls_ctx().wrap_socket(raw, server_hostname="localhost")

def test_log_file_is_written_with_real_timestamps(jams_server):
    with socket.create_connection(("127.0.0.1", 2525), timeout=5) as s:
        recv_line(s)
        s.sendall(b"NOOP\r\nQUIT\r\n")
        recv_line(s)

    data = read_log()
    assert data, f"nothing was ever written to {log_path()}"

    stamps = LINE.findall(data)
    assert stamps, f"no line in the log has the expected timestamp format: {data[:200]!r}"

    # "%H:%H" used to print the hour twice: the time on the last line should match the clock
    last = datetime.datetime.strptime(stamps[-1][0].decode(), "%Y-%m-%d %H:%M:%S")
    assert abs((datetime.datetime.now() - last).total_seconds()) < 300, f"log timestamp {last} is nowhere near now"

def test_credentials_never_reach_the_log(jams_server):
    imap_pw, sasl_pw, smtp_pw = b"ImapMarker-7f3a", b"SaslMarker-91c2", b"SmtpMarker-c40e"

    # A tag starting with L: the old "skip credentials" check only looked at the first character
    s = imap_tls()
    try:
        s.sendall(b"L1 LOGIN ci-test-user " + imap_pw + b"\r\n")
        recv_line(s)
        s.sendall(b"N2 AUTHENTICATE PLAIN " + base64.b64encode(b"\0ci-test-user\0" + sasl_pw) + b"\r\n")
        recv_line(s)
    finally:
        s.close()

    raw = socket.create_connection(("127.0.0.1", 2587), timeout=5)
    recv_line(raw)
    raw.sendall(b"EHLO test.local\r\n"); raw.recv(4096)
    raw.sendall(b"STARTTLS\r\n"); recv_line(raw)
    t = tls_ctx().wrap_socket(raw, server_hostname="localhost")
    try:
        t.sendall(b"EHLO test.local\r\n"); t.recv(4096)
        t.sendall(b"auth plain " + base64.b64encode(b"\0ci-test-user\0" + smtp_pw) + b"\r\n")
        recv_line(t)
    finally:
        t.close()

    data = read_log(wait_for=b"credentials hidden")
    assert data, f"nothing was ever written to {log_path()}"

    for pw in (imap_pw, sasl_pw, smtp_pw):
        assert pw not in data, f"a password made it into the log: {pw!r}"
    for blob in (base64.b64encode(b"\0ci-test-user\0" + sasl_pw), base64.b64encode(b"\0ci-test-user\0" + smtp_pw)):
        assert blob not in data, "base64 credentials made it into the log"
