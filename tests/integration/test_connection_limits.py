# tests/integration/test_connection_limits.py
import os, re, socket, ssl, time, pytest

SMTP_PORT = 2525
IMAP_PORT = 2143

def configured_idle_timeout():
    # The CI fixture sets [limits] idle_timeout low so these tests don't wait 5 minutes
    text = open(os.environ["JAMS_CONFIG"]).read()
    limits = re.search(r"^\[limits\](.*?)(?=^\[|\Z)", text, re.S | re.M)
    match = limits and re.search(r"^\s*idle_timeout\s*=\s*(\d+)", limits.group(1), re.M)
    return int(match.group(1)) if match else None

IDLE_TIMEOUT = configured_idle_timeout()
needs_short_timeout = pytest.mark.skipif(
    not IDLE_TIMEOUT or IDLE_TIMEOUT > 30, reason="needs [limits] idle_timeout <= 30 in the test config"
)

def connect_from(source_ip, port):
    # All of 127.0.0.0/8 is loopback on Linux, so each address acts like a different client
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.bind((source_ip, 0))
    s.connect(("127.0.0.1", port))
    return s

def greeting(s, timeout=3):
    s.settimeout(timeout)
    try:
        return s.recv(1024)
    except (socket.timeout, ConnectionResetError):
        return b""

def is_closed(s, timeout):
    # recv returning b"" (or a reset) means the server hung up
    s.settimeout(timeout)
    try:
        return s.recv(1024) == b""
    except ConnectionResetError:
        return True
    except socket.timeout:
        return False

def test_one_address_cannot_lock_everyone_else_out(jams_server):
    hogs = []
    try:
        for _ in range(120):
            try:
                hogs.append(connect_from("127.0.0.2", SMTP_PORT))
            except OSError:
                break

        time.sleep(0.5)

        legit = connect_from("127.0.0.1", SMTP_PORT)
        try:
            assert greeting(legit).startswith(b"220"), "a normal client was shut out by idle connections from another address"
        finally:
            legit.close()
    finally:
        for s in hogs:
            s.close()

def test_per_address_cap_refuses_the_extras(jams_server):
    hogs = []
    try:
        for _ in range(30):
            hogs.append(connect_from("127.0.0.3", SMTP_PORT))

        greeted = sum(1 for s in hogs if greeting(s, timeout=1).startswith(b"220"))
        assert greeted == 20, f"expected the default cap of 20 per address, {greeted} were greeted"
    finally:
        for s in hogs:
            s.close()

@needs_short_timeout
def test_silent_smtp_connection_is_closed(jams_server):
    s = connect_from("127.0.0.4", SMTP_PORT)
    try:
        assert greeting(s).startswith(b"220")
        assert is_closed(s, IDLE_TIMEOUT + 5), f"connection was still open after {IDLE_TIMEOUT + 5}s of silence"
    finally:
        s.close()

@needs_short_timeout
def test_silent_imap_connection_is_closed_before_login(jams_server):
    s = connect_from("127.0.0.5", IMAP_PORT)
    try:
        assert greeting(s).startswith(b"* OK")
        assert is_closed(s, IDLE_TIMEOUT + 5), f"unauthenticated IMAP was still open after {IDLE_TIMEOUT + 5}s of silence"
    finally:
        s.close()

@needs_short_timeout
def test_active_connection_is_not_closed(jams_server):
    s = connect_from("127.0.0.6", SMTP_PORT)
    try:
        assert greeting(s).startswith(b"220")
        deadline = time.time() + IDLE_TIMEOUT + 3
        while time.time() < deadline:
            s.sendall(b"NOOP\r\n")
            assert greeting(s).startswith(b"250"), "a client sending commands was cut off"
            time.sleep(1)
    finally:
        s.close()

@needs_short_timeout
def test_logged_in_imap_gets_the_longer_timeout(jams_server):
    # Logged in IMAP clients sit quietly between checks (and in IDLE), RFC 3501 5.4 says at least 30 minutes
    raw = connect_from("127.0.0.7", IMAP_PORT)
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n")
    raw.recv(1024)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    try:
        s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n")
        if b"a1 OK" not in greeting(s, timeout=5):
            pytest.skip("no seeded test user available to log in with")

        time.sleep(IDLE_TIMEOUT + 3)

        s.sendall(b"a2 NOOP\r\n")
        assert b"a2 OK" in greeting(s, timeout=5), "a logged in IMAP session was closed after the short timeout"
    finally:
        s.close()
