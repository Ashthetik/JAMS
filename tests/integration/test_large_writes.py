# tests/integration/test_large_writes.py
import os, re, socket, ssl, time, uuid, pytest

IMAP_PORT = 2143
BIG = 20 * 1024 * 1024

def config_limit(name):
    text = open(os.environ["JAMS_CONFIG"]).read()
    limits = re.search(r"^\[limits\](.*?)(?=^\[|\Z)", text, re.S | re.M)
    match = limits and re.search(rf"^\s*{name}\s*=\s*(\d+)", limits.group(1), re.M)
    return int(match.group(1)) if match else None

def recv_until(s, pattern, timeout):
    s.settimeout(timeout)
    data = b""
    try:
        while not re.search(pattern, data):
            chunk = s.recv(1 << 20)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ConnectionResetError, ssl.SSLError):
        pass
    return data

def imap_session(rcvbuf=None):
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if rcvbuf:
        # Small receive buffer, so the server's send() can't take a big reply in one go
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    raw.settimeout(5)
    raw.connect(("127.0.0.1", IMAP_PORT))
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n")
    raw.recv(1024)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n")
    if b"a1 OK" not in recv_until(s, rb"a1 (OK|NO|BAD)", 5):
        s.close()
        pytest.skip("no seeded test user available to log in with")
    return s

@pytest.fixture(scope="module")
def big_mailbox(jams_server):
    # One 20 MB message in its own mailbox, shared by the tests below
    s = imap_session()
    try:
        s.sendall(b"a2 APPEND INBOX {16}\r\n")
        recv_until(s, rb"\+ ", 5)
        s.sendall(b"Subject: seed\r\n\r\n")
        recv_until(s, rb"a2 (OK|NO)", 5)

        name = "big" + uuid.uuid4().hex[:8]
        s.sendall(f"a3 CREATE {name}\r\n".encode())
        recv_until(s, rb"a3 (OK|NO)", 5)

        line = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!?\r\n"
        body = (line * (BIG // len(line)))
        message = b"Subject: big\r\n\r\n" + body
        s.sendall(f"a4 APPEND {name} {{{len(message)}}}\r\n".encode())
        assert b"+ " in recv_until(s, rb"\+ ", 5)
        s.sendall(message + b"\r\n")
        assert b"a4 OK" in recv_until(s, rb"a4 (OK|NO|BAD)", 60), "couldn't store the 20 MB test message"
        return name, message
    finally:
        s.close()

def test_big_fetch_arrives_complete(big_mailbox):
    name, message = big_mailbox
    s = imap_session(rcvbuf=65536)
    try:
        s.sendall(f"b1 SELECT {name}\r\n".encode())
        recv_until(s, rb"b1 (OK|NO)", 5)

        s.sendall(b"b2 FETCH 1 BODY[]\r\n")
        time.sleep(3)  # slow reader: let both socket buffers fill up first

        data = recv_until(s, rb"\r\nb2 (OK|NO|BAD)[^\r\n]*\r\n", 60)
        m = re.search(rb"BODY\[\] \{(\d+)\}\r\n", data)
        assert m, "no BODY[] literal in the response"

        declared = int(m.group(1))
        literal = data[m.end():m.end() + declared]
        assert declared == len(message)
        assert len(literal) == declared, f"declared {declared} bytes, only {len(literal)} arrived"
        assert literal == message, "the message arrived, but its bytes don't match what was stored"
        assert data[m.end() + declared:].startswith(b")\r\nb2 OK"), "the stream after the literal is corrupt"
    finally:
        s.close()

def test_logout_sends_both_replies():
    # LOGOUT queues "* BYE" and then the tagged OK, and closes after them
    with socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"c1 LOGOUT\r\n")
        data = recv_until(s, rb"c1 OK[^\r\n]*\r\n", 5)
        assert b"* BYE" in data
        assert b"c1 OK" in data, f"the tagged reply after BYE was dropped when the connection closed: {data!r}"

def test_reader_that_stops_reading_times_out(big_mailbox):
    name, message = big_mailbox
    timeout = config_limit("imap_idle_timeout")
    if not timeout or timeout > 30:
        pytest.skip("needs [limits] imap_idle_timeout <= 30 in the test config")

    s = imap_session(rcvbuf=65536)
    try:
        s.sendall(f"d1 SELECT {name}\r\n".encode())
        recv_until(s, rb"d1 (OK|NO)", 5)

        # Ask for 20 MB, then never read: the server's write stalls with nowhere to go
        s.sendall(b"d2 FETCH 1 BODY[]\r\n")
        time.sleep(timeout + 5)

        # Drain what the kernel already buffered: the server should have hung up behind it
        s.settimeout(30)
        closed = False
        try:
            while True:
                chunk = s.recv(1 << 20)
                if not chunk:
                    closed = True
                    break
        except (ConnectionResetError, ssl.SSLError):
            closed = True
        except socket.timeout:
            pass

        assert closed, "a client that stopped reading for longer than the timeout kept its connection"
    finally:
        s.close()
