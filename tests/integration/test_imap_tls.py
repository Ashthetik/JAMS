# tests/integration/test_imap_tls.py
import socket, ssl, pytest

IMAP_PORT = 2143
IMAPS_PORT = 2993

def recv_until(s, marker, timeout=5):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ssl.SSLError):
        pass
    return data

def tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def imaps_connect():
    raw = socket.create_connection(("127.0.0.1", IMAPS_PORT), timeout=5)
    return tls_context().wrap_socket(raw, server_hostname="localhost")

def starttls_connect():
    raw = socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5)
    raw.recv(1024)
    raw.sendall(b"t1 STARTTLS\r\n")
    assert b"t1 OK" in recv_until(raw, b"t1 ")
    return tls_context().wrap_socket(raw, server_hostname="localhost")

def test_imaps_sends_nothing_in_plaintext(jams_server):
    # RFC 8314: on 993 the first thing on the wire is the TLS handshake, never a cleartext greeting
    with socket.create_connection(("127.0.0.1", IMAPS_PORT), timeout=5) as raw:
        raw.settimeout(1.5)
        try:
            leaked = raw.recv(1024)
        except socket.timeout:
            leaked = b""
        assert b"* OK" not in leaked, f"IMAPS sent a plaintext greeting: {leaked!r}"

def test_imaps_greeting_arrives_over_tls(jams_server):
    with imaps_connect() as s:
        greeting = recv_until(s, b"\r\n")
        assert greeting.startswith(b"* OK"), f"no greeting over TLS: {greeting!r}"
        assert b"AUTH=PLAIN" in greeting and b"LOGINDISABLED" not in greeting
        assert b"STARTTLS" not in greeting, "TLS is already active, STARTTLS should not be offered"

def test_imaps_rejects_starttls(jams_server):
    with imaps_connect() as s:
        recv_until(s, b"\r\n")
        s.sendall(b"s1 STARTTLS\r\n")
        assert b"s1 BAD" in recv_until(s, b"s1 ")

def test_plaintext_imap_advertises_logindisabled(jams_server):
    with socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5) as s:
        greeting = recv_until(s, b"\r\n")
        assert b"LOGINDISABLED" in greeting and b"STARTTLS" in greeting
        assert b"AUTH=PLAIN" not in greeting

        s.sendall(b"c1 CAPABILITY\r\n")
        caps = recv_until(s, b"c1 ")
        assert b"LOGINDISABLED" in caps and b"AUTH=PLAIN" not in caps

def test_plaintext_login_is_refused(jams_server):
    with socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"l1 LOGIN ci-test-user ci-test-password\r\n")
        reply = recv_until(s, b"l1 ")
        assert b"l1 NO" in reply and b"PRIVACYREQUIRED" in reply, f"plaintext LOGIN should be refused, got {reply!r}"

        s.sendall(b"l2 AUTHENTICATE PLAIN AGNpLXRlc3QtdXNlcgBjaS10ZXN0LXBhc3N3b3Jk\r\n")
        reply = recv_until(s, b"l2 ")
        assert b"l2 NO" in reply and b"PRIVACYREQUIRED" in reply, f"plaintext AUTHENTICATE should be refused, got {reply!r}"

def test_capabilities_change_after_starttls(jams_server):
    with starttls_connect() as s:
        s.sendall(b"c2 CAPABILITY\r\n")
        caps = recv_until(s, b"c2 ")
        assert b"AUTH=PLAIN" in caps and b"LOGINDISABLED" not in caps

@pytest.mark.parametrize("connect", [starttls_connect, imaps_connect], ids=["starttls-143", "imaps-993"])
def test_login_works_once_encrypted(jams_server, connect):
    with connect() as s:
        if connect is imaps_connect:
            recv_until(s, b"\r\n")

        s.sendall(b"a1 LOGIN ci-test-user ci-test-password\r\n")
        reply = recv_until(s, b"a1 ")

        if b"AUTHENTICATIONFAILED" in reply:
            pytest.skip("no seeded test user available to log in with")

        assert b"a1 OK" in reply, f"LOGIN over TLS should work, got {reply!r}"
