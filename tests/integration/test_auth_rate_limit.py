# tests/integration/test_auth_rate_limit.py
import base64, socket, ssl, time, pytest

IMAP_PORT = 2143
SUBMISSION_PORT = 2587
MAX_FAILURES = 10

def tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def recv_line(s, timeout=10):
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

def imap_from(source_ip):
    # All of 127.0.0.0/8 is loopback on Linux, so each address acts like a different client.
    # 127.0.0.1 itself is exempt from the limit (local webmail logs in for everyone from there)
    raw = socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=5, source_address=(source_ip, 0))
    recv_line(raw)
    raw.sendall(b"t1 STARTTLS\r\n")
    recv_line(raw)
    return tls_context().wrap_socket(raw, server_hostname="localhost")

def imap_login(s, tag, password):
    s.sendall(f"{tag} LOGIN ci-test-user {password}\r\n".encode())
    start = time.perf_counter()
    reply = recv_line(s)
    return reply, time.perf_counter() - start

def use_up_failures(s):
    for i in range(MAX_FAILURES):
        reply, _ = imap_login(s, f"f{i}", "wrong-password")
        assert b" NO " in reply, f"wrong password #{i + 1} wasn't refused: {reply!r}"

def test_address_is_refused_after_too_many_failures(jams_server):
    s = imap_from("127.0.0.40")
    try:
        _, first = imap_login(s, "p0", "wrong-password")
        use_up_failures(s)

        reply, refused = imap_login(s, "p1", "wrong-password")
        assert b" NO " in reply
        assert refused < first / 2, (
            f"a throttled attempt took {refused * 1000:.0f} ms, about as long as a real check "
            f"({first * 1000:.0f} ms), so it is still burning a password hash"
        )
    finally:
        s.close()

def test_right_password_is_refused_while_throttled(jams_server):
    s = imap_from("127.0.0.41")
    try:
        use_up_failures(s)
        reply, _ = imap_login(s, "ok1", "ci-test-password")
        assert b"ok1 OK" not in reply, "an address over the limit could keep guessing until it hit the right password"
    finally:
        s.close()

def test_other_addresses_still_log_in(jams_server):
    hog = imap_from("127.0.0.42")
    try:
        use_up_failures(hog)

        s = imap_from("127.0.0.43")
        try:
            reply, _ = imap_login(s, "ok2", "ci-test-password")
            assert b"ok2 OK" in reply, f"one address's failures locked out a different address: {reply!r}"
        finally:
            s.close()
    finally:
        hog.close()

def test_limit_is_shared_between_imap_and_smtp_auth(jams_server):
    s = imap_from("127.0.0.44")
    try:
        use_up_failures(s)
    finally:
        s.close()

    # Same handshake as test_auth.py's smtp_tls_connect, from the throttled address
    raw = socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=5, source_address=("127.0.0.44", 0))
    raw.recv(1024)
    raw.sendall(b"EHLO test.local\r\n")
    raw.recv(1024)
    raw.sendall(b"STARTTLS\r\n")
    assert b"220" in raw.recv(1024)

    tls = tls_context().wrap_socket(raw, server_hostname="localhost")
    try:
        tls.sendall(b"EHLO test.local\r\n")
        tls.recv(1024)

        creds = base64.b64encode(b"\x00ci-test-user\x00ci-test-password").decode()
        tls.sendall(f"AUTH PLAIN {creds}\r\n".encode())
        reply = recv_line(tls)
        assert reply and not reply.startswith(b"235"), f"IMAP failures didn't count against SMTP AUTH from the same address: {reply!r}"
    finally:
        tls.close()

def test_guesses_at_missing_accounts_count_too(jams_server):
    # Unknown usernames used to fail through an exception before any hashing,
    # which skipped both the PBKDF2 run and anything counted after it
    s = imap_from("127.0.0.45")
    try:
        for i in range(MAX_FAILURES):
            s.sendall(f"m{i} LOGIN no-such-user-{i} wrong-password\r\n".encode())
            assert b" NO " in recv_line(s)

        reply, _ = imap_login(s, "ok3", "ci-test-password")
        assert b"ok3 OK" not in reply, "guesses against missing accounts weren't counted"
    finally:
        s.close()
