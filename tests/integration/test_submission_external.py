# tests/integration/test_submission_external.py
import os, socket, ssl, base64, subprocess, time, glob, pytest, dkim

SUBMISSION_PORT = 2587
FAKE_MX = os.path.join(os.path.dirname(__file__), "..", "tools", "fake_mx.py")

def recv_until(s, marker, timeout=5):
    s.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ssl.SSLError):
        pass
    return data

def submission_session(authenticate=True):
    raw = socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=5)
    recv_until(raw, b"\r\n")
    raw.sendall(b"EHLO client.test\r\n"); recv_until(raw, b"250 ")
    raw.sendall(b"STARTTLS\r\n"); recv_until(raw, b"220")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    s.sendall(b"EHLO client.test\r\n"); recv_until(s, b"250 ")

    if authenticate:
        s.sendall(b"AUTH PLAIN " + base64.b64encode(b"\0ci-test-user\0ci-test-password") + b"\r\n")
        if b"235" not in recv_until(s, b"\r\n"):
            s.close()
            pytest.skip("no seeded test user available to log in with")

    return s

def send(s, rcpt, body, timeout=20):
    s.sendall(b"MAIL FROM:<ci-test-user@test.local>\r\n"); recv_until(s, b"\r\n")
    s.sendall(f"RCPT TO:<{rcpt}>\r\n".encode())
    rcpt_reply = recv_until(s, b"\r\n")
    if not rcpt_reply.startswith(b"250"):
        return rcpt_reply, None

    s.sendall(b"DATA\r\n"); recv_until(s, b"354")
    s.sendall(body + b"\r\n.\r\n")
    return rcpt_reply, recv_until(s, b"\r\n", timeout=timeout)

def test_authenticated_user_can_address_external_recipient(jams_server):
    with submission_session() as s:
        s.sendall(b"MAIL FROM:<ci-test-user@test.local>\r\n"); recv_until(s, b"\r\n")
        s.sendall(b"RCPT TO:<friend@example.com>\r\n")
        reply = recv_until(s, b"\r\n")
        assert reply.startswith(b"250"), f"authenticated external RCPT should be accepted, got {reply!r}"

def test_unauthenticated_cannot_send(jams_server):
    with submission_session(authenticate=False) as s:
        s.sendall(b"MAIL FROM:<anyone@test.local>\r\n")
        assert recv_until(s, b"\r\n").startswith(b"530")

        s.sendall(b"RCPT TO:<friend@example.com>\r\n")
        assert recv_until(s, b"\r\n").startswith(b"503")

@pytest.fixture
def fake_mx(tmp_path):
    # Port 25 needs root; skip if passwordless sudo isn't available or 25 is taken
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        pytest.skip("needs passwordless sudo to listen on port 25")

    out_dir = tmp_path / "received"
    out_dir.mkdir()
    os.chmod(out_dir, 0o777)

    proc = subprocess.Popen(["sudo", "-n", "python3", FAKE_MX, "127.0.0.1", str(out_dir)])
    time.sleep(1)
    if proc.poll() is not None:
        pytest.skip("could not start the fake MX on 127.0.0.1:25")

    yield out_dir

    subprocess.run(["sudo", "-n", "kill", str(proc.pid)], capture_output=True)
    subprocess.run(["sudo", "-n", "pkill", "-f", "fake_mx.py 127.0.0.1"], capture_output=True)

def jams_dkim_public_key():
    der = subprocess.run(["sudo", "-n", "openssl", "rsa", "-in", "/etc/jams/tls/key.pem", "-pubout", "-outform", "DER"],
                         capture_output=True).stdout
    return base64.b64encode(der).decode()

def test_external_mail_is_relayed_and_dkim_verifies(jams_server, fake_mx):
    # localhost has an A record but no MX, so this also covers the implicit MX fallback
    body = (b"From: CI User <ci-test-user@test.local>\r\nTo: friend@localhost\r\n"
            b"Subject: hello from JAMS\r\nDate: Tue, 27 Oct 2026 10:20:00 -0400\r\n"
            b"Message-ID: <relay-test@test.local>\r\n\r\nThis left the building.\r\n..and kept its dots\r\n")

    with submission_session() as s:
        rcpt_reply, data_reply = send(s, "friend@localhost", body)

    assert rcpt_reply.startswith(b"250"), rcpt_reply
    assert data_reply and data_reply.startswith(b"250"), f"relay failed: {data_reply!r}"

    received = sorted(glob.glob(str(fake_mx / "*.eml")))
    assert received, "nothing arrived at the external MX"

    message = open(received[-1], "rb").read()
    headers, _, content = message.partition(b"\r\n\r\n")
    assert b"DKIM-Signature:" in headers
    assert content.startswith(b"This left the building.") and b".and kept its dots" in content

    pub = jams_dkim_public_key()
    dnsfunc = lambda name, timeout=5: f"v=DKIM1; k=rsa; p={pub}".encode()
    assert dkim.verify(message, dnsfunc=dnsfunc), "the relayed message's DKIM signature did not verify"
