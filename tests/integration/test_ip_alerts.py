# tests/integration/test_ip_alerts.py
import os, re, socket, ssl, time, pytest

IMAP_PORT = 2143

def alert_mailbox():
    # [reporting] ip_alert_mta in the test config; the CI fixture points it at traversal-victim
    text = open(os.environ["JAMS_CONFIG"]).read()
    m = re.search(r'^\s*ip_alert_mta\s*=\s*"([^"@]+)@', text, re.M)
    return m.group(1) if m else None

PASSWORDS = {"traversal-victim": "victim-password", "ci-test-user": "ci-test-password"}

def recv_until(s, pattern, timeout=10):
    s.settimeout(timeout)
    data = b""
    try:
        while not re.search(pattern, data):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data

def imap_from(source_ip):
    raw = socket.create_connection(("127.0.0.1", IMAP_PORT), timeout=10, source_address=(source_ip, 0))
    recv_until(raw, rb"\r\n")
    raw.sendall(b"t1 STARTTLS\r\n")
    recv_until(raw, rb"t1 ")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname="localhost")

def login(source_ip, user="ci-test-user"):
    s = imap_from(source_ip)
    try:
        s.sendall(f"a1 LOGIN {user} {PASSWORDS[user]}\r\n".encode())
        reply = recv_until(s, rb"a1 (OK|NO|BAD)")
        if b"a1 OK" not in reply:
            pytest.skip(f"couldn't log in as {user} from {source_ip}: {reply!r}")
    finally:
        s.close()

def alerts_in(mailbox):
    # Read over IMAP: in CI the server runs as root and Maildirs are 0700
    s = imap_from("127.0.0.1")
    try:
        s.sendall(f"a1 LOGIN {mailbox} {PASSWORDS[mailbox]}\r\n".encode())
        recv_until(s, rb"a1 (OK|NO)")
        s.sendall(b"a2 SELECT INBOX\r\n")
        count = int(re.search(rb"\* (\d+) EXISTS", recv_until(s, rb"a2 (OK|NO)")).group(1))
        if count == 0:
            return []
        s.sendall(f"a3 FETCH 1:{count} (BODY[])\r\n".encode())
        data = recv_until(s, rb"a3 (OK|NO|BAD)", timeout=20)
        return [m for m in re.split(rb"\* \d+ FETCH", data) if b"Login from a new IP" in m]
    finally:
        s.close()

def wait_for_alerts(mailbox, expected, timeout=10):
    deadline = time.time() + timeout
    found = alerts_in(mailbox)
    while len(found) < expected and time.time() < deadline:
        time.sleep(0.5)
        found = alerts_in(mailbox)
    return found

@pytest.fixture
def mailbox(jams_server):
    name = alert_mailbox()
    if name not in PASSWORDS:
        pytest.skip("needs [reporting] ip_alert_mta pointing at a seeded test mailbox")
    return name

def test_alert_fires_once_per_new_address(mailbox):
    login("127.0.0.70")  # whatever came before, this is now the known address
    time.sleep(2)        # let any alert from that settle
    before = len(alerts_in(mailbox))

    login("127.0.0.70")
    login("127.0.0.71")  # new address: one alert
    login("127.0.0.71")  # same address again: no more
    found = wait_for_alerts(mailbox, before + 1)
    time.sleep(2)
    found = alerts_in(mailbox)

    assert len(found) == before + 1, f"expected exactly one new alert, got {len(found) - before}"
    assert b"ci-test-user" in found[-1] and b"127.0.0.71" in found[-1], "the alert should name the user and the new address"

def test_wrong_password_never_alerts(mailbox):
    login("127.0.0.72")
    time.sleep(2)
    before = len(alerts_in(mailbox))

    s = imap_from("127.0.0.73")
    try:
        s.sendall(b"a1 LOGIN ci-test-user wrong-password\r\n")
        assert b"a1 NO" in recv_until(s, rb"a1 (OK|NO)")
    finally:
        s.close()

    time.sleep(3)
    assert len(alerts_in(mailbox)) == before, "a failed login from a new address sent an alert"
