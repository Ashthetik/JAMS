# tests/integration/test_tls_first_command.py
#
# Clients often send their first command in the same TCP segment as the
# final TLS handshake message. The server must still answer it instead of
# waiting for more data. These tests force that by building the handshake
# with memory BIOs and sending Finished + the first command in one write.
import socket, ssl, pytest

def recv_plain(s, timeout=1.5):
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            s.settimeout(0.4)
    except socket.timeout:
        pass
    return data

def first_command_answered(sock, first_command, expected):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname="localhost")

    def handshake_step():
        try:
            tls.do_handshake()
            return True
        except ssl.SSLWantReadError:
            return False

    done = handshake_step()
    sock.sendall(outgoing.read())

    while not done:
        sock.settimeout(5)
        incoming.write(sock.recv(65536))
        done = handshake_step()
        pending = outgoing.read()

        if done:
            tls.write(first_command)
            sock.sendall(pending + outgoing.read())
        elif pending:
            sock.sendall(pending)

    received = b""
    sock.settimeout(5)
    try:
        while expected not in received:
            chunk = sock.recv(65536)
            if not chunk:
                break
            incoming.write(chunk)
            try:
                while True:
                    received += tls.read(65536)
            except ssl.SSLWantReadError:
                pass
    except socket.timeout:
        pass

    return expected in received

@pytest.mark.parametrize("port", [2525, 2587], ids=["smtp-25", "submission-587"])
def test_smtp_first_command_after_starttls(jams_server, port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        recv_plain(s)
        s.sendall(b"EHLO test.local\r\n"); recv_plain(s)
        s.sendall(b"STARTTLS\r\n")
        assert b"220" in recv_plain(s)

        assert first_command_answered(s, b"EHLO test.local\r\n", b"250"), "EHLO sent with the handshake's last flight was never answered"

def test_imap_first_command_after_starttls(jams_server):
    with socket.create_connection(("127.0.0.1", 2143), timeout=5) as s:
        recv_plain(s)
        s.sendall(b"t1 STARTTLS\r\n")
        assert b"t1 OK" in recv_plain(s)

        assert first_command_answered(s, b"c1 CAPABILITY\r\n", b"c1 OK"), "command sent with the handshake's last flight was never answered"

def test_imaps_first_command(jams_server):
    with socket.create_connection(("127.0.0.1", 2993), timeout=5) as s:
        assert first_command_answered(s, b"c1 CAPABILITY\r\n", b"c1 OK"), "command sent with the handshake's last flight was never answered"
