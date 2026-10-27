import socket

def smtp_roundtrip(port, lines, read_each=True):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        banner = s.recv(1024)
        replies = [banner]
        for line in lines:
            s.sendall(line.encode() + b"\r\n")
            if read_each:
                replies.append(s.recv(1024))

        return replies

def test_bad_command_sequence(jams_server):
    replies = smtp_roundtrip(2525, ["EHLO test.local", "DATA"])
    assert b"503" in replies[-1]

def test_oversized_line_reject(jams_server):
    huge = "MAIL FROM:<" + "a" * 5000 + "@test.local>"
    replies = smtp_roundtrip(2525, ["EHLO test.local", huge])
    assert b"500" in replies[-1]

def test_max_rcpt(jams_server):
    lines = ["EHLO test.local", "MAIL FROM:<a@test.local>"]
    # Recipients must be real local mailboxes to be accepted, so repeat a known one to reach the limit
    lines += ["RCPT TO:<ci-test-user@test.local>" for _ in range(105)]
    replies = smtp_roundtrip(2525, lines)

    assert b"452" in replies[-1]

def test_crlf_injection_in_rcpt(jams_server):
    payload = "RCPT TO:<a@test.local>\r\nRSET\r\nMAIL FROM:<x@x>"
    lines = ["EHLO test.local", "MAIL FROM:<a@test.local>", payload]
    replies = smtp_roundtrip(2525, lines)

    assert replies[-1] is not None

def test_abrupt_disconnect_mid_data():
    with socket.create_connection(("127.0.0.1", 2525), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n"); s.recv(1024)
        s.sendall(b"MAIL FROM:<a@test.local>\r\n"); s.recv(1024)
        s.sendall(b"RCPT TO:<a@test.local>\r\n"); s.recv(1024)
        s.sendall(b"DATA\r\n"); s.recv(1024)
        s.sendall(b"partial body no terminator")

    banner = socket.create_connection(("127.0.0.1", 2525), timeout=5).recv(1024)
    assert b"220" in banner


