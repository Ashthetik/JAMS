"""
Test helper: a minimal receiving MTA for outbound relay tests.

Listens on <address>:25, accepts every message, and writes each one (with
dot-stuffing removed) to <output-dir>/<n>.eml, readable by everyone.
Port 25 is privileged, so tests start it with sudo.

Usage: fake_mx.py <address> <output-dir>
"""
import os, socket, sys

address, out_dir = sys.argv[1], sys.argv[2]

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((address, 25))
server.listen(5)

count = 0
while True:
    conn, _ = server.accept()
    stream = conn.makefile("rb")
    conn.sendall(b"220 fake-mx ESMTP\r\n")

    data, in_data = b"", False
    for line in stream:
        if in_data:
            if line == b".\r\n":
                in_data = False
                count += 1
                path = os.path.join(out_dir, f"{count}.eml")
                with open(path, "wb") as f:
                    f.write(data)
                os.chmod(path, 0o644)
                data = b""
                conn.sendall(b"250 queued\r\n")
            else:
                data += line[1:] if line.startswith(b"..") else line
            continue

        command = line.strip().upper()
        if command.startswith(b"EHLO"):
            conn.sendall(b"250-fake-mx\r\n250 8BITMIME\r\n")
        elif command.startswith(b"DATA"):
            in_data = True
            conn.sendall(b"354 go ahead\r\n")
        elif command.startswith(b"QUIT"):
            conn.sendall(b"221 bye\r\n")
            break
        else:
            conn.sendall(b"250 ok\r\n")

    conn.close()
