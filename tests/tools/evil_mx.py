"""
Test helper: a deliberately hostile receiving MTA for outbound relay tests.

JAMS dials out to whatever MX a recipient domain names, so the far end of a
relay is allowed to be anything at all. This plays the "anything at all" cases
that a cooperative fake_mx.py can't.

Listens on <address>:25 and answers every connection according to <mode>:

  badcode  greets, then repeats "250\\r\\n" forever. The 4th character is '\\r',
           which is neither ' ' (the last line of a reply) nor '-' (a line with
           more to follow), so a parser that only looks for ' ' reads it as an
           endless continuation.
  nocrlf   greets, then streams bytes and never a line ending, so a reader that
           accumulates until CRLF accumulates forever.

Port 25 is privileged, so tests start it with sudo. It appends one line per
accepted connection to <conn-log>, which is how a test tells "the relay gave up
and the next one started" from "the relay pool is gone". It also exits on its
own after <lifetime-seconds>, so a crashed test can never leave it holding
port 25.

Usage: evil_mx.py <address> <mode> <conn-log> [lifetime-seconds]
"""
import os, socket, sys, threading, time

address, mode, conn_log = sys.argv[1:4]
lifetime = float(sys.argv[4]) if len(sys.argv) > 4 else 120.0

if mode not in ("badcode", "nocrlf"):
    raise SystemExit(f"unknown mode: {mode}")

log_lock = threading.Lock()


def note(text):
    with log_lock:
        with open(conn_log, "a") as f:
            f.write(text + "\n")
        os.chmod(conn_log, 0o666)


def handle(conn):
    try:
        conn.sendall(b"220 evil-mx ESMTP\r\n")
        payload = b"250\r\n" if mode == "badcode" else b"A" * 4096
        pause = 0.02 if mode == "badcode" else 0.01

        while True:
            conn.sendall(payload)
            time.sleep(pause)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def expire():
    time.sleep(lifetime)
    os._exit(0)


server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((address, 25))
server.listen(16)

note(f"listening {address}:25 mode={mode}")
threading.Thread(target=expire, daemon=True).start()

while True:
    conn, _ = server.accept()
    note("accepted")
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
