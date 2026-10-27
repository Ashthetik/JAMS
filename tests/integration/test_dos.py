import socket, threading, time, pytest

LINE_LIMIT = 2048
SLOW_HOLD_SECONDS = 8
BYTE_INTERVAL = 0.5

def test_many_connections_dos():
    def connect_and_hold():
        try:
            s = socket.create_connection(("127.0.0.1", 2525), timeout=5)
            s.recv(1024)
        except Exception:
            pass

    threads = [threading.Thread(target=connect_and_hold) for _ in range(200)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    banner = socket.create_connection(("127.0.0.1", 2525), timeout=5).recv(1024)
    assert b"220" in banner

def test_slowloris_partial_command():
    stop_event = threading.Event()

    def slow_drip():
        with socket.create_connection(("127.0.0.1", 2525), timeout=15) as s:
            s.recv(1024)
            payload = b"MAIL FROM:<slowloris@evil.test>"
            i = 0
            deadline = time.time() + SLOW_HOLD_SECONDS
            while time.time() < deadline and not stop_event.is_set():
                if i < len(payload):
                    s.sendall(payload[i:i+1])
                    i += 1
                else:
                    s.sendall(b"X")
                time.sleep(BYTE_INTERVAL)

    slow_thread = threading.Thread(target=slow_drip)
    slow_thread.start()

    try:
        time.sleep(1.0)

        for i in range(20):
            start = time.time()
            with socket.create_connection(("127.0.0.1", 2525), timeout=3) as s:
                banner = s.recv(1024)
                assert b"220" in banner
                s.sendall(b"QUIT\r\n")
                s.recv(1024)
            elapsed = time.time() - start
            assert elapsed < 1.0, (
                f"Connection {i} took {elapsed:.2f}s while a slowloris "
                "connection was active — possible resource contention"
            )
    finally:
        stop_event.set()
        slow_thread.join(timeout=SLOW_HOLD_SECONDS + 2)

def test_many_simultaneous_connections():
    NUM_SLOW_CONNS = 50
    sockets = []

    try:
        for _ in range(NUM_SLOW_CONNS):
            # The slow clients come from their own address: one address is capped
            # (max_connections_per_ip), and the point is that everyone else still gets in
            s = socket.create_connection(("127.0.0.1", 2525), timeout=5, source_address=("127.0.0.2", 0))
            s.recv(1024)
            s.sendall(b"MAIL FROM:<slow@evil.test")  
            sockets.append(s)

        time.sleep(2.0)

        with socket.create_connection(("127.0.0.1", 2525), timeout=3) as s:
            banner = s.recv(1024)
            assert b"220" in banner

    finally:
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass

        time.sleep(1.0)
        with socket.create_connection(("127.0.0.1", 2525), timeout=3) as s:
            banner = s.recv(1024)
            assert b"220" in banner

def test_oversized_trickled_line_rejected():
    with socket.create_connection(("127.0.0.1", 2525), timeout=30) as s:
        s.recv(1024)
        chunk = b"A" * 100
        total_sent = 0
        target = LINE_LIMIT + 500

        while total_sent < target:
            s.sendall(chunk)
            total_sent += len(chunk)
            time.sleep(0.05)

        s.settimeout(5)
        reply = s.recv(1024)
        assert b"500" in reply, (
            f"Expected 500 'Line too long' once the trickled line "
            f"exceeded {LINE_LIMIT} bytes, got: {reply!r}"
        )
