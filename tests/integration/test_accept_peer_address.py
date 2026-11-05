# tests/integration/test_accept_peer_address.py
import socket, threading, time, pytest

SMTP_PORT = 2525

# [limits] max_connections_per_ip, default 20
PER_IP_CAP = 20

# Two addresses nothing else in the suite touches, so a slot left behind by another
# test can never decide this one. All of 127.0.0.0/8 is loopback on Linux.
FULL_IP = "127.0.0.80"
FREE_IP = "127.0.0.81"

# Each round every thread connects at the same instant, so the listen backlog holds a
# mix of both addresses. Threads per address stays well under PER_IP_CAP so the free
# address can never cap itself out on its own burst.
BURST_THREADS = 6
BURST_ROUNDS = 12
BURST_PER_IP = BURST_THREADS * BURST_ROUNDS

def connect_from(source_ip, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.bind((source_ip, 0))
    s.connect(("127.0.0.1", SMTP_PORT))
    return s

def got_banner(s, timeout=3):
    # A refused connection is accepted and then closed straight away, so recv gives
    # b"" or a reset rather than a 220
    s.settimeout(timeout)
    try:
        return s.recv(64).startswith(b"220")
    except (socket.timeout, ConnectionResetError, OSError):
        return False

class Keepalive(threading.Thread):
    """
    [limits] idle_timeout is 5s in the CI config, so the connections pinning FULL_IP
    to its cap have to keep talking or the sweep frees their slots mid-test and the
    whole premise quietly evaporates.
    """
    def __init__(self, socks):
        super().__init__(daemon=True)
        self.socks = socks
        self.done = threading.Event()

    def run(self):
        while not self.done.wait(1.5):
            for s in self.socks:
                try:
                    s.sendall(b"NOOP\r\n")
                    s.settimeout(2)
                    s.recv(256)
                except OSError:
                    pass

def test_a_burst_does_not_mix_up_which_address_a_connection_came_from(jams_server):
    """
    The accept path used to read the peer address out of a shared member after it had
    already asked the kernel for the next connection, so a connection could be recorded
    under its neighbour's address. Fill one address to its cap, leave another empty, and
    hit both at once: every attempt from the full address must be refused and every
    attempt from the empty one must be served.
    """
    holders = []
    keepalive = None
    try:
        # 1. Pin FULL_IP at exactly the per-address cap
        for _ in range(PER_IP_CAP):
            holders.append(connect_from(FULL_IP))

        greeted = sum(1 for s in holders if got_banner(s, timeout=3))
        assert greeted == PER_IP_CAP, (
            f"precondition: only {greeted} of {PER_IP_CAP} connections from {FULL_IP} were greeted"
        )

        keepalive = Keepalive(holders)
        keepalive.start()

        # 2. FREE_IP has room on a quiet server
        probe = connect_from(FREE_IP)
        try:
            assert got_banner(probe, timeout=3), f"precondition: {FREE_IP} was refused while idle"
        finally:
            probe.close()

        # let the server reap the probe so FREE_IP starts the burst empty
        time.sleep(0.5)

        # 3. Hammer both addresses at the same time so the listen backlog holds a mix
        served = {FULL_IP: 0, FREE_IP: 0}
        lock = threading.Lock()
        round_start = threading.Barrier(BURST_THREADS * 2)

        def burst(source_ip):
            hits = 0
            for _ in range(BURST_ROUNDS):
                try:
                    round_start.wait(timeout=60)
                except threading.BrokenBarrierError:
                    break
                try:
                    s = connect_from(source_ip, timeout=5)
                except OSError:
                    s = None
                if s is not None:
                    try:
                        if got_banner(s, timeout=3):
                            hits += 1
                    finally:
                        s.close()
                # a breath so the loop can reap the sockets this round dropped, otherwise
                # FREE_IP can hit its own cap on closed-but-not-yet-reaped connections
                time.sleep(0.05)
            with lock:
                served[source_ip] += hits

        threads = [
            threading.Thread(target=burst, args=(ip,))
            for ip in (FULL_IP, FREE_IP)
            for _ in range(BURST_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        assert not any(t.is_alive() for t in threads), "burst threads did not finish"

        # 4. The holders must still be up, or step 1 stopped being true partway through
        still_held = 0
        for s in holders:
            try:
                s.sendall(b"NOOP\r\n")
                s.settimeout(3)
                if b"250" in s.recv(256):
                    still_held += 1
            except OSError:
                pass
        assert still_held == PER_IP_CAP, (
            f"precondition: {still_held} of {PER_IP_CAP} connections from {FULL_IP} survived the burst"
        )

        tally = (
            f"served: {FULL_IP} (at its cap) {served[FULL_IP]}/{BURST_PER_IP}, "
            f"{FREE_IP} (empty) {served[FREE_IP]}/{BURST_PER_IP}"
        )

        # An address at its cap must be refused every single time
        assert served[FULL_IP] == 0, (
            f"an address at its connection cap was served anyway, so connections are being "
            f"credited to the wrong address. {tally}"
        )

        # An empty address must be served every time; allow a hair of slack for the
        # server reaping a just-closed socket a moment late
        assert served[FREE_IP] >= BURST_PER_IP - 4, (
            f"an address with no open connections was refused, so connections are being "
            f"credited to the wrong address. {tally}"
        )
    finally:
        if keepalive is not None:
            keepalive.done.set()
            keepalive.join(timeout=5)
        for s in holders:
            s.close()
        # don't hand the next test a capful of connections the server hasn't reaped yet
        time.sleep(0.5)
