import subprocess, socket, time, os, signal, pytest, sys

def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        sys.exit(
            f"Missing required environment variable: {name}\n"
            f"Set it before running the integration suite, e.g.:\n"
            f"  JAMS_BIN=/path/to/mailserver JAMS_CONFIG=/path/to/server.toml pytest tests/integration"
        )
    return val

JAMS_BIN = _require_env("JAMS_BIN")
JAMS_CONFIG = _require_env("JAMS_CONFIG")
PORTS = {
    "smtp": 2525, "submission": 2587,
    "imap4": 2143, "imap4s": 2993
}

def wait_for_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except (ConnectionRefusedError, OSError) as e:
            print(f"Error occurred: {e}")
            time.sleep(0.1)
    return False

@pytest.fixture(scope="session")
def jams_server():
    os.makedirs("/tmp/jams/logs", exist_ok=True)

    # sudo resets the environment, so the pepper and paths have to be passed through explicitly
    sudo = ["sudo", "--preserve-env=JAMS_PEPPER,JAMS_CONFIG,JAMS_LOG_PATH"]

    # Seed the test account first; a non-zero exit just means it already exists from an earlier run
    subprocess.run(
        sudo + [JAMS_BIN, "--add-user", "ci-test-user", "ci-test-password"],
        cwd=os.path.dirname(JAMS_CONFIG),
        timeout=30
    )

    proc = subprocess.Popen(
        sudo + [JAMS_BIN],
        cwd=os.path.dirname(JAMS_CONFIG),
        stdout=open("/tmp/jams/logs/stdout.log", "w"),
        stderr=open("/tmp/jams/logs/stderr.log", "w")
    )

    for name, port in PORTS.items():
        if not wait_for_port(port):
            proc.terminate()
            raise RuntimeError(f"{name} port {port} never came up, check server logs")

    yield proc

    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

# @pytest.fixture(scope="session", autouse=True)
# def seed_test_user():
#     print("starting seed_test_user")
#     subprocess.run(
#         ["sudo", JAMS_BIN, "--add-user", "ci-test-user", "ci-test-password"],
#         check=True,
#         # timeout=30,
#         cwd=os.path.dirname(JAMS_CONFIG)
#     )