# tests/integration/test_dkim_signing.py
#
# Signs messages with JAMS's DKIM signer (via the dkim_sign helper built next
# to the mailserver binary) and verifies them with dkimpy, an independent
# implementation. If these pass, real receivers can verify JAMS's signatures.
import os, base64, subprocess, pytest, dkim

DKIM_SIGN = os.path.join(os.path.dirname(os.environ.get("JAMS_BIN", "")), "dkim_sign")

@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    if not os.path.exists(DKIM_SIGN):
        pytest.skip(f"dkim_sign helper not built at {DKIM_SIGN}")

    key = tmp_path_factory.mktemp("dkim") / "key.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
                   check=True, capture_output=True)
    der = subprocess.run(["openssl", "rsa", "-in", str(key), "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    return str(key), base64.b64encode(der).decode()

def sign(keypair, message):
    key, _ = keypair
    return subprocess.run([DKIM_SIGN, key, "test.local", "jams"], input=message, capture_output=True)

def on_the_wire(signed):
    # The relay sends every line CRLF-terminated, whatever the input used
    return signed.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")

def verifies(keypair, signed):
    _, pub = keypair
    dnsfunc = lambda name, timeout=5: f"v=DKIM1; k=rsa; p={pub}".encode()
    return dkim.verify(on_the_wire(signed), dnsfunc=dnsfunc)

HEADERS = (b"From: Alice <alice@test.local>\r\nTo: bob@example.com\r\n"
           b"Subject: Hello   there\r\nDate: Tue, 27 Oct 2026 10:00:00 -0400\r\n"
           b"Message-ID: <abc@test.local>\r\n")

@pytest.mark.parametrize("body", [
    b"Hi Bob,\r\n\r\nThis is   a test.  \r\n\r\n\r\n",
    b"",
    b"line one\nline two  \n\n",
    b".leading dot\r\n..two dots\r\n",
], ids=["normal", "empty-body", "bare-lf-body", "leading-dots"])
def test_signature_verifies_independently(keypair, body):
    result = sign(keypair, HEADERS + b"\r\n" + body)
    assert result.returncode == 0, result.stderr
    assert verifies(keypair, result.stdout), "dkimpy rejected JAMS's DKIM signature"

def test_body_stays_separated_from_headers(keypair):
    signed = sign(keypair, HEADERS + b"\r\nfirst body line\r\n").stdout
    headers, sep, body = signed.partition(b"\r\n\r\n")
    assert sep, "no blank line between headers and body"
    assert b"DKIM-Signature:" in headers and body.startswith(b"first body line")

def test_no_line_exceeds_smtp_limit(keypair):
    signed = sign(keypair, HEADERS + b"\r\nbody\r\n").stdout
    assert max(len(line) for line in signed.split(b"\r\n")) <= 998

def test_tampered_body_fails(keypair):
    signed = sign(keypair, HEADERS + b"\r\noriginal\r\n").stdout
    assert not verifies(keypair, signed.replace(b"original", b"tampered"))

def test_message_without_separator_is_rejected(keypair):
    assert sign(keypair, b"From: a@test.local\r\nSubject: no body separator").returncode != 0
