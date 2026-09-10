> [!NOTE]
> JAMS - v0.2.1-beta | Experimental  
> Repository: [DeTraced-Security/JAMS](https://github.com/DeTraced-Security/JAMS)  
> Security Contact: [detraced-sec@proton.me](mailto:report@mail.detraced.org)  

---
# Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Building from Source](#building-from-source)
- [Initial Setup](#initial-setup)
- [Running the Server](#running-the-server)
- [Configuration](#configuration)
- [Protocol Support](#protocol-support)
- [Authentication](#authentication)
- [Email Validation (DKIM/SPF/DMARC)](#email-validation-dkimspfdmarc)
- [TLS & Encryption](#tls--encryption)
- [Storage](#storage)
- [Security Notes](#security-notes)
- [Feature Roadmap](#feature-roadmap)
- [Contributing & Bug Reports](#contributing--bug-reports)

---
# Overview
JAMS is a self-hosted mail server designed to be an alternative to providers such as Proton Mail. It’s a client-agnostic project, meaning it can connect to any mail client, such as Thunderbird, Outlook, Apple Mail, etc. over IMAP4 and SMTP. JAMS is written in C++23 and utilises `io_uring` for system-based asynchronous I/O.

### Design Goals
- No Bundled Client - BYOC
- Strong security primitives: TLS1.2+, DKIM/SPF/DMARC, PBKDF2 Password Hashing
- Zero-Access Storage: Messages are encrypted at rest and the server never holds the key
- Minimal dependencies: To eliminate supply-chain vectors, we rely on as little dependencies as possible

---
# Architecture
JAMS spawns four independent threads, each through the `io_uring` event loop:

| Thread | Protocol       | Default Port | Purpose                              |
| ------ | -------------- | ------------ | ------------------------------------ |
| 1      | ESMTP Inbound  | 25           | Receives mail from remote MTAs       |
| 2      | ESMTP Outbound | 587          | Authenticated outbound mail          |
| 3      | IMAP4          | 143          | Client Access (plaintext + STARTTLS) |
| 4      | IMAP4S         | 993          | Client Access (TLS from Connect)     |
```
External MTA -- (25) --> ESMTP Inbound --> Maildir Storage
Mail Client -- (587) --> ESMTP Outbound --> Outbound Relay
Mail Client -- (143) --> IMAP4 --> Maildir Read/Write
Mail Client -- (993) --> IMAP4S --> Maildir Read/Write
```
No mutable state is shared between threads to ensure data integrity and security. The SQLite3 credential store and TLS context are initialised once at start-up and accessed as read-only form thereafter.

### Source Layout
```
src/

├── main.cpp # Entry point, thread spawning, signal handling
├── globals.hpp # Global shutdown flag
├── io/ 
├── io_uring_loop.hpp/.cpp # Core async event loop (io_uring wrapper)
│ └── session_factory.hpp # Pluggable session factory pattern
├── smtp/
│ ├── smtp_session.hpp/.cpp # Inbound SMTP (port 25)
│ └── submission_server.hpp/.cpp # Submission server (port 587)
├── imap/
│ └── imap_session.hpp/.cpp # IMAP4 + IMAP4S (ports 143 / 993)
├── tls/
│ ├── tls_context.hpp/.cpp # OpenSSL context management
│ └── tls_conn.hpp/.cpp # TLS wrapper (memory BIO pattern)
├── auth/
│ ├── cred_store.hpp/.cpp # SQLite-backed user database
│ ├── sasl.hpp/.cpp # SASL PLAIN / LOGIN
│ ├── dkim_verifier.hpp/.cpp # DKIM signature verification (RFC 6376)
│ ├── spf_checker.hpp/.cpp # SPF evaluation (RFC 7208)
│ └── dmarc_checker.hpp/.cpp # DMARC policy (RFC 7489)
├── dns/
│ ├── dns_resolver.hpp/.cpp # Async stub resolver (io_uring UDP)
│ ├── dns_message.hpp/.cpp # DNS message parsing/encoding
│ └── dns_types.hpp # DNS record types
├── storage/
│ └── maildir.hpp/.cpp # Maildir format delivery
```

---
# Prerequisites
### Build Dependencies

| Dependency      | Min Version                | Ubuntu/Debian                                                                                | Fedora/RHEL                                                                 |
| --------------- | -------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| CMake           | 3.22                       | `apt install cmake`                                                                          | `dnf install cmake`                                                         |
| GCC/Clang/Ninja | C++23 (GCC 13+, Clang 17+) | - `apt install g++` (or `apt install gcc`)<br>- `apt install clang`<br>- `apt install ninja` | - `dnf install gcc`<br>- `dnf install clang`<br>- `dnf install ninja-build` |
| liburing        | Any Recent                 | `apt install liburing-dev`                                                                   | `dnf install liburing-devel`                                                |
| OpenSSL         | 1.1+                       | `apt install libssl-dev`                                                                     | `dnf install openssl-devel`                                                 |
| SQLite3         | 3.x+                       | `apt install libsqlite3-dev`                                                                 | `dnf install sqlite`                                                        |
### Runtime Requirements
- Linux Kernel 5.1+ - Required for `io_uring`
- Directories `/var/lib/jams`, `/var/mail/vhosts/` (see [[#Initial Setup]])
- A TLS Certificate and Private Key (for IMAP4S and STARTTLS)
- `CAP_NET_BIND_SERVICE` to bind ports below 1024

---
# Building From Source
```sh
git clone https://github.com/DeTraced-Security/JAMS.git
cd JAMS

# Release build (optimised, -O3)
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Debug build (AddressSanitizer + UBSan)
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```
The output binary is `build/mailserver`

---

# Initial Setup
1. Create required directories
```sh
sudo mkdir -p /var/lib/jams
sudo mkdir -p /var/mail/vhosts

# Set ownership to the user running JAMS
sudo chown -R mailserver:mailserver /var/lib/jams /var/mail/vhosts
```
2. Grant port-binding capability
```sh
sudo setcap cap_net_bind_service=+ep ./build/mailserver
```

3. Obtain a TLS certificate
JAMS requires a certificate and private key for IMAP4S and STARTTLS, it’s recommended to use Certbot for this, but if such a service is unavailable, you can self-sign with the following:
```sh
sudo openssl req -x509 -newkey rsa:4096 \
	-keyout /etc/jams/key.pem \
	-out /etc/jams/cert.pem \
	-days 365 -nodes \
	-subj "/CN=your.maildomain.com"
```

4. Add Users
The SQLite DB is created automatically by JAMS at `/var/lib/jams/users.db` or next to the mailserver binary on first run. The Schema is as follows:
```sql
CREATE TABLE users (
	username TEXT PRIMARY KEY,
	hash TEXT NOT NULL,
	salt TEXT NOT NULL,
	iterations INTEGER NOT NULL,
	active INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL
);
```
> [!WARNING]
> Never insert plaintext passwords. Passwords must be stored as PBKDF2-HMAC-SHA256 (100,000 iterations). A user-management CLI is planned, until then use the `CredentialStore` API in the `main.cpp`  
>  
> You can do so with the following after the CredentialStore initialisation:

```cpp
const bool user_create = cred_store.add_user("username", "password");
if (!user_create) {
	std::cerr << "[JAMS - CredStore] Failed to create user!" << std::endl;
}
```

---
# Running the Server
```sh
./build/mailserver [options]
```
### Command-Line Options

| Flag                 | Default                  | Description          |
| -------------------- | ------------------------ | -------------------- |
| `--smtp-port <port>` | 25                       | Inbound ESMTP Port   |
| `--db <path>`        | `/var/lib/jams/users.db` | Path to User DB      |
| `--help`             | —                        | Print Usage and Exit |
#### Example
```sh
./build/mailserver --smtp-port 25 --db ./users.db
```
The server will print the start banner, initialise all four listeners and run until an issued `SIGINT` or `SIGTERM` signal is received. All threads will then proceed to gracefully shutdown.

#### Systemd Service
```service
# /etc/systemd/system/jams.service
[Unit]
Description=JAMS Mail Server
After=network.target

[Service]
Type=simple
User=mailserver
ExecStart=/usr/local/bin/mailserver --db /var/lib/jams/users.db
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now jams
```

---
# Configuration
Below is a table of configurable variables in JAMS, which can be changed with the `config/server.toml` file and their respective source files:

| Parameter                  | Current Value            | Source File                 |
| -------------------------- | ------------------------ | --------------------------- |
| Server Hostname            | mail.detraced.org        | `src/smtp/smtp_session.cpp` |
| Mail Root                  | `/var/mail/vhosts`       | `src/storage/maildir.hpp`   |
| DB Path                    | `/var/lib/jams/users.db` | `src/main.cpp`              |
| IMAP4 Port                 | 143                      | `src/main.cpp`              |
| IMAP4S Port                | 993                      | `src/main.cpp`              |
| Outbound (Submission) Port | 587                      | `src/main.cpp`              |
| Max Message Size           | 50MB                     | `src/smtp/smtp_session.cpp` |
| Max Recipients             | 100                      | `src/smtp/smtp_session.cpp` |

> [!NOTE]
> Max Message Size and Max Recipients is non-configurable to better align with their applicable RFCs and will be made configurable once JAMS has reached it's stable release (v1.0.0)

---
# Protocol Support
### ESMTP Inbound - Port 25
Receives mail from remote MTAs with the following commands:
- EHLO, HELO
- MAIL FROM, RCPT TO, DATA
- REST, NOOP, QUIT
- STARTTLS

Limits:

| Limit                   | Value      |
| ----------------------- | ---------- |
| Max Line Length         | 2048 bytes |
| Max Message Size        | 50MB       |
| Max Recipients Per Mail | 100        |
### ESMTP Outbound (Submission) - Port 587
For authenticated users sending mail. Differences from Inbound:
- `STARTTLS` must be negotiated before AUTH
- AUTH PLAIN or AUTH LOGIN is required before MAIL FROM
- No SPF/DKIM/DMARC checking - User is Trusted. Will correct this in future

### IMAP4(S) - Ports 143/993
Commands available per connection state:

| State             | Commands                                                      |
| ----------------- | ------------------------------------------------------------- |
| Any               | CAPABILITY, NOOP, LOGOUT                                      |
| Not Authenticated | STARTTLS (143 only), LOGIN, AUTHENTICATE                      |
| Authenticated     | SELECT, EXAMINE, LIST, LSUB, STATUS, CREATE                   |
| Selected          | FETCH, STORE, EXPUNGE, CHECK, CLOSE, UID SEARCH, APPEND, IDLE |
Standard mailboxes are created automatically per user on first access: `INBOX`/`Inbox`, `Drafts`, `Sent`, `Trash`, `Spam`, `Archive`.

#### IDLE
JAMS supports `IDLE` for push-like notifications. While a client is in IDLE, the server polls `Maildir/new` and sends `* N EXISTS` upon new arrivals.

#### Encrypted Storage (Planned)
JAMS, when implemented, will hold message bodies at rest under LZ-Compressed AES-256-GCM encrypted ciphertext. The server will never hold the decryption keys or plaintext data on the disk, unless where necessary and no other route can be taken. Compatible clients will detect the `X-JAMS-Encrypted` header and decrypt locally, on the user’s device.

---

# Authentication
### Credential Store

| Property   | Value                                   |
| ---------- | --------------------------------------- |
| Backend    | SQLite3                                 |
| Algorithm  | PBKDF2-HMAC-SHA256                      |
| Iterations | 100,000                                 |
| Salt       | Random (Per-User)                       |
| Comparison | Constant-Time (Timing-Attack Resistant) |
### SASL Mechanism
Supported on ESMTP (Submission) Outbound (587) and IMAP4:

| Mechanism | RFC      | Notes                       |
| --------- | -------- | --------------------------- |
| PLAIN     | RFC-4616 | Requires Active TLS Session |
| LOGIN     | RFC-4954 | Challenge-Response Variant  |
Maximum authentication attempts before disconnect: 3

> [!WARNING]
> `AUTH` on port 587 requires an active `STARTTLS` session. Credentials will never be transmitted in plaintext.

---
# Email Validation (DKIM/SPF/DMARC)
All three major anti-spoofing standards are implemented for inbound mail. DNS queries are issued asynchronously via the build-in `io_uring` stub resolver.

### SPF - RFC-7208
Evaluates the connecting server’s IP against the sender’s domain’s DNS Records.
- Supported mechanisms: `all`, `include`, `a`, `mx`, `ip4`, `ip6`
- IPv4 and IPv6 CIDR matching
- Enforces the RFC 7208 limit of **10 DNS lookups** per evaluation

### DKIM - RFC 6376
Verifies the cryptographic signatures on inbound messages.
- Algorithms: `rsa-sha256`, `ed25519-sha256`
- Canonicalisations: `relaxed` and `simple` (header + body)
- Public keys fetched via async DNS and cached per session

### DMARC - RFC 7489
Evaluates alignment between the `FROM:` domain and SPF/DKIM results.

| Property  | Detail                                       |
| --------- | -------------------------------------------- |
| Policies  | `none`, `quarantine`, `reject`               |
| Alignment | `relaxed` (default) or `strict` for SPF/DKIM |
| Sampling  | `pct=` field partially implemented           |

> [!WARNING]
> Parsing and verification are complete. Policy enforcement is not yet wired together into the delivery pipeline

---
# TLS and Encryption

| Property         | Value                                |
| ---------------- | ------------------------------------ |
| Minimum Version  | TLS 1.2+                             |
| Compression      | Disabled                             |
| Preferred Suites | ECDHR FS suites (to be implemtented) |
| Implementation   | OpenSSL with memory BIOs             |
The memory BIO pattern decouples the TLS state from the sockets. `TlsConn` object is completely independent from the file descriptors making it testable and reusable across connection types.

---
# Storage
Mail is stored in the Maildir format under `/var/mail/vhosts/<domain>/<user>/`
```
/var/mail/vhosts/

└── example.com/

└── alice/

├── INBOX/

│ ├── tmp/ <- in-flight delivery (incomplete writes)

│ ├── new/ <- delivered, unread

│ └── cur/ <- read messages (with flag suffixes)

├── Sent/

├── Drafts/

├── Trash/

├── Spam/

└── Archive/
```
Atomic Delivery: messages are written to `tmp/` before being renamed to `new/`, meaning a crash mid-way through the delivery leaves an orphaned `tmp/` file that cannot corrupt the rest of the mail system.

Message filenames are encoded with a UNIX timestamp (unique), byte size, and IMAP Flag Suffix.

--- 
# Security Notes
> [!CAUTION]
> Known Limitations in Current Experimental Release

| Issue                                            | Risk                                                   | Roadmap Status                 |
| ------------------------------------------------ | ------------------------------------------------------ | ------------------------------ |
| Plaintext Storage (messages)                     | Local confidentiality breach if storage is compromised | Zero-Access Encryption Planned |
| No Rate-Limit/Throttling                         | (D)DoS and Brute-Force Exposure                        | Not Started                    |
| DMARC/SPF/DKIM Policies not Enforced at Delivery | Spoofed mail may be accepted                           | In Progress                    |
| No Outbound DKIM Signing                         | Outbound Delivery & Authenticity                       | Planned                        |
These are acknowledged gaps, and will be fixed across staged versions (vx.y.z, alpha/beta/stable). It is NOT recommend to run JAMS, in its current state, in a production environment or environments handling sensitive data until the aforementioned items are resolved.

### Responsible Disclosure
Report security vulnerabilities to [detraced-sec@proton.me](mailto:detraced-sec@proton.me) with a detailed description. Issues are triaged within **28 days**. See [[SECURITY]] for the full policy.

**Do not open a public GitHub issue for security vulnerabilities.**
