#include "auth/credentials/cred_store.hpp"
#include "globals.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#include <unistd.h>

using namespace Auth;

CredentialStore::CredentialStore(const std::string& db_path) {
    int db = sqlite3_open(db_path.c_str(), &db_);

    if (db != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db_);
        sqlite3_close_v2(db_);
        db_ = nullptr;

        logger.error("[FATAL] [CREDSTORE] Failed to open DB: " + err);
        throw std::runtime_error("[CredStore] Failed to open DB: " + err);
    }

    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA foreign_keys=ON");
    ensure_schema();

    logger.info("[AUTH] Credential Store opened: " + db_path);
}

CredentialStore::~CredentialStore() {
    if (db_) {
        sqlite3_close_v2(db_);
    }
}

void CredentialStore::ensure_schema() {
    exec(R"sql(
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                iterations INTEGER NOT NULL DEFAULT 100000,
                active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                last_known_ip TEXT
            );

            CREATE TABLE IF NOT EXISTS aliases (
                alias TEXT PRIMARY KEY, -- full address
                username TEXT NOT NULL, -- target account
                active INTEGER NOT NULL DEFAULT 1,
                max_uses INTEGER,
                uses_count INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS alias_allowed_domains (
                alias TEXT NOT NULL,
                domain TEXT NOT NULL,
                PRIMARY KEY (alias, domain),
                FOREIGN KEY (alias) REFERENCES aliases(alias) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS message_purge_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alias TEXT NOT NULL,
                username TEXT NOT NULL,
                maildir_path TEXT NOT NULL,
                purge_at INTEGER NOT NULL,
                FOREIGN KEY (alias) REFERENCES aliases(alias) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_purge_queue_time ON message_purge_queue(purge_at);
            CREATE INDEX IF NOT EXISTS idx_aliases_username ON aliases(username);
        )sql");
}

namespace {
    /**
     * Sends the "login from a new IP" alert. Runs on the alert worker, never on an
     * event loop: it's a blocking SMTP conversation, and on the IMAP thread an
     * unreachable server froze mail reading for everyone (H3).
     * It hands the alert to JAMS's own SMTP listener on loopback, so the configured
     * ip_alert_mta has to be a local mailbox (port 25 only takes local recipients)
     */
    void send_unknown_ip_alert(const std::string& username, const std::string& ip) {
        const std::string alert_to{ get_ip_reporter() };
        if (alert_to.empty()) {
            logger.warn("[AUTH] New IP login for " + username + " from " + ip + ", but [reporting] ip_alert_mta isn't set");
            return;
        }

        const std::string alert_from{ "no-reply@" + get_hostname() };
        const std::string msg =
            "From: JAMS Security <" + alert_from + ">\r\n"
            "To: <" + alert_to + ">\r\n"
            "Subject: JAMS: Login from a new IP - " + username + "\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "A login was made from an IP address this account hasn't used before.\r\n\r\n"
            "Username : " + username + "\r\n"
            "IP       : " + ip + "\r\n";

        uint16_t port = 25;
        if (auto itr = configs.find("smtp"); itr != configs.end()) {
            try {
                port = static_cast<uint16_t>(std::stoi(itr->second));
            }
            catch (const std::exception&) {
            }
        }

        int sock = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sock < 0) {
            logger.error("[AUTH] IP alert: socket() failed: " + std::string(strerror(errno)));
            return;
        }

        struct timeval tv { .tv_sec = 10, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            logger.error("[AUTH] IP alert: connect to 127.0.0.1:" + std::to_string(port) + " failed: " + std::string(strerror(errno)));
            ::close(sock);
            return;
        }

        std::string pending;
        // Reads one full reply (all continuation lines) and checks its code
        auto expect = [&](const char* code) -> bool {
            while (true) {
                auto eol = pending.find("\r\n");
                if (eol != std::string::npos) {
                    std::string line = pending.substr(0, eol);
                    pending.erase(0, eol + 2);

                    if (line.size() >= 4 && line[3] == '-') {
                        continue; // more lines of the same reply
                    }

                    return line.compare(0, 3, code) == 0;
                }

                char buf[512];
                ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
                if (n <= 0) {
                    return false;
                }

                pending.append(buf, static_cast<size_t>(n));
            }
            };

        auto send_all = [&](const std::string& data) -> bool {
            size_t sent = 0;
            while (sent < data.size()) {
                ssize_t n = ::send(sock, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
                if (n <= 0) {
                    return false;
                }
                sent += static_cast<size_t>(n);
            }
            return true;
            };

        struct Step {
            const char* name;
            std::string line; // empty: just read the server's reply
            const char* code;
        };

        const Step steps[] = {
            { "greeting", "", "220" },
            { "EHLO", "EHLO " + get_hostname() + "\r\n", "250" },
            { "MAIL FROM", "MAIL FROM:<" + alert_from + ">\r\n", "250" },
            { "RCPT TO", "RCPT TO:<" + alert_to + ">\r\n", "250" },
            { "DATA", "DATA\r\n", "354" },
            { "message", msg + "\r\n.\r\n", "250" },
        };

        const char* failed_at = nullptr;
        for (const auto& step : steps) {
            if ((!step.line.empty() && !send_all(step.line)) || !expect(step.code)) {
                failed_at = step.name;
                break;
            }
        }

        send_all("QUIT\r\n");
        ::close(sock);

        if (failed_at) {
            logger.error("[AUTH] IP alert for " + username + " to " + alert_to + " failed at " + failed_at);
        }
        else {
            logger.info("[AUTH] New IP alert sent for: " + username);
        }
    }

    // One background thread sends the alerts, in order, so a slow mail server only ever delays alerts
    class AlertWorker {
    public:
        AlertWorker() : thread_([this]() { run(); }) {}

        ~AlertWorker() {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stop_ = true;
            }

            cv_.notify_all();
            thread_.join();
        }

        void submit(std::function<void()> job) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                jobs_.push_back(std::move(job));
            }

            cv_.notify_one();
        }

    private:
        void run() {
            while (true) {
                std::function<void()> job;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    cv_.wait(lock, [this]() { return stop_ || !jobs_.empty(); });

                    if (jobs_.empty()) {
                        return; // stopping, and nothing left to send
                    }

                    job = std::move(jobs_.front());
                    jobs_.pop_front();
                }

                try {
                    job();
                }
                catch (const std::exception& ex) {
                    logger.error("[AUTH] IP alert worker: " + std::string(ex.what()));
                }
            }
        }

        std::mutex mutex_;
        std::condition_variable cv_;
        std::deque<std::function<void()>> jobs_;
        bool stop_{ false };
        std::thread thread_; // last, so it starts after everything it uses
    };

    void notify_unknown_ip(const std::string& username, const std::string& ip) {
        static AlertWorker worker;
        worker.submit([username, ip]() { send_unknown_ip_alert(username, ip); });
    }
}

bool CredentialStore::add_user(const std::string& username, const std::string& passwd, const std::string& ip) {
    if (username.empty() || passwd.empty()) {
        return false;
    }

    // Same allowlist as verify(), otherwise the account could never log in
    for (const char c : username) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_' && c != '+') {
            logger.warn("[AUTH] add_user rejected unsafe username");
            return false;
        }
    }

    if (user_exists(username)) {
        return false;
    }

    auto hashed = hash_password(passwd, username);
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    /**
     * Accounts created offline (e.g. via --add-user) have no known IP yet.
     * Storing NULL rather than a hash of "" means the first real login isn't
     * treated as an unknown-IP login.
     */
    const bool has_ip = !ip.empty();
    auto hashed_ip = has_ip ? hash_data(ip) : HashedPassword{};

    // SQLite Statement
    sqlite3_stmt* stmt = nullptr;
    const char* sql =
        "INSERT INTO users (username, hash, iterations, active, created_at, last_known_ip) "
        "VALUES (?, ?, ?, 1, ?, ?)";

    // Prepare the statement
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    // Bind the values to avoid SQL Injection via concatenation
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashed.hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, hashed.iterations);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(now));
    if (has_ip) {
        sqlite3_bind_text(stmt, 5, hashed_ip.hash.c_str(), -1, SQLITE_STATIC);
    }
    else {
        sqlite3_bind_null(stmt, 5);
    }

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt); // Construct the statement with the binds

    if (ok) {
        logger.info("[AUTH] User added: " + username);
    }
    else {
        logger.error("[AUTH] add_user failed: " + std::string(sqlite3_errmsg(db_)));
    }

    return ok;
}

bool CredentialStore::verify(const std::string& username, const std::string& passwd, const std::string& ip) {
    // Username safety check
    for (char c : username) {
        if (!std::isalnum(c) && c != '.' && c != '-' && c != '_' && c != '+') {
            logger.warn("[AUTH] rejected unsafe username");
            return false;
        }
    }

    if (username.empty() || passwd.empty()) {
        return false;
    }

    // Checked before anything expensive, so a guessing address stops costing us PBKDF2 runs
    if (is_throttled(ip)) {
        logger.warn("[AUTH] refusing login for " + username + " from " + ip + ": too many failed logins");
        return false;
    }

    try {
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT hash, iterations, last_known_ip FROM users "
            "WHERE username = ? AND active = 1";

        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            logger.error("[auth] SQL Account Verification perpare failed: " + std::string(sqlite3_errmsg(db_)));
            return false;
        }

        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        bool user_found = false;
        std::string stored_hash, salt, stored_ip;
        int iterations = 100000;

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* hash_cstr = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 0)
                );
            const char* ip_cstr = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 2)
                );
            // Safe-guard against potential NULL values that may crash the call
            if (!hash_cstr) {
                sqlite3_finalize(stmt);
                return false;
            }

            if (ip_cstr) {
                stored_ip = ip_cstr;
            }

            stored_hash = hash_cstr;
            iterations = sqlite3_column_int(stmt, 1);

            user_found = true;
        }

        sqlite3_finalize(stmt);

        /**
         * Constant-Time evaluation - timing attack prevention.
         * Unknown users get the same derived salt and the same PBKDF2 run. The old
         * "deadbeef" stand-in was too short for pbkdf2(), which threw before hashing,
         * so a missing account answered ~100x faster than a wrong password
         */
        salt = derive_salt(username);
        std::string computed = pbkdf2(passwd, salt, iterations);

        const bool auth_ok = constant_time_eq(computed, stored_hash);

        if (!user_found || !auth_ok) {
            record_failure(ip);
            return false;
        }

        // The IP hash is another full PBKDF2 run, so only a correct password earns it
        std::string ip_hash = hash_data(ip).hash;

        if (ip_hash != stored_ip) {
            // The first login just records the address; after that, only a change alerts
            if (!stored_ip.empty()) {
                notify_unknown_ip(username, ip);
            }

            remember_ip(username, ip_hash);
        }

        return true;
    }
    catch (const std::exception& ex) {
        logger.error("[AUTH] verify() exception: " + std::string(ex.what()));
        return false;
    }
}

bool CredentialStore::is_throttled(const std::string& ip) {
    // Local webmail and proxies log in for every user from loopback, so one
    // user's typos there must not lock everyone else out
    if (ip == "127.0.0.1") {
        return false;
    }

    std::lock_guard<std::mutex> lock(failures_mutex_);

    auto itr = failures_.find(ip);
    if (itr == failures_.end()) {
        return false;
    }

    if (std::chrono::steady_clock::now() - itr->second.start >= AUTH_FAILURE_WINDOW) {
        failures_.erase(itr);
        return false;
    }

    return itr->second.count >= MAX_AUTH_FAILURES;
}

void CredentialStore::record_failure(const std::string& ip) {
    if (ip == "127.0.0.1") {
        return;
    }

    std::lock_guard<std::mutex> lock(failures_mutex_);
    auto now = std::chrono::steady_clock::now();

    // Keep the table from growing forever under a spread-out attack
    if (failures_.size() >= 4096) {
        std::erase_if(failures_, [&now](const auto& entry) {
            return now - entry.second.start >= AUTH_FAILURE_WINDOW;
            });
    }

    auto& window = failures_[ip];
    if (window.count == 0 || now - window.start >= AUTH_FAILURE_WINDOW) {
        window = FailureWindow{ 0, now };
    }

    if (++window.count == MAX_AUTH_FAILURES) {
        logger.warn("[AUTH] " + ip + " reached " + std::to_string(MAX_AUTH_FAILURES) + " failed logins, refusing it for the rest of the window");
    }
}

void CredentialStore::remember_ip(const std::string& username, const std::string& ip_hash) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE users SET last_known_ip = ? WHERE username = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[AUTH] remember_ip prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return;
    }

    sqlite3_bind_text(stmt, 1, ip_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        logger.error("[AUTH] remember_ip failed: " + std::string(sqlite3_errmsg(db_)));
    }

    sqlite3_finalize(stmt);
}

bool CredentialStore::deactivate_user(const std::string& username) {
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(
        db_, "UPDATE users SET active = 0 WHERE username = ?",
        -1, &stmt, nullptr
    ) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    return ok;
}

bool CredentialStore::activate_user(const std::string& username) {
    sqlite3_stmt* stmt{ nullptr };

    if (sqlite3_prepare_v2(
        db_, "UPDATE users SET active = 1 WHERE username = ?",
        -1, &stmt, nullptr
    ) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    return ok;
}

bool CredentialStore::change_password(
    const std::string& username, const std::string& old_passwd,
    const std::string& new_passwd
) {
    if (old_passwd.empty() || new_passwd.empty() || username.empty()) {
        return false;
    }

    sqlite3_stmt* sel{ nullptr };
    if (sqlite3_prepare_v2(db_, "SELECT hash, iterations FROM users WHERE username = ?", -1, &sel, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(sel, 1, username.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(sel) != SQLITE_ROW) {
        sqlite3_finalize(sel);
        return false;
    }

    std::string stored_hash = reinterpret_cast<const char*>(sqlite3_column_text(sel, 0));
    const std::string stored_salt = derive_salt(username);
    const int stored_iterations = sqlite3_column_int(sel, 1);

    sqlite3_finalize(sel);

    auto check = hash_password(old_passwd, username, stored_iterations);
    if (!constant_time_eq(check.hash, stored_hash)) {
        return false;
    }

    auto hashed_new = hash_password(new_passwd, username, 100000);
    sqlite3_stmt* upd{ nullptr };

    if (sqlite3_prepare_v2(db_, "UPDATE users SET hash = ?, iterations = ? WHERE username = ?", -1, &upd, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(upd, 1, hashed_new.hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(upd, 2, hashed_new.iterations);
    sqlite3_bind_text(upd, 3, username.c_str(), -1, SQLITE_STATIC);

    bool ok = (sqlite3_step(upd) == SQLITE_DONE);
    sqlite3_finalize(upd);

    return ok && sqlite3_changes(db_) > 0;
}

std::string CredentialStore::derive_salt(const std::string& data) {
    const char* pepper = std::getenv("JAMS_PEPPER");
    if (!pepper) {
        throw std::runtime_error("[CRED] [FATAL] JAMS_PEPPER not set!");
    }

    unsigned char salt_byte[16];

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA512", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)pepper, strlen(pepper)),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)data.c_str(), data.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)"jams-salt", 9),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(ctx, salt_byte, sizeof(salt_byte), params) != 1) {
        EVP_KDF_CTX_free(ctx);
        throw std::runtime_error("[CRED] [FATAL] HKDF derivation failed!");
    }

    EVP_KDF_CTX_free(ctx);

    std::ostringstream stream;
    for (unsigned char b : salt_byte) {
        stream << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }

    return stream.str();
}

CredentialStore::HashedPassword CredentialStore::hash_data(const std::string& data, const int iterations) {
    HashedPassword hashed;
    hashed.salt = "";
    hashed.iterations = iterations ? iterations : 100000;

    std::string derived_salt = derive_salt(data);
    unsigned char salt_bytes[16];
    for (size_t i = 0; i < 16; i++) {
        salt_bytes[i] = std::stoi(derived_salt.substr(i * 2, 2), nullptr, 16);
    }

    unsigned char hash_bytes[64];
    PKCS5_PBKDF2_HMAC(
        data.c_str(),
        data.size(),
        salt_bytes,
        sizeof(salt_bytes),
        hashed.iterations,
        EVP_sha512(),
        sizeof(hash_bytes),
        hash_bytes
    );

    std::ostringstream stream;
    for (unsigned char b : hash_bytes) {
        stream << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }

    hashed.hash = stream.str();
    return hashed;
}

CredentialStore::HashedPassword CredentialStore::hash_password(const std::string& password, const int iterations) {
    HashedPassword hashed = hash_data(password, iterations);

    return hashed;
}

bool CredentialStore::user_exists(const std::string& username) {
    sqlite3_stmt* stmt{ nullptr };

    if (sqlite3_prepare_v2(
        db_, "SELECT 1 FROM users WHERE username = ?",
        -1, &stmt, nullptr
    ) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return ok;
}

bool CredentialStore::is_active_user(const std::string& username) {
    sqlite3_stmt* stmt{ nullptr };

    if (sqlite3_prepare_v2(
        db_, "SELECT 1 FROM users WHERE username = ? AND active = 1",
        -1, &stmt, nullptr
    ) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return ok;
}

CredentialStore::HashedPassword CredentialStore::hash_password(
    const std::string& passwd, const std::string& username, const int itr
) {
    HashedPassword hashed;
    const std::string salt = derive_salt(username);

    hashed.salt = "";
    hashed.iterations = itr ? itr : 100000;
    hashed.hash = pbkdf2(passwd, salt, hashed.iterations);

    return hashed;
}

std::string CredentialStore::pbkdf2(
    const std::string& passwd, const std::string& salt_hex,
    int iterations
) {
    uint8_t salt_bytes[16];
    for (size_t i = 0; i < 16; i++) {
        salt_bytes[i] = static_cast<uint8_t>(
            std::stoi(salt_hex.substr(i * 2, 2), nullptr, 16)
            );
    }

    uint8_t out[32]; // SHA-256 output in 32 bytes

    int rc = PKCS5_PBKDF2_HMAC(
        passwd.c_str(), static_cast<int>(passwd.size()),
        salt_bytes, sizeof(salt_bytes),
        iterations, EVP_sha256(), sizeof(out), out
    );

    if (rc != 1) {
        logger.error("[FATAL] [AUTH] PBKDF2 faiiled");
        throw std::runtime_error("[auth/CredStore] PBKDF2 failed");
    }

    return base64_encode(out, sizeof(out));
}

bool CredentialStore::constant_time_eq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        // Dummy comparison to avoid length-based timing attacks
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= static_cast<uint8_t>(a[i]);
        }

        return false;
    }

    // CRYPTO_memcmp is OSSL's constant time comparison
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string CredentialStore::base64_encode(const uint8_t* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, data, static_cast<int>(len));
    BIO_flush(b64);

    BUF_MEM* buf{};
    BIO_get_mem_ptr(mem, &buf);

    std::string result(buf->data, buf->length);
    BIO_free_all(b64);

    return result;
}

std::vector<uint8_t> CredentialStore::base64_decode(const std::string& b64) {
    std::vector<uint8_t> result(b64.size());
    BIO* b64_bio = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));

    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64_bio, mem);

    int n = BIO_read(b64_bio, result.data(), static_cast<int>(result.size()));

    BIO_free_all(b64_bio);

    if (n < 0) {
        return {};
    }

    result.resize(static_cast<size_t>(n));
    return result;
}

bool CredentialStore::exec(const std::string& sql) {
    char* err{ nullptr };
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);

    if (rc != SQLITE_OK) {
        logger.error("[AUTH] SQL Error: " + std::string((err ? err : "unknown")));
        sqlite3_free(err);

        return false;
    }

    return true;
}
