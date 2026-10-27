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
#include <chrono>
#include <cstring>
#include <iostream>
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

void notify_unknown_ip(const std::string& username, const std::string& ip) {
    const std::string alert_to{ get_ip_reporter() }; // external MTA
    const std::string alert_from{ "no-reply@" + get_hostname() };
    const std::string subject{ "JAMS: Unknown IP Login - " + username };

    const std::string body =
        "An attempted login was detected from an unrecognised IP address.\r\n\r\n"
        "Username : " + username + "\r\n"
        "IP       : " + ip + "\r\n";

    const std::string msg =
        "From: JAMS Security <" + alert_from + ">\r\n"
        "To:<" + alert_to + ">\r\n"
        "Subject: " + subject + "\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n" + body;

    try {
        struct addrinfo hints {}, * res{ nullptr };
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_INET;

        if (getaddrinfo(get_hostname().c_str(), "25", &hints, &res) != 0) {
            logger.error("[AUTH] [ERROR] notify_unknown_ip: DNS Resolution Failed.");
            return;
        }

        int sock = socket(res->ai_family, res->ai_socktype, 0);
        connect(sock, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);

        auto send_cmd = [&](const std::string& cmd) {
            send(sock, cmd.c_str(), cmd.size(), 0);
            char buf[512]{};
            recv(sock, buf, sizeof(buf) - 1, 0);
            };

        send_cmd("");  // read banner
        send_cmd("EHLO mail.detraced.org\r\n");
        send_cmd("MAIL FROM:<" + alert_from + ">\r\n");
        send_cmd("RCPT TO:<" + alert_to + ">\r\n");
        send_cmd("DATA\r\n");
        send_cmd(msg + "\r\n.\r\n");
        send_cmd("QUIT\r\n");

        close(sock);

        logger.info("[AUTH] Unknown IP alert sent for: " + username);
    }
    catch (const std::exception& ex) {
        logger.error("[AUTH] [ERROR] Failed to send unknown IP alert: " + std::string(ex.what()));
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

    try {
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT hash, iterations, last_known_ip FROM users "
            "WHERE username = ? AND active = 1";

        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            logger.error("[auth] SQL Account Verification perpare failed: " + std::string(sqlite3_errmsg(db_)));
            return false;
        }

        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        auto hashed_ip = hash_data(ip);
        bool unknown_ip{ false };

        bool user_found = false;
        std::string stored_hash, salt;
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

            if (ip_cstr && std::string(ip_cstr) != hashed_ip.hash) {
                unknown_ip = true;
            }

            salt = derive_salt(username);
            stored_hash = hash_cstr;
            iterations = sqlite3_column_int(stmt, 1);

            user_found = true;
        }

        sqlite3_finalize(stmt);

        // Constant-Time evaluation - timing attack prevention
        std::string computed = pbkdf2(
            passwd, salt.empty() ? "deadbeef" : salt,
            iterations
        );

        const bool auth_ok = constant_time_eq(computed, stored_hash);

        if (!user_found) {
            return false;
        }

        if (unknown_ip) {
            notify_unknown_ip(username, ip);
        }

        return auth_ok;
    }
    catch (const std::exception& ex) {
        logger.error("[AUTH] verify() exception: " + std::string(ex.what()));
        return false;
    }
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
