#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <sqlite3.h>

namespace Auth {

    // SQLite-backed persistent user credential store.
    //
    // Password hashing:
    //   PBKDF2-HMAC-SHA256 with 100,000 iterations and a 16-byte random salt.
    //   OpenSSL's PKCS5_PBKDF2_HMAC() is used — no extra dependencies.
    //   The stored hash is base64(PBKDF2(password, salt, 100000, SHA256, 32)).
    //
    // Usage:
    //   CredentialStore store("/var/lib/jams/users.db");
    //   store.add_user("alice", "s3cr3t");
    //   bool ok = store.verify("alice", "s3cr3t"); // true
    //   bool ok = store.verify("alice", "wrong");   // false
    class CredentialStore {
    public:
        sqlite3* db_{ nullptr };

        explicit CredentialStore(const std::string& db_path);
        ~CredentialStore();

        CredentialStore(const CredentialStore&) = delete;
        CredentialStore& operator=(const CredentialStore&) = delete;

        /// @brief Add a new user, returns false on error or existing user
        /// @param username 
        /// @param passwd 
        /// @param ip
        /// @return 
        bool add_user(const std::string& username, const std::string& passwd, const std::string& ip);

        /// @brief Verify the credentials, returns false on incorrect, unknown, or inactive accounts.
        /// This function works in constant-time. An address over the failed login limit is
        /// refused before any hashing, even with the right password
        /// @param username 
        /// @param passwd 
        /// @param ip
        /// @return 
        bool verify(const std::string& username, const std::string& passwd, const std::string& ip);

        /// @brief Deactivate a user account (soft-delete to preserve audit trails)
        /// @param username 
        /// @return 
        bool deactivate_user(const std::string& username);

        /// @brief (re)activate a user's account, if deactivated
        /// @param username 
        /// @return 
        bool activate_user(const std::string& username);

        /// @brief Change a user's password
        /// @param username 
        /// @param old_passwd Old password in B64
        /// @param new_passwd New password in B64
        /// @return 
        bool change_password(
            const std::string& username, const std::string& old_passwd,
            const std::string& new_passwd
        );

        /// @brief Verify is a user exists
        /// @param username 
        /// @return 
        bool user_exists(const std::string& username);

        /// @brief True if the account exists and has not been deactivated
        /// @param username
        /// @return
        bool is_active_user(const std::string& username);

        sqlite3* handle() const {
            return db_;
        }

    private:
        /// @brief Failed logins one address may make within AUTH_FAILURE_WINDOW before it is
        /// refused outright. Every check costs a PBKDF2 run, so this is what keeps guessing cheap for us
        static constexpr int MAX_AUTH_FAILURES = 10;
        static constexpr std::chrono::seconds AUTH_FAILURE_WINDOW{ 600 };

        struct FailureWindow {
            int count{ 0 };
            std::chrono::steady_clock::time_point start;
        };

        // verify() is called from the IMAP, IMAPS and submission threads
        std::mutex failures_mutex_;
        std::unordered_map<std::string, FailureWindow> failures_;

        /// @brief True if this address has used up its failed logins for the current window
        /// @param ip 
        /// @return 
        bool is_throttled(const std::string& ip);

        /// @brief Counts a failed login against an address
        /// @param ip 
        void record_failure(const std::string& ip);

        /// @brief Stores the address hash a user last logged in from, so only a change alerts
        /// @param username 
        /// @param ip_hash 
        void remember_ip(const std::string& username, const std::string& ip_hash);

        struct HashedPassword {
            std::string hash; // base64 encoded SHA256
            std::string salt; // base64 encoded hash salt
            int iterations{ 100000 };
        };

        /// @brief Hash the password in PBKDF2 SHA-256
        /// @param password 
        /// @return 
        static HashedPassword hash_password(const std::string& password, const int itr = 100000);

        static HashedPassword hash_password(const std::string& password, const std::string& username, const int itr = 100000);

        static HashedPassword hash_data(const std::string& data, const int iter = 100000);

        static std::string derive_salt(const std::string& username);

        /// @brief Returns the b64 encoded 32byte PBKDF2 hash
        /// @param passwd 
        /// @param salt 
        /// @param iterations 
        /// @return 
        static std::string pbkdf2(const std::string& passwd, const std::string& salt, int iterations);

        /// @brief Constant-Time comparison to prevent timing attacks
        /// @param a 
        /// @param b 
        /// @return 
        static bool constant_time_eq(const std::string& a, const std::string& b);

        /// @brief Base64 Encoder helper
        /// @param data 
        /// @param len 
        /// @return 
        static std::string base64_encode(const uint8_t* data, size_t len);

        /// @brief Base64 Decoder helper
        /// @param b64 
        /// @return 
        static std::vector<uint8_t> base64_decode(const std::string& b64);

        /// @brief Execute prebuilt SQL Queries
        /// @param query 
        /// @return 
        bool exec(const std::string& query);

        /// @brief Ensure the SQL schema is valid
        void ensure_schema();
    };
};
