#include "globals.hpp"
#include "auth/credentials/aliases.hpp"

#include <ctime>
#include <algorithm>

using namespace Auth;

std::string Aliases::extract_domain(const std::string& address)
{
    auto pos = address.rfind('@');
    if (pos == std::string::npos) {
        return "";
    }

    std::string domain = address.substr(pos + 1);
    std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

    return domain;
}

std::string Aliases::resolve(const std::string& address) {
    static constexpr const char* SQL = "SELECT username FROM aliases WHERE alias = ? AND active = 1;";

    sqlite3_stmt* stmt{ nullptr };
    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] Resolve prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return address;
    }

    sqlite3_bind_text(stmt, 1, address.c_str(), -1, SQLITE_TRANSIENT);
    std::string result = address;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }

    sqlite3_finalize(stmt);
    return result;
}

bool Aliases::add(
    const std::string& alias, const std::string& username, const AliasPolicy& policy
) {
    static constexpr const char* SQL = "INSERT INTO aliases (alias, username, active, max_uses, expires_at, created_at) "
        "VALUES (?, ?, 1, ?, ?, ?);";

    sqlite3_stmt* stmt{ nullptr };

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] Add prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, policy.max_uses.value());
    sqlite3_bind_int64(stmt, 4, policy.expires_at.value());
    sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(std::time(nullptr)));

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok) {
        logger.error("[ALIAS] Add insert failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_finalize(stmt);
    return ok;
}

/**
 * Read-only on purpose. RCPT is reachable without authentication and no message
 * exists yet, so naming an alias as a recipient must not spend anything: a
 * stranger could otherwise burn every use of a one-time alias and never send
 * mail. NULL max_uses / expires_at both mean "no limit".
 */
bool Aliases::accept(const std::string& alias) {
    static constexpr const char* SEL =
        "SELECT 1 FROM aliases WHERE alias = ? AND active = 1 "
        "AND (expires_at IS NULL OR expires_at > ?) "
        "AND (max_uses IS NULL OR uses_count < max_uses);";

    sqlite3_stmt* stmt{ nullptr };
    if (sqlite3_prepare_v2(db_, SEL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] accept prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(std::time(nullptr)));

    bool usable = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);

    return usable;
}

/**
 * Called once per alias after a message has actually been stored for it. One
 * conditional statement, so the same limits are re-checked at the moment of
 * spending and a use can never be taken from an alias that has none left.
 */
bool Aliases::consume(const std::string& alias) {
    static constexpr const char* UPD =
        "UPDATE aliases SET uses_count = uses_count + 1, "
        "active = CASE WHEN max_uses IS NOT NULL AND uses_count + 1 >= max_uses THEN 0 ELSE active END "
        "WHERE alias = ? AND active = 1 "
        "AND (expires_at IS NULL OR expires_at > ?) "
        "AND (max_uses IS NULL OR uses_count < max_uses);";

    sqlite3_stmt* stmt{ nullptr };
    if (sqlite3_prepare_v2(db_, UPD, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] consume prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(std::time(nullptr)));

    bool ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db_) > 0;
    sqlite3_finalize(stmt);

    if (!ok) {
        logger.warn("[ALIAS] consume spent nothing for: " + alias);
    }

    return ok;
}

// aliases.cpp
void Aliases::deactivate(const std::string& alias) {
    static constexpr const char* SQL = "UPDATE aliases SET active = 0 WHERE alias = ?;";
    sqlite3_stmt* stmt{ nullptr };
    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] deactivate prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return;
    }
    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

bool Aliases::remove(const std::string& alias) {
    static constexpr const char* SQL = "DELETE FROM aliases WHERE alias = ?;";
    sqlite3_stmt* stmt{ nullptr };

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] Remove prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok) {
        logger.error("[ALIAS] Remove delete failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_finalize(stmt);
    return ok;
}

std::vector<std::string> Aliases::list_for(const std::string& username) {
    static constexpr const char* SQL = "SELECT alias FROM aliases WHERE username = ? AND active = 1;";
    sqlite3_stmt* stmt{ nullptr };
    std::vector<std::string> out;

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] List For prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return out;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        out.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    }

    sqlite3_finalize(stmt);
    return out;
}

bool Aliases::is_domain_allowed(const std::string& alias, const std::string& sender_domain) {
    static constexpr const char* SQL = "SELECT COUNT(*) FROM alias_allowed_domains WHERE alias = ?;";
    sqlite3_stmt* stmt{ nullptr };

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] is_domain_allowed failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);

    int total = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (total == 0) {
        return true; // no allowlist configured, accept from anyone
    }

    static constexpr const char* CHECK =
        "SELECT 1 FROM alias_allowed_domains WHERE alias = ? AND domain = ?;";
    sqlite3_stmt* c{ nullptr };

    if (sqlite3_prepare_v2(db_, CHECK, -1, &c, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] is_domain_allowed failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_bind_text(c, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(c, 2, sender_domain.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = sqlite3_step(c) == SQLITE_ROW;

    sqlite3_finalize(c);
    return ok;
}

void Aliases::schedule_purge(const std::string& alias, const std::string& username, const std::string& maildir_path) {
    static constexpr const char* SQL = "SELECT auto_delete_after FROM aliases WHERE alias = ?;";
    sqlite3_stmt* stmt{ nullptr };

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] schedule_purge failed to prepare: " + std::string(sqlite3_errmsg(db_)));
        return;
    }

    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW || sqlite3_column_type(stmt, 0) == SQLITE_NULL) {
        sqlite3_finalize(stmt);
        return; // no TTL configured
    }

    int ttl = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    int64_t purge_at = static_cast<int64_t>(std::time(nullptr)) + ttl;
    static constexpr const char* INS =
        "INSERT INTO message_purge_queue (alias, username, maildir_path, purge_at) "
        "VALUES (?, ?, ?, ?);";
    sqlite3_stmt* ins{ nullptr };

    if (sqlite3_prepare_v2(db_, INS, -1, &ins, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] schedule_purge insert failed to prepare: " + std::string(sqlite3_errmsg(db_)));
        return;
    }

    sqlite3_bind_text(ins, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 3, maildir_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins, 4, purge_at);

    sqlite3_step(ins);
    sqlite3_finalize(ins);
}

void Aliases::reap_expired() {
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    static constexpr const char* SQL = "UPDATE aliases SET active = 0 "
        "WHERE active = 1 AND ("
        "  (expires_at IS NOT NULL AND expires_at <= ?) OR "
        "  (max_uses IS NOT NULL AND uses_count >= max_uses)"
        ");";
    sqlite3_stmt* stmt{ nullptr };

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] reap_expired failed to prepare: " + std::string(sqlite3_errmsg(db_)));
        return;
    }

    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return;
}

std::vector<std::tuple<int64_t, std::string>> Aliases::due_purges() {
    int64_t now = static_cast<int64_t>(std::time(nullptr));

    static constexpr const char* SQL = "SELECT id, maildir_path FROM message_purge_queue WHERE purge_at <= ?;";
    sqlite3_stmt* stmt{ nullptr };
    std::vector<std::tuple<int64_t, std::string>> out{};

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] due_purges prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return out;
    }

    sqlite3_bind_int64(stmt, 1, now);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(stmt, 0);
        std::string path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        out.emplace_back(id, path);
    }

    sqlite3_finalize(stmt);
    return out;
}

void Aliases::mark_purged(int64_t queue_id) {
    static constexpr const char* SQL = "DELETE FROM message_purge_queue WHERE id = ?;";
    sqlite3_stmt* stmt{ nullptr };

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALAIS] mark_purged prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return;
    }

    sqlite3_bind_int64(stmt, 1, queue_id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        logger.error("[ALIAS] mark_purged delete failed: " + std::string(sqlite3_errmsg(db_)));
        return;
    }

    sqlite3_finalize(stmt);
    return;
}
