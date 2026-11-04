#pragma once

#include "auth/credentials/cred_store.hpp"
#include "utils/config/toml_parse.hpp"

namespace Auth
{
    struct AliasPolicy
    {
        std::optional<int64_t> expires_at;
        std::optional<int> max_uses;
        std::optional<int> auto_delete_after; // seconds
    };

    class Aliases
    {
    public:
        explicit Aliases(Auth::CredentialStore &db) : db_(db.handle()) {};

        /// @brief Returns target username if address is an active alias,
        /// otherwise returns `address` unchanged.
        /// @param address
        /// @return
        std::string resolve(const std::string &address);

        /// @brief
        /// @param alias
        /// @param username
        /// @param expiry
        /// @param receives_from
        /// @return
        bool add(const std::string &alias, const std::string &username, const AliasPolicy &policy);

        /// @brief
        /// @param alias
        /// @return
        bool remove(const std::string &alias);

        /// @brief
        /// @param username
        /// @return
        std::vector<std::string> list_for(const std::string &username);

        bool add_allowed_domain(const std::string &alias, const std::string &domain);

        bool is_domain_allowed(const std::string &alias, const std::string &sender_domain);

        /// @brief Is this alias usable right now? Read-only: spends nothing.
        /// Called at RCPT, where no message exists yet.
        bool accept(const std::string &alias);

        /// @brief Spend one use, and deactivate the alias if that was the last one.
        /// Called once per alias after a message has actually been stored for it.
        bool consume(const std::string &alias);

        void schedule_purge(const std::string &alias, const std::string &username, const std::string &maildir);

        void reap_expired();

        std::vector<std::tuple<int64_t, std::string>> due_purges();

        void mark_purged(int64_t queue_id);

        static std::string extract_domain(const std::string &address);

    private:
        sqlite3 *db_; // Borrowing from CredStore

        void deactivate(const std::string &alias);
    };
};
