#pragma once

#include "io/io_uring_loop.hpp"
#include "io/session_factory.hpp"
#include "auth/credentials/cred_store.hpp"
#include "storage/maildir.hpp"

#include <cstdint>
#include <ctime>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace IMAP {
    enum class State {
        NotAuthenticated,
        Authenticated,
        Selected,
        Logout,
    };

    struct MessageMeta {
        uint32_t uuid; // IMAP UID, kept per mailbox in jams-uidlist
        uint32_t seq; // sequence number from session
        time_t internal_date{ 0 }; // derived from file timestamp
        std::string filename;
        std::string flags; // IMAP Flags: \Seen, \Answered, \Flagged, \Deleted
        size_t size; // blob size in bytes
        bool in_cur{ false };
    };


    // Implements the alpha command set:
    //   Any state:       CAPABILITY NOOP LOGOUT
    //   Not authed:      STARTTLS LOGIN
    //   Authenticated:   SELECT EXAMINE LIST LSUB STATUS
    //   Selected:        FETCH STORE EXPUNGE CHECK CLOSE IDLE
    //
    // Zero-access storage:
    //   The server never decrypts message bodies. FETCH BODY[] returns the raw
    //   AES-256-GCM blob. Clients identify encrypted messages via the
    //   X-JAMS-Encrypted header and decrypt locally.
    //
    // IDLE (RFC 2177):
    //   Client sends IDLE -> server sends "+ idling"
    //   Server polls Maildir/new/ every IDLE_POLL_MS milliseconds
    //   On new mail: sends "* N EXISTS"
    //   Client sends DONE -> server responds OK
    //
    // State machine:
    //   NotAuthenticated -> Authenticated (after LOGIN)
    //   Authenticated    -> Selected (after SELECT/EXAMINE)
    //   Selected         -> Authenticated (after CLOSE)
    //   Any              -> Logout (after LOGOUT)
    class Session : public SMTP::ISession {
    public:
        Session(
            uint64_t conn_id, std::string remote_ip, Async::IoUringLoop& loop,
            Auth::CredentialStore& cred_store, const std::string& mail_root
        );

        /// @brief Called by io_uring whenever bytes arrive
        /// @param bytes 
        void on_data(std::span<const uint8_t> bytes);

        bool wants_close() const override {
            return state_ == State::Logout;
        }

        bool wants_tls_upgrade() const override {
            return tls_upgrade_pending_;
        }

        void clear_tls_upgrade() override {
            tls_upgrade_pending_ = false;
        }

    private:
        bool tls_upgrade_pending_{ false };

        std::string message_path(const MessageMeta& msg) const;

        void process_line(const std::string& line);

        void cmd_capability(const std::string& tag);

        void cmd_noop(const std::string& tag);

        void cmd_logout(const std::string& tag);

        void cmd_starttls(const std::string& tag);

        void cmd_login(const std::string& tag, const std::string& args);

        void cmd_auth(const std::string& tag, const std::string& args);

        void cmd_append(const std::string& tag, const std::string& args);

        void cmd_create(const std::string& tag, const std::string& args);

        void complete_append();


        void complete_plain_auth(const std::string& tag, const std::string& b64);

        void cmd_select(
            const std::string& tag, const std::string& mailbox,
            bool read_only
        );

        void cmd_list(const std::string& tag, const std::string& args);

        void cmd_lsub(const std::string& tag, const std::string& args);

        void cmd_status(const std::string& tag, const std::string& args);

        void cmd_fetch(const std::string& tag, const std::string& args, bool by_uid = false);

        void cmd_store(const std::string& tag, const std::string& args, bool by_uid = false);

        void cmd_expunge(const std::string& tag);

        void cmd_check(const std::string& tag);

        void cmd_close(const std::string& tag);

        void cmd_uid_search(const std::string& tag, const std::string& args);

        void ensure_mailbox_dirs(const std::string& mailbox);

        /// @brief Checks a client-supplied mailbox name before it is used to build a path.
        /// Rejects separators, dot segments, control characters and Maildir internals
        /// so a mailbox name can never resolve outside the user's own Maildir
        /// @param mailbox
        /// @return
        static bool is_valid_mailbox_name(const std::string& mailbox);

        /// @brief Builds the Maildir directory for a mailbox that has already been validated
        /// @param mailbox
        /// @return
        std::string mailbox_root(const std::string& mailbox) const;

        void ensure_standard_folders();

        /// @brief Resolves a sequence set to the sequence numbers of the messages it names.
        /// With by_uid the numbers in the set are UIDs (UID FETCH, UID STORE)
        /// @param set 
        /// @param by_uid 
        /// @return 
        std::vector<uint32_t> parse_sequence_set(const std::string& set, bool by_uid) const;

        /// @brief Fetches the given message from the maildir
        /// @param msg 
        /// @param items 
        /// @return 
        std::string fetch_message(const MessageMeta& msg, const std::string& items) const;

        /// @brief Reads the encrypted blobs and returns their value
        /// @param msg 
        /// @return 
        std::vector<uint8_t> read_blob(const MessageMeta& msg) const;

        /// @brief Build a synthetic envelope with NILs as the actual headers are encrypted
        /// @param msg 
        /// @return 
        std::string build_envelope(const MessageMeta& msg) const;

        /// @brief Builds the body structure for an encrypted octet stream
        /// @param msg 
        /// @return 
        std::string build_body(const MessageMeta& msg) const;

        /// @brief Loads all messages from the selected mailbox
        /// @param mailbox 
        void load_mailbox(const std::string& mailbox);

        /// @brief Scans the new/ directory for any messages that may have arrived
        /// @return 
        size_t scan_new() const;

        /// @brief Moves new/ messages to cur/ to mark that it's been seen by the server
        void incorporate_new();

        /// @brief Gives every loaded message its UID from the mailbox's jams-uidlist,
        /// assigns new messages UIDs above every earlier one, then orders messages by UID
        /// @param mailbox 
        void assign_uuids(const std::string& mailbox);

        /// @brief Reads a mailbox's jams-uidlist
        /// @return false if the file is missing or unreadable
        bool read_uuid_map(
            const std::string& mailbox, uint32_t& validity, uint32_t& next,
            std::unordered_map<std::string, uint32_t>& uuids
        ) const;

        /// @brief Atomically replaces a mailbox's jams-uidlist
        void write_uuid_map(
            const std::string& mailbox, uint32_t validity, uint32_t next,
            const std::unordered_map<std::string, uint32_t>& uuids
        ) const;

        /// @brief The part of a Maildir filename that never changes, everything before ":2,"
        /// @param filename 
        /// @return 
        static std::string base_name(const std::string& filename);

        /// @brief Derives the internal date from the maildir filename, specifically the timestamp
        /// @param filename 
        /// @return 
        static time_t date_from_file(const std::string& filename);

        /// @brief Parses the flags from the filename suffix: ":2,<flags>"
        /// @param filename 
        /// @return 
        static std::string flags_from_file(const std::string& filename);

        /// @brief Send back a response to the client
        /// @param line 
        void send(const std::string& line);

        /// @brief Send back an OK response to the client
        /// @param tag 
        /// @param msg 
        void ok(const std::string& tag, const std::string& msg);

        /// @brief Send back a NO response to the client
        /// @param tag 
        /// @param msg 
        void no(const std::string& tag, const std::string& msg);

        /// @brief Send back a BAD response to the client
        /// @param tag 
        /// @param msg 
        void bad(const std::string& tag, const std::string& msg);

        /// @brief Send back an untagged ("*") response to the client
        /// @param data 
        void untagged(const std::string& data);

        /// @brief Per-mailbox UID store, kept next to cur/ and new/ like dovecot-uidlist
        static constexpr const char* UUID_MAP_FILE = "jams-uidlist";

        /// @brief Serialises jams-uidlist updates, since 143 and 993 run on separate threads
        static std::mutex uuid_map_mutex_;

        /// @brief Largest message APPEND will accept, matching the SMTP SIZE limit (RFC 7889 APPENDLIMIT)
        static constexpr size_t MAX_APPEND_SIZE = 52428800;

        uint64_t conn_id_;
        std::string remote_ip_;
        Async::IoUringLoop& loop_;
        Auth::CredentialStore& cred_store_;
        std::string mail_root_; // i.e. /var/mail/vhosts

        State state_{ State::NotAuthenticated };
        std::string line_buf_;
        std::string username_;
        std::string selected_mailbox_;
        bool read_only_{ false };
        bool auth_pending_{ false };
        std::string auth_tag_;

        // APPEND ingestion state
        bool literal_pending_{ false };
        size_t literal_remaining_{ 0 };
        std::vector<uint8_t> literal_buf_;
        std::string append_tag_;
        std::string append_mailbox_;
        std::string append_flags_;
        static std::atomic<uint32_t> append_seq_;

        std::vector<MessageMeta> messages_;
        uint32_t next_uuid_{ 1 }; // The next UUID to assign
        uint32_t uuid_validity_{ 0 }; // UIDVALIDITY of the selected mailbox
    };
};
