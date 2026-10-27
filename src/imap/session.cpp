#include "imap/session.hpp"
#include "auth/credentials/cred_store.hpp"
#include "globals.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace IMAP;

Session::Session(
    uint64_t conn_id, std::string remote_ip, Async::IoUringLoop& loop,
    Auth::CredentialStore& cred_store, const std::string& mail_root
) : conn_id_(conn_id), remote_ip_(remote_ip), loop_(loop), cred_store_(cred_store),
mail_root_(mail_root) {
    // Send greeting on connect
    untagged("OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN IDLE] JAMS IMAP server ready");
}

bool Session::is_valid_mailbox_name(const std::string& mailbox) {
    if (mailbox.empty() || mailbox.size() > 255) {
        return false;
    }

    /**
     * Mailbox names become a single Maildir++ directory (".Name"), so anything
     * that could act as a path separator or dot segment is refused outright
     * rather than sanitised.
     */
    if (mailbox.front() == '.' || mailbox.back() == '.' || mailbox.find("..") != std::string::npos) {
        return false;
    }

    for (const char c : mailbox) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F || c == '/' || c == '\\' || c == '"') {
            return false;
        }
    }

    // Maildir's own subdirectories are never valid mailbox names
    if (mailbox == "cur" || mailbox == "new" || mailbox == "tmp") {
        return false;
    }

    return true;
}

std::string Session::mailbox_root(const std::string& mailbox) const {
    std::string base = mail_root_ + "/" + username_;

    // Subfolders are as per Maildir++ convention: .FolderName
    if (mailbox != "INBOX") {
        base += "/." + mailbox;
    }

    return base;
}

std::string Session::message_path(const MessageMeta& msg) const {
    std::string dir = msg.in_cur ? "/cur/" : "/new/";

    return mailbox_root(selected_mailbox_) + dir + msg.filename;
}

void Session::on_data(std::span<const uint8_t> bytes) {
    size_t offset = 0;

    // Fast-path: drain literal bypes for an in-progress APPEND
    if (literal_pending_ && literal_remaining_ > 0) {
        size_t take = std::min(bytes.size(), literal_remaining_);
        literal_buf_.insert(literal_buf_.end(), bytes.begin(), bytes.begin() + take);

        literal_remaining_ -= take;
        offset = take;

        if (literal_remaining_ == 0) {
            literal_pending_ = false;
            complete_append();
        }
    }


    for (size_t i = offset; i < bytes.size(); ++i) {
        uint8_t b = bytes[i];
        if (b == '\n') {
            if (!line_buf_.empty() && line_buf_.back() == '\r') {
                line_buf_.pop_back();
            }

            process_line(line_buf_);
            line_buf_.clear();

            if (tls_upgrade_pending_) {
                tls_upgrade_pending_ = false;
                return;
            }

            // Anything after LOGOUT, or after a refused LITERAL+ append, is not a command
            if (state_ == State::Logout) {
                return;
            }

            // Drain any literal bytes that arrived in the same call
            if (literal_pending_ && literal_remaining_ > 0) {
                size_t avail = bytes.size() - (i + 1);
                size_t take = std::min(avail, literal_remaining_);
                auto   start = bytes.begin() + i + 1;

                literal_buf_.insert(literal_buf_.end(), start, start + take);
                literal_remaining_ -= take;
                i += take;

                if (literal_remaining_ == 0) {
                    literal_pending_ = false;
                    complete_append();
                }
            }

        }
        else {
            line_buf_ += static_cast<char>(b);

            if (line_buf_.size() > 8192) {
                bad("*", "Line too long");
                line_buf_.clear();
            }
        }
    }
}

void Session::process_line(const std::string& line) {
    if (line.empty()) {
        return;
    }

    if (is_idle_active_) {
        std::string upper = line;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::tolower);

        if (upper == "DONE") {
            cmd_idle_done();
        }

        return;
    }

    if (auth_pending_) {
        auth_pending_ = false;
        complete_plain_auth(auth_tag_, line);

        return;
    }

    std::istringstream ss(line);
    std::string tag, command;
    ss >> tag >> command;

    if (command != "LOGIN" && command != "AUTHENTICATE") {
        logger.debug("[IMAP] " + std::to_string(conn_id_) + " " + line);
    }

    std::string args;
    std::getline(ss, args);

    if (!args.empty() && args.front() == ' ') {
        args.erase(0, 1);
    }

    // normalise command to UPPERCASE
    std::transform(command.begin(), command.end(), command.begin(), ::toupper);

    if (command == "CAPABILITY") {
        cmd_capability(tag);
        return;
    }

    if (command == "NOOP") {
        cmd_noop(tag);
        return;
    }

    if (command == "LOGOUT") {
        cmd_logout(tag);
        return;
    }

    if (state_ == State::NotAuthenticated) {
        if (command == "STARTTLS") {
            cmd_starttls(tag);
            return;
        }

        if (command == "LOGIN") {
            cmd_login(tag, args);
            return;
        }

        if (command == "AUTHENTICATE") {
            cmd_auth(tag, args);
            return;
        }

        no(tag, "Not authenticated");
        return;
    }

    /// Commands available once Authenticated to move into the Selected state
    if (state_ == State::Authenticated || state_ == State::Selected) {
        if (command == "SELECT") {
            cmd_select(tag, args, false);
            return;
        }

        if (command == "EXAMINE") {
            cmd_select(tag, args, true);
            return;
        }

        if (command == "LIST") {
            cmd_list(tag, args);
            return;
        }

        if (command == "LSUB") {
            cmd_lsub(tag, args);
            return;
        }

        if (command == "STATUS") {
            cmd_status(tag, args);
            return;
        }

        if (command == "APPEND") {
            cmd_append(tag, args);
            return;
        }

        if (command == "CREATE") {
            cmd_create(tag, args);
            return;
        }

        if (command == "IDLE") {
            cmd_idle(tag);
            return;
        }

        if (command == "SUBSCRIBE" || command == "UNSUBSCRIBE") {
            // stub until Subscribe is implemented (beta)
            ok(tag, command + " completed");
            return;
        }

        if (command == "UID") {
            std::istringstream uid_ss(args);
            std::string uid_cmd;
            std::string uid_args;
            uid_ss >> uid_cmd;
            std::getline(uid_ss, uid_args);

            if (!uid_args.empty() && uid_args.front() == ' ') {
                uid_args.erase(0, 1);
            }

            std::transform(uid_cmd.begin(), uid_cmd.end(), uid_cmd.begin(), ::toupper);

            if (uid_cmd == "FETCH") {
                cmd_fetch(tag, uid_args);
                return;
            }
            if (uid_cmd == "SEARCH") {
                cmd_uid_search(tag, uid_args);
                return;
            }
            if (uid_cmd == "STORE") {
                cmd_store(tag, uid_args);
                return;
            }

            bad(tag, "Unknown UID command");
            return;
        }
    }

    /// Commands only available to the Selected state, after AUTH
    if (state_ == State::Selected) {
        if (command == "FETCH") {
            cmd_fetch(tag, args);
            return;
        }

        if (command == "STORE") {
            cmd_store(tag, args);
            return;
        }

        if (command == "EXPUNGE") {
            cmd_expunge(tag);
            return;
        }

        if (command == "CHECK") {
            cmd_check(tag);
            return;
        }

        if (command == "CLOSE") {
            cmd_close(tag);
            return;
        }
    }

    bad(tag, "Command not recognised in current state");
}

void Session::cmd_idle(const std::string& tag) {
    if (state_ != State::Authenticated && state_ != State::Selected) {
        bad(tag, "IDLE requires authenticated state");
        return;
    }

    idle_tag_ = tag;
    is_idle_active_ = true;

    send("+ idling");

    loop_.register_idle_session(conn_id_, username_, selected_mailbox_);
}

void Session::cmd_idle_done() {
    if (!is_idle_active_) {
        return;
    }

    is_idle_active_ = false;
    loop_.unregister_idle_session(conn_id_);

    // Refresh our states
    if (state_ == State::Selected) {
        size_t old_count = messages_.size();

        incorporate_new();

        if (messages_.size() != old_count) {
            untagged(std::to_string(messages_.size()) + " EXISTS");
            untagged("0 RECENT");
        }
    }

    ok(idle_tag_, "IDLE Terminated");
    idle_tag_.clear();
}

void Session::cmd_capability(const std::string& tag) {
    untagged("CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN LITERAL+ SASL-IR APPENDLIMIT=" + std::to_string(MAX_APPEND_SIZE));

    ok(tag, "CAPABILITY completed");
}

void Session::cmd_noop(const std::string& tag) {
    if (state_ == State::Selected) {
        incorporate_new();
    }

    ok(tag, "NOOP completed");
}

void Session::cmd_logout(const std::string& tag) {
    untagged("BYE JAMS IMAP server logging out");
    ok(tag, "LOGOUT completed");

    state_ = State::Logout;
    loop_.submit_close(conn_id_);
}

void Session::cmd_starttls(const std::string& tag) {
    if (tls_upgrade_pending_) {
        bad(tag, "TLS already pending");
        return;
    }

    ok(tag, "Begin TLS negotiation");
    tls_upgrade_pending_ = true;
    loop_.upgrade_tls(conn_id_);
}

void Session::cmd_uid_search(const std::string& tag, const std::string& args) {
    std::string upper = args;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

    std::vector<uint32_t> results;
    auto since_pos = upper.find("SINCE ");

    if (since_pos != std::string::npos) {
        std::string date_str = args.substr(since_pos + 6);
        while (!date_str.empty() && std::isspace(date_str.front())) {
            date_str.erase(0, 1);
        }
        while (!date_str.empty() && std::isspace(date_str.back())) {
            date_str.pop_back();
        }

        struct tm tm {};
        if (strptime(date_str.c_str(), "%d-%b-%Y", &tm)) {
            tm.tm_hour = 0;
            tm.tm_sec = 0;
            tm.tm_isdst = -1;
            time_t since_t = mktime(&tm);

            for (const auto& msg : messages_) {
                if (static_cast<time_t>(msg.uuid) >= since_t) {
                    results.push_back(msg.uuid);
                }
            }
        }
    }
    else {
        for (const auto& msg : messages_) {
            results.push_back(msg.uuid);
        }
    }

    std::string response = "SEARCH";
    for (uint32_t uid : results) {
        response += " " + std::to_string(uid);
    }

    untagged(response);
    ok(tag, "UID SEARCH completed");
}

void Session::cmd_append(const std::string& tag, const std::string& args) {
    std::string rest = args;
    std::string mbox = "";

    if (!rest.empty() && rest.front() == '"') {
        auto close = rest.find('"', 1);
        if (close == std::string::npos) {
            bad(tag, "Unterminated mailbox name");
            return;
        }

        mbox = rest.substr(1, close - 1);
        rest = rest.substr(close + 1);
    }
    else {
        auto sp = rest.find(' ');
        mbox = (sp == std::string::npos) ? rest : rest.substr(0, sp);
        rest = (sp == std::string::npos) ? "" : rest.substr(sp);
    }

    if (mbox.empty()) {
        bad(tag, "APPEND requires a mailbox name");
        return;
    }

    std::string u_mbox = mbox;
    std::transform(u_mbox.begin(), u_mbox.end(), u_mbox.begin(), ::toupper);

    if (u_mbox == "INBOX") {
        mbox = "INBOX";
    }

    if (!is_valid_mailbox_name(mbox)) {
        no(tag, "[CANNOT] Invalid mailbox name");
        return;
    }

    // Skip optional flags
    std::string flags;
    auto trim_ws = [](const std::string& ws) {
        size_t a = ws.find_first_not_of(' ');
        return (a == std::string::npos) ? "" : ws.substr(a);
        };
    rest = trim_ws(rest);

    if (!rest.empty() && rest.front() == '(') {
        auto close = rest.find(')');
        if (close != std::string::npos) {
            flags = rest.substr(1, close - 1);
            rest = trim_ws(rest.substr(close + 1));
        }
    }

    // Skip optional date-time
    if (!rest.empty() && rest.front() == '"') {
        auto close = rest.find('"', 1);
        if (close != std::string::npos) {
            rest = trim_ws(rest.substr(close + 1));
        }
    }

    // Must end in {size}
    if (rest.empty() || rest.front() != '{' || rest.back() != '}') {
        bad(tag, "APPEND literal size missing");
        return;
    }

    size_t sz = 0;
    auto inner = rest.substr(1, rest.size() - 2);
    bool non_synchronizing{ false };

    if (!inner.empty() && inner.back() == '+') {
        inner.pop_back();
        non_synchronizing = true;
    }

    auto [ptr, ec] = std::from_chars(inner.data(), inner.data() + inner.size(), sz);
    if (ec != std::errc{} || ptr != inner.data() + inner.size()) {
        bad(tag, "Bad literal size");
        return;
    }

    if (sz == 0 || sz > MAX_APPEND_SIZE) {
        /**
         * A LITERAL+ client sends the message bytes without waiting for "+",
         * so after refusing it the rest of the stream is message data, not
         * commands. RFC 7888 section 4: reject with BAD and close the connection.
         */
        if (non_synchronizing) {
            bad(tag, "[TOOBIG] Message size exceeds the APPENDLIMIT, closing connection");
            state_ = State::Logout;
            loop_.submit_close(conn_id_);
            return;
        }

        no(tag, sz == 0 ? "Empty message" : "[TOOBIG] Message size exceeds the APPENDLIMIT");
        return;
    }

    ensure_mailbox_dirs(mbox);

    // Arm literal reader. The buffer grows as bytes arrive rather than
    // reserving whatever size the client claimed up front.
    append_tag_ = tag;
    append_mailbox_ = mbox;
    append_flags_ = flags;
    literal_buf_.clear();
    literal_remaining_ = sz;
    literal_pending_ = true;

    send("+ Ready for literal data");
}

void Session::cmd_create(const std::string& tag, const std::string& args) {
    std::string mbox = args;
    if (mbox.size() >= 2 && mbox.front() == '"' && mbox.back() == '"') {
        mbox = mbox.substr(1, mbox.size() - 2);
    }

    std::string u_mbox = mbox;
    std::transform(u_mbox.begin(), u_mbox.end(), u_mbox.begin(), ::toupper);

    if (mbox.empty() || u_mbox == "INBOX") {
        no(tag, "Cannot create that mailbox");
        return;
    }

    if (!is_valid_mailbox_name(mbox)) {
        no(tag, "[CANNOT] Invalid mailbox name");
        return;
    }

    ensure_mailbox_dirs(mbox);
    ok(tag, "CREATE completed");
}

std::atomic<uint32_t> Session::append_seq_{ 0 };

void Session::complete_append() {
    auto now = std::chrono::system_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();
    std::string fname = std::to_string(secs)
        + "." + std::to_string(::getpid()) + "." + std::to_string(append_seq_++)
        + ".jams_append";

    // Map flags to suffix characters
    std::string flag_chars;
    if (append_flags_.find("\\Seen") != std::string::npos) {
        flag_chars += 'S';
    }
    if (append_flags_.find("\\Answered") != std::string::npos) {
        flag_chars += 'R';
    }
    if (append_flags_.find("\\Flagged") != std::string::npos) {
        flag_chars += 'F';
    }
    if (append_flags_.find("\\Deleted") != std::string::npos) {
        flag_chars += 'T';
    }
    if (append_flags_.find("\\Draft") != std::string::npos) {
        flag_chars += 'D';
    }

    fname += ":2," + flag_chars;


    ensure_mailbox_dirs(append_mailbox_);

    std::string path = mailbox_root(append_mailbox_) + "/cur/" + fname;
    std::ofstream out(path, std::ios::binary);

    if (!out) {
        logger.error("[IMAP] APPEND open failed: " + std::string(std::strerror(errno)) + " path=" + path);

        no(append_tag_, "APPEND failed: could not write message");
        return;
    }

    out.write(
        reinterpret_cast<const char*>(literal_buf_.data()),
        static_cast<std::streamsize>(literal_buf_.size())
    );
    out.close();

    logger.info(
        "[IMAP] " + std::to_string(conn_id_) + " appended "
        + std::to_string(literal_buf_.size()) + " bytes to "
        + append_mailbox_
    );

    ok(append_tag_, "APPEND completed");
}

void Session::ensure_mailbox_dirs(const std::string& mailbox) {
    std::string base = mailbox_root(mailbox);

    // Sanity check to ensure the base dir is real
    ::mkdir(base.c_str(), 0700);

    for (const char* sub : { "cur", "new", "tmp" }) {
        std::string dir = base + "/" + sub;
        ::mkdir(dir.c_str(), 0700); // no-op if already exists
    }
}

void Session::cmd_login(const std::string& tag, const std::string& args) {
    std::istringstream ss(args);
    std::string user, pass;

    // Simpel unquoted parse, literal parsing not yet supported
    auto read_token = [](std::istringstream& s) {
        std::string token;
        s >> token;

        if (token.size() >= 2 && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.size() - 2);
        }

        return token;
        };

    user = read_token(ss);
    pass = read_token(ss);

    auto at = user.find('@');
    if (at != std::string::npos) {
        user = user.substr(0, at);
    }

    if (user.empty() || pass.empty()) {
        bad(tag, "LOGIN requres username and password");
        return;
    }

    if (!cred_store_.verify(user, pass, remote_ip_)) {
        no(tag, "[AUTHENTICATIONFAILED] Invalid credentials");
        return;
    }

    username_ = user;
    state_ = State::Authenticated;
    ensure_standard_folders();

    logger.info("[IMAP] " + std::to_string(conn_id_) + " authenticated: " + username_);

    ok(tag, "[CAPABILITY IMAP4rev1] LOGIN completed");
}

void Session::cmd_select(
    const std::string& tag, const std::string& mailbox,
    bool read_only
) {
    // Strip quotes from mailbox name
    std::string mbox = mailbox;
    if (mbox.size() >= 2 && mbox.front() == '"' && mbox.back() == '"') {
        mbox = mbox.substr(1, mbox.size() - 2);
    }

    if (mbox.empty()) {
        bad(tag, "SELECT requires a mailbox name");
        return;
    }

    // normalise inbox to UPPERCASE
    std::string u_mbox = mbox;
    std::transform(u_mbox.begin(), u_mbox.end(), u_mbox.begin(), ::toupper);

    if (u_mbox == "INBOX") {
        mbox = "INBOX";
    }

    if (!is_valid_mailbox_name(mbox)) {
        no(tag, "[NONEXISTENT] Invalid mailbox name");
        return;
    }

    load_mailbox(mbox);

    selected_mailbox_ = mbox;
    read_only_ = read_only;
    state_ = State::Selected;

    // Require untagged responses
    untagged(std::to_string(messages_.size()) + " EXISTS");
    untagged("0 RECENT");
    untagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
    untagged("OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Permanent flags");
    untagged("OK [UIDVALIDITY " + std::to_string(IMAP_UUID_VALIDITY) + "] UIDs valid");
    untagged("OK [UIDNEXT " + std::to_string(next_uuid_) + "] Next UID");

    if (read_only) {
        ok(tag, "[READ-ONLY] EXAMINE completed");
    }
    else {
        ok(tag, "[READ-WRITE] SELECT completed");
    }
}

void Session::ensure_standard_folders() {
    for (const char* folder : { "Sent", "Drafts", "Junk", "Trash" }) {
        ensure_mailbox_dirs(folder);
    }
}

void Session::cmd_list(const std::string& tag, const std::string& /* args */) {
    untagged("LIST (\\HasNoChildren) \"/\" \"INBOX\"");
    untagged("LIST (\\HasNoChildren \\Sent) \"/\" \"Sent\"");
    untagged("LIST (\\HasNoChildren \\Drafts) \"/\" \"Drafts\"");
    untagged("LIST (\\HasNoChildren \\Junk) \"/\" \"Junk\"");
    untagged("LIST (\\HasNoChildren \\Trash) \"/\" \"Trash\"");

    std::string user_root = mail_root_ + "/" + username_;
    DIR* d = ::opendir(user_root.c_str());

    if (d) {
        struct dirent* ent;
        while ((ent = ::readdir(d)) != nullptr) {
            std::string name = ent->d_name;
            if (name.size() < 2 || name[0] != '.' || name[1] == '.') {
                continue; // Maildir subfolders start with '.'
            }

            std::string mbox = name.substr(1);
            if (
                mbox == "cur" || mbox == "new" || mbox == "tmp"
                || mbox == "Sent" || mbox == "Drafts"
                || mbox == "Junk" || mbox == "Trash"
                ) {
                continue; // skip maildir directories
            }

            untagged("LIST (\\HasNoChildren) \"/\" \"" + mbox + "\"");
        }

        ::closedir(d);
    }

    ok(tag, "LIST completed");
}

void Session::cmd_lsub(const std::string& tag, const std::string& /* args */) {
    // Beta will introduce subscribed folders, for now this mirrors LIST
    untagged("LSUB (\\HasNoChildren) \"/\" \"INBOX\"");
    untagged("LSUB (\\HasNoChildren \\Sent) \"/\" \"Sent\"");
    untagged("LSUB (\\HasNoChildren \\Drafts) \"/\" \"Drafts\"");
    untagged("LSUB (\\HasNoChildren \\Junk) \"/\" \"Junk\"");
    untagged("LSUB (\\HasNoChildren \\Trash) \"/\" \"Trash\"");

    std::string user_root = mail_root_ + "/" + username_;
    DIR* d = ::opendir(user_root.c_str());

    if (d) {
        struct dirent* ent;
        while ((ent = ::readdir(d)) != nullptr) {
            std::string name = ent->d_name;
            if (name.size() < 2 || name[0] != '.' || name[1] == '.') {
                continue; // Maildir subfolders start with '.'
            }

            std::string mbox = name.substr(1);

            if (
                mbox == "cur" || mbox == "new" || mbox == "tmp"
                || mbox == "Sent" || mbox == "Drafts"
                || mbox == "Junk" || mbox == "Trash"
                ) {
                continue; // skip maildir directories
            }

            untagged("LSUB (\\HasNoChildren) \"/\" \"" + mbox + "\"");
        }

        ::closedir(d);
    }

    ok(tag, "LSUB completed");
}

void Session::cmd_status(const std::string& tag, const std::string& args) {
    // STATUS will show the messages unseen
    std::istringstream ss(args);
    std::string mbox, items_str;

    ss >> mbox;
    std::getline(ss, items_str);

    size_t unseen = 0;

    for (const auto& message : messages_) {
        if (message.flags.find("\\Seen") == std::string::npos) {
            ++unseen;
        }
    }

    std::string response = "STATUS " + mbox + " (MESSAGES "
        + std::to_string(messages_.size())
        + " UNSEEN " + std::to_string(unseen)
        + " UIDNEXT " + std::to_string(next_uuid_) + ")";

    untagged(response);
    ok(tag, "STATUS completed");
}

void Session::cmd_fetch(const std::string& tag, const std::string& args) {
    // fetch teh sequence-set items:
    auto sp = args.find(' ');
    if (sp == std::string::npos) {
        bad(tag, "FETCH requires sequence-set and items");
        return;
    }

    std::string seq_str = args.substr(0, sp);
    std::string items = args.substr(sp + 1);

    auto seqs = parse_sequence_set(seq_str);

    for (uint32_t seq : seqs) {
        // Find the message by the sequence number
        auto itr = std::find_if(messages_.begin(), messages_.end(), [seq](const MessageMeta& m) {
            return m.seq == seq;
            });

        if (itr == messages_.end()) {
            // No messages to iterate over
            continue;
        }

        std::string response = fetch_message(*itr, items);
        untagged(response);

        // if BODY[] was fetched without .PEEK, set it as seen
        std::string upper_items = items;
        std::transform(upper_items.begin(), upper_items.end(), upper_items.begin(), ::toupper);

        if (
            upper_items.find("BODY[") != std::string::npos &&
            upper_items.find(".PEEK") == std::string::npos &&
            !read_only_
            ) {
            if (itr->flags.find("\\Seen") == std::string::npos) {
                itr->flags += itr->flags.empty() ? " \\Seen" : " \\Seen";
                persist_flags(*itr);
            }
        }

        std::string response = fetch_message(*itr, items);
        untagged(response);
    }

    ok(tag, "FETCH completed");
}

std::string Session::fetch_message(
    const MessageMeta& msg, const std::string& items
) const {
    std::string upper = items;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

    std::string result = std::to_string(msg.seq) + " FETCH (";
    bool first = true;

    auto add = [&](const std::string& part) {
        if (!first) {
            result += ' ';
        }

        result += part;
        first = false;
        };

    if (upper.find("FLAGS") != std::string::npos) {
        add("FLAGS (" + msg.flags + ")");
    }

    if (upper.find("UID") != std::string::npos) {
        add("UID " + std::to_string(msg.uuid));
    }

    if (upper.find("RFC822.SIZE") != std::string::npos) {
        add("RFC822.SIZE " + std::to_string(msg.size));
    }

    if (upper.find("ENVELOPE") != std::string::npos) {
        add("ENVELOPE " + build_envelope(msg));
    }

    if (upper.find("BODYSTRUCTURE") != std::string::npos) {
        add("BODYSTRUCTURE " + build_body(msg));
    }

    if (
        upper.find("BODY[") != std::string::npos ||
        upper.find("RFC822") != std::string::npos
        ) {
        auto blob = read_blob(msg);
        add(
            "BODY[] {" + std::to_string(blob.size()) + "}\r\n" +
            std::string(blob.begin(), blob.end())
        );
    }

    if (upper.find("INTERNALDATE") != std::string::npos) {
        // Format: "04-Jun-2026 09:49:10 +0000"
        time_t t = static_cast<time_t>(msg.uuid);
        struct tm tm {};
        gmtime_r(&t, &tm);
        char buf[64];
        strftime(buf, sizeof(buf), "\"%d-%b-%Y %H:%M:%S +0000\"", &tm);
        add(std::string("INTERNALDATE ") + buf);
    }

    result += ')';
    return result;
}

std::vector<uint8_t> Session::read_blob(const MessageMeta& msg) const {
    std::string dir = msg.in_cur ? "/cur/" : "/new/";
    std::string path = mailbox_root(selected_mailbox_) + dir + msg.filename;
    std::ifstream file(path, std::ios::binary);

    if (!file) {
        logger.error("[IMAP] Failed to open path: " + path + " errno=" + std::to_string(errno) + " (" + std::strerror(errno) + ")");
        return {};
    }

    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

std::string Session::build_envelope(const MessageMeta& /* msg */) const {
    // Synthetic headers to so clients can display something before decryption
    return "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";
}

std::string Session::build_body(const MessageMeta& msg) const {
    return "(\"APPLICATION\" \"OCTET-STREAM\" "
        "(\"X-JAMS-Encrypted\" \"AES-256-GCM\") NIL NIL \"BASE64\" "
        + std::to_string(msg.size) + " NIL NIL NIL)";
}

void Session::persist_flags(MessageMeta& msg) {
    auto flag_chars = [](const std::string& flags) {
        // Maildir requires flag letters in ASCII order: D F R S T
        std::string s;
        if (flags.find("\\Draft") != std::string::npos)    s += 'D';
        if (flags.find("\\Flagged") != std::string::npos)  s += 'F';
        if (flags.find("\\Answered") != std::string::npos) s += 'R';
        if (flags.find("\\Seen") != std::string::npos)     s += 'S';
        if (flags.find("\\Deleted") != std::string::npos)  s += 'T';
        return s;
        };

    std::string base = msg.filename;
    auto colon = base.find(":2,");
    if (colon != std::string::npos) {
        base = base.substr(0, colon);
    }

    std::string new_name = base + ":2," + flag_chars(msg.flags);
    if (new_name == msg.filename) {
        return; // nothing changed
    }

    std::string old_path = message_path(msg);

    MessageMeta renamed = msg;
    renamed.filename = new_name;
    std::string new_path = message_path(renamed);

    if (::rename(old_path.c_str(), new_path.c_str()) == 0) {
        msg.filename = new_name;
    }
    else {
        logger.error("[IMAP] persist_flags rename failed: " + old_path
            + " -> " + new_path + " (" + std::strerror(errno) + ")");
    }
}

void Session::cmd_store(const std::string& tag, const std::string& args) {
    if (read_only_) {
        no(tag, "[READ-ONLY] Mailbox is read-only");
        return;
    }

    // STORE seq FLAGS are \Seen, \Deleted, etc.
    std::istringstream ss(args);
    std::string seq_str, action, flags_str;

    ss >> seq_str >> action;
    std::getline(ss, flags_str);

    // trim and strip parenthesis
    auto trim = [](std::string s) {
        size_t a = s.find_first_not_of(" \t(");
        size_t b = s.find_last_not_of(" \t)");

        return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
        };

    flags_str = trim(flags_str);

    // Normalise the action to UPPERCASE
    std::string upper = action;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

    auto seqs = parse_sequence_set(seq_str);

    for (uint32_t seq : seqs) {
        auto itr = std::find_if(
            messages_.begin(), messages_.end(),
            [seq](const MessageMeta& m) {
                return m.seq == seq;
            });

        if (itr == messages_.end()) {
            continue;
        }

        if (upper == "FLAGS" || upper == "FLAGS.SILENT") {
            itr->flags = flags_str;
        }
        else if (upper == "+FLAGS" || upper == "+FLAGS.SILENT") {
            if (itr->flags.find(flags_str) == std::string::npos) {
                itr->flags += (itr->flags.empty() ? "" : " ") + flags_str;
            }
        }
        else if (upper == "-FLAGS" || upper == "-FLAGS.SILENT") {
            size_t pos = itr->flags.find(flags_str);
            if (pos != std::string::npos) {
                itr->flags.erase(pos, flags_str.size());
            }
        }

        // Persist flags to disk
        persist_flags(*itr);

        // Send FETCH unless .SILENT is present
        if (upper.find(".SILENT") == std::string::npos) {
            untagged(std::to_string(seq) + " FETCH (FLAGS (" + itr->flags + "))");
        }
    }

    ok(tag, "STORE completed");
}

void Session::cmd_expunge(const std::string& tag) {
    if (read_only_) {
        no(tag, "[READ-ONLY] Mailbox is read-only");
        return;
    }

    std::vector<MessageMeta> remaining;
    uint32_t seq = 0;

    for (auto& msg : messages_) {
        ++seq;

        if (msg.flags.find("\\Deleted") != std::string::npos) {
            // Delete the file!
            std::string path = message_path(msg);

            if (::unlink(path.c_str()) != 0) {
                logger.error("[IMAP] EXPUNGE unlink failed: "
                    + path + " errno=" + std::to_string(errno)
                    + " (" + std::strerror(errno) + ")");
            }
            untagged(std::to_string(seq) + " EXPUNGE");
            --seq;
        }
        else {
            remaining.push_back(std::move(msg));
        }
    }

    messages_ = std::move(remaining);

    // Reassign sequences
    for (uint32_t i = 0; i < messages_.size(); ++i) {
        messages_[i].seq = i + 1;
    }

    ok(tag, "EXPUNGE completed");
}

void Session::cmd_check(const std::string& tag) {
    incorporate_new();
    ok(tag, "CHECK completed");
}

void Session::cmd_close(const std::string& tag) {
    // Silently expunge \Deleted messages
    if (!read_only_) {
        for (auto& msg : messages_) {
            if (msg.flags.find("\\Deleted") != std::string::npos) {
                std::string path = message_path(msg);

                if (::unlink(path.c_str()) != 0) {
                    logger.error("[IMAP] CLOSE unlink failed: "
                        + path + " errno=" + std::to_string(errno)
                        + " (" + std::strerror(errno) + ")");
                }
            }
        }
    }

    messages_.clear();
    selected_mailbox_.clear();
    state_ = State::Authenticated;

    ok(tag, "CLOSE completed");
}

void Session::cmd_auth(const std::string& tag, const std::string& args) {
    std::istringstream ss(args);
    std::string mechanism, initial_response;
    ss >> mechanism >> initial_response;

    for (char& c : mechanism) c = toupper(c);
    if (mechanism != "PLAIN") {
        no(tag, "Unsupported authentication mechanism");
        return;
    }

    if (initial_response.empty()) {
        send("+ "); // challenge — wait for next line
        auth_pending_ = true;
        auth_tag_ = tag;
        return;
    }

    complete_plain_auth(tag, initial_response);  // SASL-IR inline

}

void Session::complete_plain_auth(const std::string& tag, const std::string& b64) {
    auto base64_decode = [](const std::string& b64) -> std::vector<uint8_t> {
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
        };
    auto decoded = base64_decode(b64);

    auto it1 = std::find(decoded.begin(), decoded.end(), '\0');
    if (it1 == decoded.end()) { bad(tag, "Malformed PLAIN credentials"); return; }
    auto it2 = std::find(it1 + 1, decoded.end(), '\0');
    if (it2 == decoded.end()) { bad(tag, "Malformed PLAIN credentials"); return; }

    std::string user(it1 + 1, it2);
    std::string pass(it2 + 1, decoded.end());

    auto at = user.find('@');
    if (at != std::string::npos) user = user.substr(0, at);

    if (!cred_store_.verify(user, pass, remote_ip_)) {
        no(tag, "[AUTHENTICATIONFAILED] Invalid credentials");
        return;
    }

    username_ = user;
    state_ = State::Authenticated;
    ok(tag, "[CAPABILITY IMAP4rev1] Authentication successful");
}

void Session::load_mailbox(const std::string& mailbox) {
    messages_.clear();
    next_uuid_ = 1;

    std::string base = mailbox_root(mailbox);

    uint32_t seq = 0;

    for (const char* subdir : { "cur", "new" }) {
        bool is_cur = (std::string(subdir) == "cur");
        std::string dir = base + "/" + subdir;

        DIR* d = ::opendir(dir.c_str());
        if (!d) {
            // No directory exists, we can soft-fail
            continue;
        }

        struct dirent* ent;
        while ((ent = ::readdir(d)) != nullptr) {
            if (ent->d_name[0] == '.') {
                continue;
            }

            std::string fname = ent->d_name;

            // Get the file size
            struct stat st {};
            std::string full = dir + "/" + fname;

            if (::stat(full.c_str(), &st) != 0) {
                continue;
            }

            MessageMeta meta;
            meta.uuid = uuid_from_file(fname);
            meta.seq = ++seq;
            meta.filename = fname;
            meta.flags = flags_from_file(fname);
            meta.size = static_cast<size_t>(st.st_size);
            meta.in_cur = is_cur;

            messages_.push_back(std::move(meta));
        }

        ::closedir(d);
    }

    // Sort by UUID for stable ordering
    std::sort(
        messages_.begin(), messages_.end(),
        [](const MessageMeta& a, const MessageMeta& b) {
            return a.uuid < b.uuid;
        });

    // reassign sequences after sort
    for (uint32_t i = 0; i < messages_.size(); i++) {
        messages_[i].seq = i + 1;
        next_uuid_ = std::max(next_uuid_, messages_[i].uuid + 1);
    }

    logger.info("[IMAP] " + std::to_string(conn_id_) + " loaded " + std::to_string(messages_.size()) + " messages from " + mailbox);
}

size_t Session::scan_new() const {
    std::string dir = mail_root_ + "/" + username_ + "/new";
    size_t count{ 0 };

    DIR* d = ::opendir(dir.c_str());
    if (!d) {
        return count;
    }

    struct dirent* ent;
    while ((ent = ::readdir(d)) != nullptr) {
        if (ent->d_name[0] != '.') {
            ++count;
        }
    }

    ::closedir(d);
    return count;
}

void Session::incorporate_new() {
    std::string new_dir = mail_root_ + "/" + username_ + "/new";
    std::string cur_dir = mail_root_ + "/" + username_ + "/cur";

    DIR* d = ::opendir(new_dir.c_str());
    if (!d) {
        return;
    }

    struct dirent* ent;
    while ((ent = ::readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') {
            continue;
        }

        std::string fname = ent->d_name;
        std::string src = new_dir + "/" + fname;

        // Add :2, flags if not present
        std::string dst_name = fname;
        if (dst_name.find(":2,") == std::string::npos) {
            dst_name += ":2,";
        }

        std::string dst = cur_dir + "/" + dst_name;

        if (::rename(src.c_str(), dst.c_str()) == 0) {
            struct stat st {};

            if (::stat(dst.c_str(), &st) == 0) {
                MessageMeta meta;
                meta.uuid = uuid_from_file(dst_name);
                meta.seq = static_cast<uint32_t>(messages_.size()) + 1;
                meta.filename = dst_name;
                meta.size = static_cast<size_t>(st.st_size);
                meta.in_cur = true;
                meta.flags = "";

                messages_.push_back(std::move(meta));
                next_uuid_ = std::max(next_uuid_, meta.uuid + 1);
            }
        }
    }

    ::closedir(d);
}

uint32_t Session::uuid_from_file(const std::string& filename) {
    // Maildir conventions start with a UNIX timestamp, PID, then host
    // We'll be using the timestamp as the UUID
    auto dot = filename.find_first_of('.');
    if (dot == std::string::npos) {
        return 1;
    }

    uint32_t uuid = 0;
    auto [ptr, ec] = std::from_chars(filename.data(), filename.data() + dot, uuid);

    return (ec == std::errc{}) ? uuid : 1;
}

std::string Session::flags_from_file(const std::string& filename) {
    // Flags are placed after the :2,
    auto pos = filename.find(":2,");
    if (pos == std::string::npos) {
        return "";
    }

    std::string raw_flags = filename.substr(pos + 3);
    std::string imap_flags;

    if (raw_flags.find('D') != std::string::npos) {
        imap_flags += "\\Draft ";
    }

    if (raw_flags.find('F') != std::string::npos) {
        imap_flags += "\\Flagged ";
    }

    if (raw_flags.find('R') != std::string::npos) {
        imap_flags += "\\Answered ";
    }

    if (raw_flags.find('S') != std::string::npos) {
        imap_flags += "\\Seen ";

    }

    if (raw_flags.find('T') != std::string::npos) {
        imap_flags += "\\Deleted ";
    }

    if (!imap_flags.empty() && imap_flags.back() == ' ') {
        imap_flags.pop_back();
    }

    return imap_flags;
}

std::vector<uint32_t> Session::parse_sequence_set(
    const std::string& set
) const {
    std::vector<uint32_t> result;
    uint32_t max_seq = static_cast<uint32_t>(messages_.size());

    if (max_seq == 0) {
        return result;
    }

    // Split on ','
    std::istringstream ss(set);
    std::string range;

    while (std::getline(ss, range, ',')) {
        auto colon = range.find(':');

        auto parse_num = [&](const std::string& s) -> uint32_t {
            if (s == "*") {
                return max_seq;
            }

            uint32_t n = 0;
            std::from_chars(s.data(), s.data() + s.size(), n);

            return std::min(n, max_seq);
            };

        if (colon == std::string::npos) {
            uint32_t n = parse_num(range);

            if (n >= 1 && n <= max_seq) {
                result.push_back(n);
            }
        }
        else {
            uint32_t lo = parse_num(range.substr(0, colon));
            uint32_t hi = parse_num(range.substr(colon + 1));

            if (lo > hi) {
                std::swap(lo, hi);
            }

            for (uint32_t i = lo; i <= hi; ++i) {
                if (i >= 1 && i <= max_seq) {
                    result.push_back(i);
                }
            }
        }
    }

    return result;
}

void Session::send(const std::string& line) {
    std::string out = line + "\r\n";

    loop_.submit_write(conn_id_, std::vector<uint8_t>(out.begin(), out.end()));
}

void Session::ok(const std::string& tag, const std::string& msg) {
    send(tag + " OK " + msg);
}

void Session::no(const std::string& tag, const std::string& msg) {
    send(tag + " NO " + msg);
}

void Session::bad(const std::string& tag, const std::string& msg) {
    send(tag + " BAD " + msg);
}

void Session::untagged(const std::string& data) {
    send("* " + data);
}
