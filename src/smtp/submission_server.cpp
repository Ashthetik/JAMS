#include "smtp/submission_server.hpp"
#include "io/io_uring_loop.hpp"
#include "storage/maildir.hpp"
#include "tls/tls_client.hpp"
#include "globals.hpp"

#include <cctype>
#include <iostream>
#include <iterator>
#include <sstream>
#include <resolv.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>
#include <filesystem>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

using namespace SMTP;

namespace {
    /**
     * Outbound relays run here instead of on the 587 event loop. A relay is a
     * blocking SMTP conversation with 30 second timeouts, so on the loop one
     * slow or dead remote server froze submission for every user
     */
    class RelayWorkers {
    public:
        explicit RelayWorkers(size_t count) {
            for (size_t i = 0; i < count; ++i) {
                threads_.emplace_back([this]() { run(); });
            }
        }

        ~RelayWorkers() {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stop_ = true;
            }

            cv_.notify_all();
            for (auto& t : threads_) {
                t.join();
            }
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

                    if (stop_ && jobs_.empty()) {
                        return;
                    }

                    job = std::move(jobs_.front());
                    jobs_.pop_front();
                }

                try {
                    job();
                }
                catch (const std::exception& ex) {
                    logger.error("[RELAY] worker job threw: " + std::string(ex.what()));
                }
            }
        }

        std::mutex mutex_;
        std::condition_variable cv_;
        std::deque<std::function<void()>> jobs_;
        std::vector<std::thread> threads_;
        bool stop_{ false };
    };

    RelayWorkers& relay_workers() {
        static RelayWorkers workers(4);
        return workers;
    }
}

SubmissionServer::SubmissionServer(
    uint64_t conn_id, const std::string& remote_ip,
    Async::IoUringLoop& loop, Auth::CredentialStore& store,
    Auth::Aliases& aliases
) : dkim_signer_(std::make_shared<DKIM::Signer>(DKIM::Signer::Config{
        .domain = get_hostname(),
        .selector = "jams",
        .priv_key_path = "/etc/jams/tls/key.pem"
    })), conn_id_(conn_id), remote_ip_(remote_ip), loop_(loop), sasl_(store, remote_ip), aliases_(aliases) {
    reply(220, get_hostname() + " ESMTP submission");
}

SubmissionServer::~SubmissionServer() {
    // A relay finishing after this must not touch the session
    *alive_ = false;
}

void SubmissionServer::on_tls_established() {
    tls_active_ = true;

    // No banner needed here, EHLO is received after the handshake
    logger.info("[SUBMISSION]: " + std::to_string(conn_id_) + " TLS handshake completed");
}

void SubmissionServer::on_data(std::span<const uint8_t> bytes) {
    // While a relay is out, hold whatever the client pipelined after the message
    if (relay_pending_) {
        held_input_.append(bytes.begin(), bytes.end());
        return;
    }

    for (size_t i = 0; i < bytes.size(); ++i) {
        uint8_t b = bytes[i];
        if (state_ == State::Data) {
            // in DATA mode, accumulate the raw bytes
            // and detect teh EOD sequence: CRLF.CRLF
            line_buf_ += static_cast<char>(b);

            data_tail_ += static_cast<char>(b);
            if (data_tail_.size() > 5) {
                data_tail_.erase(0, data_tail_.size() - 5);
            }

            if (data_tail_ == "\r\n.\r\n") {
                env_.body = line_buf_.substr(
                    0, line_buf_.size() - 5
                ); // remove the "\r\n.\r\n"
                line_buf_.clear();
                data_tail_.clear();

                /**
                 * Whatever the outcome, the transaction is over: the user stays
                 * logged in and can start the next message with MAIL FROM.
                 * Leaving the state at Data would read later commands as message text.
                 */
                if (!from_header_owned(env_.body)) {
                    reply(550, "5.7.1 From header must only contain addresses you own");
                }
                else {
                    std::vector<std::pair<std::string, std::string>> external;
                    std::string relay_body;
                    bool local_ok = deliver(external, relay_body);

                    if (!external.empty()) {
                        start_relay(local_ok, std::move(external), std::move(relay_body));

                        state_ = State::Authenticated;
                        env_ = {};

                        // Anything after the message waits for the relay's reply
                        held_input_.append(bytes.begin() + i + 1, bytes.end());
                        return;
                    }

                    if (local_ok) {
                        reply(250, "OK: Message Accepted");
                    }
                    else {
                        reply(452, "Insufficient Storage");
                    }
                }

                state_ = State::Authenticated;
                env_ = {};
            }
        }
        else {
            // Command mode: buffer until LF
            if (b == '\n') {
                // Strip until CR isn't present
                if (!line_buf_.empty() && line_buf_.back() == '\r') {
                    line_buf_.pop_back();
                }

                process_line(line_buf_);
                line_buf_.clear();


                if (tls_upgrade_pending_) {
                    tls_upgrade_pending_ = false;
                    return;
                }
            }
            else {
                line_buf_ += static_cast<char>(b);
                // Guard against long lines (RFC-5321 4.5.3)
                if (line_buf_.size() > 2048) {
                    reply(500, "Line too long");
                    line_buf_.clear();
                }
            }
        }
    }
}

auto SubmissionServer::extract_address(const std::string& body, const std::string& header_name) {
    std::vector<std::string> addresses = {};
    std::istringstream ss(body);
    std::string line{};
    bool in_header{ false };

    while (std::getline(ss, line)) {
        if (line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.empty()) {
            break;
        }

        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower.substr(0, header_name.size() + 1) == header_name + ":") {
            in_header = true;
            line = line.substr(header_name.size() + 1);
        }
        else if (in_header && (line[0] == ' ' || line[0] == '\t')) {
            // folded header continuation
        }
        else {
            in_header = false;
            continue;
        }

        if (in_header) {
            std::istringstream field(line);
            std::string token{};

            while (std::getline(field, token, ',')) {
                auto lt = token.find('<');
                auto gt = token.find('>');

                if (lt != std::string::npos && gt != std::string::npos) {
                    token = token.substr(lt + 1, gt - lt - 1);
                }

                // trim WS
                auto start = token.find_first_not_of(" \t");
                auto end = token.find_last_not_of(" \t");

                if (start != std::string::npos) {
                    token = token.substr(start, end - start + 1);
                }

                if (!token.empty()) {
                    addresses.push_back(token);
                }
            }
        }
    }

    return addresses;
}

auto SubmissionServer::strip_header(const std::string& body, const std::string& header_name) {
    std::string result{};
    std::istringstream ss(body);
    std::string line{};
    bool skipping{ false };

    while (std::getline(ss, line)) {
        std::string stripped{ line };

        if (!stripped.empty() && stripped.back() == '\r') {
            stripped.pop_back();
        }

        if (stripped.empty()) {
            // End of the header block: the body is copied byte for byte, never filtered
            result += line + "\n";
            result.append(std::istreambuf_iterator<char>(ss), std::istreambuf_iterator<char>());

            return result;
        }

        std::string lower{ stripped };
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower.substr(0, header_name.size() + 1) == header_name + ":") {
            skipping = true;
            continue;
        }

        if (skipping && (stripped[0] == ' ' || stripped[0] == '\t')) {
            continue;
        }

        skipping = false;
        result += line + "\n";
    }

    return result;
}

void SubmissionServer::process_line(std::string_view line) {
    // If SASL is in exchange, the line will be continuous, not a command
    if (sasl_.in_progress()) {
        // "*" Cancels the exchange
        auto resp = sasl_.respond(std::string(line));
        reply(resp.code, resp.message);

        if (resp.code == 235) {
            state_ = State::Authenticated;
        }

        return;
    }

    if (line.empty()) {
        return;
    }

    // Continue like SMTP
    auto sp = line.find(' ');
    std::string verb(line.substr(0, sp));
    std::string_view arg = (sp != std::string_view::npos) ? line.substr(sp + 1) : std::string_view("");

    // normalise verb to upper-case
    for (char& c : verb) {
        c = static_cast<char>(std::toupper(c));
    }

    logger.debug("[SUBMISSION]: " + std::to_string(conn_id_) + std::string(line));

    if (verb == "EHLO") {
        cmd_ehlo(arg);
    }
    else if (verb == "HELO") {
        cmd_helo(arg);
    }
    else if (verb == "MAIL") {
        cmd_mail(arg);
    }
    else if (verb == "RCPT") {
        cmd_rcpt(arg);
    }
    else if (verb == "DATA") {
        cmd_data();
    }
    else if (verb == "RSET") {
        cmd_rset();
    }
    else if (verb == "NOOP") {
        cmd_noop();
    }
    else if (verb == "QUIT") {
        cmd_quit();
    }
    else if (verb == "VRFY" || verb == "EXPN") {
        reply(502, "Command not implemented");
    }
    else if (verb == "AUTH") {
        cmd_auth(arg);
    }
    else if (verb == "STARTTLS") {
        cmd_starttls();
    }
    else {
        reply(500, "Command unrecognised");
    }
}

void SubmissionServer::cmd_ehlo(std::string_view arg) {
    client_helo_ = std::string(trim(arg));
    env_ = {};
    state_ = State::Greeted;

    std::vector<std::string> caps = {
        get_hostname() + " greets " + client_helo_,
        "8BITMIME",
        "PIPELINING",
        "SIZE 52428800"
    };

    if (loop_.is_tls_active(conn_id_)) {
        caps.push_back("AUTH PLAIN LOGIN");
    }
    else {
        /// Note: kept for Outlook compat.
        caps.push_back("STARTTLS");
        // We reject AUTH without TLS, so no need to guard here
        caps.push_back("AUTH PLAIN LOGIN");
    }

    reply_multiline(250, caps);
}

void SubmissionServer::cmd_starttls() {
    if (tls_upgrade_pending_) {
        reply(503, "TLS already pending");
        return;
    }

    if (loop_.is_tls_active(conn_id_)) {
        reply(503, "TLS Already Active");
        return;
    }

    reply(220, "Ready to start TLS");
    env_ = {};
    state_ = State::Greeted;

    line_buf_.clear();
    tls_upgrade_pending_ = true;
    loop_.upgrade_tls(conn_id_);
}

void SubmissionServer::cmd_auth(std::string_view arg) {
    if (!loop_.is_tls_active(conn_id_)) {
        reply(538, "5.7.11 Encryption required for AUTH");
        return;
    }

    if (state_ == State::Authenticated) {
        reply(503, "Already authenticated");
        return;
    }

    if (state_ != State::Greeted) {
        reply(503, "Bad sequence of commands");
        return;
    }

    auto sp = arg.find(' ');
    std::string mechanism(arg.substr(0, sp));
    std::string initial = (sp != std::string_view::npos) ? std::string(arg.substr(sp + 1)) : "";

    auto resp = sasl_.begin(mechanism, initial);
    reply(resp.code, resp.message);

    if (resp.code == 235) {
        state_ = State::Authenticated;
    }
    else if (resp.code == 334) {
        // Challenge has been sent, we wait on greeted until it's complete
        state_ = State::Greeted;
    }
}

bool SubmissionServer::owns_address(const std::string& address) {
    auto lower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    };

    const std::string wanted = lower(address);
    if (wanted.empty() || sasl_.username().empty()) {
        return false;
    }

    if (wanted == lower(sasl_.username()) + "@" + lower(get_hostname())) {
        return true;
    }

    for (const auto& alias : aliases_.list_for(sasl_.username())) {
        if (lower(alias) == wanted) {
            return true;
        }
    }

    return false;
}

bool SubmissionServer::from_header_owned(const std::string& message) {
    // Collect the unfolded From header value(s) from the header block only
    std::vector<std::string> values;
    std::istringstream ss(message);
    std::string line;
    bool in_from{ false };

    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.empty()) {
            break; // end of headers
        }

        if (line[0] == ' ' || line[0] == '\t') {
            if (in_from) {
                values.back() += " " + line; // folded continuation of this From header
            }
            continue;
        }

        const size_t colon = line.find(':');
        std::string name = line.substr(0, colon);
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);

        in_from = (colon != std::string::npos && name == "from");
        if (in_from) {
            values.push_back(line.substr(colon + 1));
        }
    }

    std::vector<std::string> addresses;
    for (std::string value : values) {
        // Drop (comments), which may contain anything
        std::string cleaned;
        int depth = 0;
        for (const char c : value) {
            if (c == '(') { ++depth; continue; }
            if (c == ')' && depth > 0) { --depth; continue; }
            if (depth == 0) { cleaned += c; }
        }

        if (cleaned.find('<') != std::string::npos) {
            // Display names may contain commas, so only trust what is inside <...>
            size_t pos = 0;
            while ((pos = cleaned.find('<', pos)) != std::string::npos) {
                const size_t close = cleaned.find('>', pos);
                if (close == std::string::npos) {
                    return false;
                }
                addresses.push_back(std::string(trim(cleaned.substr(pos + 1, close - pos - 1))));
                pos = close + 1;
            }
        }
        else {
            std::istringstream parts(cleaned);
            std::string part;
            while (std::getline(parts, part, ',')) {
                if (!trim(part).empty()) {
                    addresses.push_back(std::string(trim(part)));
                }
            }
        }
    }

    // RFC 5322 3.6.2 requires a From header; every address in it must be the user's
    if (addresses.empty()) {
        return false;
    }

    for (const auto& address : addresses) {
        if (!owns_address(address)) {
            return false;
        }
    }

    return true;
}

void SubmissionServer::cmd_helo(std::string_view arg) {
    client_helo_ = std::string(trim(arg));
    env_ = {};
    reply(250, get_hostname());
    state_ = State::Greeted;
}

void SubmissionServer::cmd_mail(std::string_view arg) {
    if (state_ != State::Authenticated) {
        if (state_ == State::Greeted) {
            reply(530, "5.7.0 Authentication Required");
        }
        else {
            reply(503, "Bad sequence of commands");
        }

        return;
    }

    std::string upper(arg);
    for (char& c : upper) {
        c = static_cast<char>(std::toupper(c));
    }

    // Check the syntax before slicing, so a short argument can't throw
    if (upper.substr(0, 5) != "FROM:") {
        reply(501, "Syntax: MAIL FROM:<address>");
        return;
    }

    auto addr = std::string(extract_address(arg.substr(5)));

    // RFC 6409 6.1: the MSA may only accept senders the authenticated user is allowed to use
    if (!owns_address(addr)) {
        reply(550, "5.7.1 Sender address not owned by the authenticated user");
        return;
    }

    env_.mail_from = addr;
    state_ = State::Mail;
    reply(250, "OK");
}

void SubmissionServer::cmd_rcpt(std::string_view arg) {
    if (state_ != State::Mail && state_ != State::Rcpt) {
        reply(503, "Bad Sequence of Commands");
        return;
    }

    std::string upper(arg);
    for (char& c : upper) {
        c = static_cast<char>(std::toupper(c));
    }

    if (upper.substr(0, 3) != "TO:") {
        reply(501, "Syntax: RCPT TO:<addr>");
        return;
    }

    auto addr = std::string(extract_address(arg.substr(3)));

    if (addr.empty()) {
        reply(501, "Empty Recipient");
        return;
    }


    // RFC 5321 4.5.3: max 100
    if (env_.rcpt_to.size() >= 100) {
        reply(452, "4.5.3 Too Many Recipients");
        return;
    }

    auto at = addr.find('@');
    const std::string domain = (at != std::string::npos) ? addr.substr(at + 1) : "";
    std::string domain_lower = domain;
    std::transform(domain_lower.begin(), domain_lower.end(), domain_lower.begin(), ::tolower);

    if (!Storage::MailDir::is_safe(domain_lower)) {
        reply(550, "Mailbox unavailable");
        return;
    }

    std::string local_domain = get_hostname();
    std::transform(local_domain.begin(), local_domain.end(), local_domain.begin(), ::tolower);

    /**
     * This is the submission port: RCPT is only reachable after AUTH and MAIL,
     * so external recipients are what it exists for (RFC 6409). Relaying is
     * blocked on port 25 instead, where senders are not authenticated.
     */
    if (domain_lower != local_domain) {
        env_.rcpt_to.push_back(addr);
        state_ = State::Rcpt;
        reply(250, "OK");
        return;
    }

    std::string resolved = aliases_.resolve(addr);
    bool is_alias = (resolved != addr);

    if (is_alias) {
        if (!aliases_.accept_and_consume(addr)) {
            reply(550, "Mailbox unavailable");
            return;
        }

        std::string sender_domain = Auth::Aliases::extract_domain(env_.mail_from);
        if (!aliases_.is_domain_allowed(addr, sender_domain)) {
            logger.info("[SUBMISSION] Rejected " + env_.mail_from + " -> " + addr + " (sender domain not allowed)");
            reply(550, "Mailbox unavailable");
            return;
        }
    }

    env_.rcpt_to.push_back(addr);
    state_ = State::Rcpt;
    reply(250, "OK");
}

void SubmissionServer::cmd_data() {
    if (state_ != State::Rcpt) {
        reply(503, "Bad sequence of commands");
        return;
    }

    reply(354, "Start mail input; end with <CRLF>.<CRLF>");
    state_ = State::Data;
    line_buf_.clear();
    data_tail_.clear();
}

void SubmissionServer::cmd_rset() {
    env_ = {};

    state_ = sasl_.authenticated() ? State::Authenticated : State::Greeted;
    reply(250, "OK");
}

void SubmissionServer::cmd_noop() {
    reply(250, "OK");
}

void SubmissionServer::cmd_quit() {
    reply(221, get_hostname() + " closing connection");
    state_ = State::Done;
    pending_close_ = true;
    loop_.submit_close(conn_id_);
}

bool SubmissionServer::deliver(std::vector<std::pair<std::string, std::string>>& external, std::string& relay_body) {
    // TODO: Encrypt before writing
    bool all_ok = true;
    std::string local_domain = get_hostname();
    std::transform(local_domain.begin(), local_domain.end(), local_domain.begin(), ::tolower);
    std::vector<std::string> all_rcpts = env_.rcpt_to;

    for (const auto& hdr : { "cc", "bcc" }) {
        for (const auto& addr : extract_address(env_.body, hdr)) {
            auto at = addr.find('@');
            if (at == std::string::npos) {
                continue;
            }

            std::string domain = addr.substr(at + 1);
            std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

            if (domain.empty() || domain != local_domain) {
                continue;
            }

            if (std::find(all_rcpts.begin(), all_rcpts.end(), addr) == all_rcpts.end()) {
                all_rcpts.push_back(addr);
            }
        }
    }

    std::string outbound_body = strip_header(env_.body, "bcc");
    relay_body = outbound_body;

    for (const auto& rcpt : all_rcpts) {
        // Extract local/account name (before @)
        auto at = rcpt.find('@');
        std::string domain = (at != std::string::npos) ? rcpt.substr(at + 1) : "";
        std::string local = (at != std::string::npos) ? rcpt.substr(0, at) : rcpt;

        if (!Storage::MailDir::is_safe(local)) {
            logger.warn("[DELIVER] Rejected unsafe local part");
            all_ok = false;

            continue;
        }

        std::string domain_lower = domain;
        std::transform(domain_lower.begin(), domain_lower.end(), domain_lower.begin(), ::tolower);

        if (domain.empty() || domain_lower == local_domain) {

            std::string target = aliases_.resolve(rcpt);
            std::string mailbox_user = target;

            auto tat = mailbox_user.find('@');
            if (tat != std::string::npos) {
                mailbox_user = mailbox_user.substr(0, tat);
            }

            if (!Storage::MailDir::is_safe(mailbox_user)) {
                logger.warn("[DELIVER] Rejected unsafe local part");
                all_ok = false;

                continue;
            }

            std::filesystem::path target_path = std::filesystem::weakly_canonical(
                std::filesystem::path(get_mailroot()) / mailbox_user
            );

            std::filesystem::path root_path = std::filesystem::weakly_canonical(get_mailroot());

            auto [root_match, target_match] = std::mismatch(root_path.begin(), root_path.end(), target_path.begin());
            if (root_match != root_path.end()) {
                logger.warn("[DELIVER] Attempted path traversal blocked");
                all_ok = false;

                continue;
            }

            Storage::MailDir mdir(target_path);
            // Recipients must never see the Bcc list (RFC 5322 3.6.3)
            auto stored_path = mdir.deliver(env_.mail_from, rcpt, outbound_body);

            if (!stored_path) {
                logger.error("[DELIVER] Failed for: " + rcpt);
                all_ok = false;
            }

            if (target != rcpt) {
                aliases_.schedule_purge(rcpt, mailbox_user, *stored_path);
            }
        }
        else {
            // Relayed off the event loop, see start_relay()
            external.emplace_back(rcpt, domain);
        }
    }

    return all_ok;
}

void SubmissionServer::start_relay(
    bool local_ok, std::vector<std::pair<std::string, std::string>> external,
    std::string body
) {
    relay_pending_ = true;

    relay_workers().submit([
        post = loop_.poster(), signer = dkim_signer_, alive = alive_, this,
        local_ok, external = std::move(external), body = std::move(body), from = env_.mail_from
    ]() {
        bool ok = local_ok;

        for (const auto& [rcpt, domain] : external) {
            if (!relay_outbound(*signer, from, rcpt, domain, body)) {
                logger.error("[DELIVER] Relay failed for: " + rcpt);
                ok = false;
            }
        }

        // Back to the loop thread. Only touch the session there, and only if it's still around
        post([alive, this, ok]() {
            if (*alive) {
                finish_relay(ok);
            }
            });
        });
}

void SubmissionServer::finish_relay(bool ok) {
    relay_pending_ = false;

    if (ok) {
        reply(250, "OK: Message Accepted");
    }
    else {
        reply(452, "Insufficient Storage");
    }

    if (!held_input_.empty()) {
        std::string held = std::move(held_input_);
        held_input_.clear();

        on_data(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(held.data()), held.size()));
    }
}

bool SubmissionServer::relay_outbound(
    DKIM::Signer& signer,
    const std::string& from, const std::string& to,
    const std::string& domain, const std::string& body
) {
    // MX lookup
    unsigned char answer[4096]{};
    int len = res_query(domain.c_str(), C_IN, T_MX, answer, sizeof(answer));

    if (len < 0) {
        /**
         * RFC 5321 5.1: a domain that exists but has no MX records is treated
         * as having an implicit MX pointing at the domain itself. res_query
         * reports that case as an error (NO_DATA), so map it to an empty,
         * zeroed answer and let the fallback below pick the domain's address.
         */
        if (h_errno != NO_DATA) {
            logger.error("[RELAY] MX Lookup failed for: " + domain);
            return false;
        }

        logger.info("[RELAY] No MX records for " + domain + ", using implicit MX");
        len = sizeof(HEADER);
    }

    HEADER* header = reinterpret_cast<HEADER*>(answer);
    unsigned char* ptr = answer + sizeof(HEADER);
    unsigned char* end = answer + len;

    // skip question
    int qdcount = ntohs(header->qdcount);
    for (int i = 0; i < qdcount; i++) {
        while (ptr < end && *ptr != 0) {
            if ((*ptr & 0xC0) == 0xC0) {
                ptr += 2;
                break;
            }
            ptr += *ptr + 1;
        }

        if (ptr < end && *ptr == 0) {
            ptr++;
        }

        ptr += 4;
    }

    int ancount = ntohs(header->ancount);
    std::string mx_host;
    uint16_t mx_prio = 65535;

    for (int i = 0; i < ancount; i++) {
        // skip name
        while (ptr < end) {
            if ((*ptr & 0xC0) == 0xC0) {
                ptr += 2;
                break;
            }

            if (*ptr == 0) {
                ptr++;
                break;
            }

            ptr += *ptr + 1;
        }

        if (ptr + 10 > end) {
            break;
        }

        uint16_t type;
        memcpy(&type, ptr, 2);
        type = ntohs(type);
        ptr += 2;
        ptr += 2; // class
        ptr += 4; // ttl

        uint16_t rdlen;
        memcpy(&rdlen, ptr, 2);
        rdlen = ntohs(rdlen);
        ptr += 2;

        unsigned char* rdata_end = ptr + rdlen;

        if (type == T_MX && ptr + 2 <= end) {
            uint16_t prio;
            memcpy(&prio, ptr, 2);
            prio = ntohs(prio);
            ptr += 2;

            char host[256] = {};
            dn_expand(answer, end, ptr, host, sizeof(host));

            if (prio < mx_prio) {
                mx_prio = prio;
                mx_host = host;
            }
        }

        ptr = rdata_end;
    }

    if (mx_host.empty()) {
        mx_host = domain;
    }

    struct addrinfo hints {}, * res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(mx_host.c_str(), "25", &hints, &res) != 0 || !res) {
        logger.error("[RELAY] getaddrinfo failed for: " + mx_host);
        return false;
    }

    static const TLS::ClientContext client_ctx;
    bool tls_active{ false };
    SSL* ssl{ nullptr };

    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        freeaddrinfo(res);
        return false;
    }

    auto close_conn = [&]() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);

            ssl = nullptr;
        }

        ::close(sock);
        };

    auto raw_send = [&](const char* data, size_t n) -> ssize_t {
        if (tls_active && ssl) {
            int written = SSL_write(ssl, data, static_cast<int>(n));

            return written > 0 ? written : -1;
        }

        return ::send(sock, data, n, 0);
        };

    auto raw_recv_byte = [&](char& c) -> ssize_t {
        if (tls_active && ssl) {
            int n = SSL_read(ssl, &c, 1);

            return n > 0 ? n : -1;
        }

        return ::recv(sock, &c, 1, 0);
        };

    // 30 second timeout
    struct timeval tv { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        logger.error("[RELAY] connect failed for: " + mx_host + " because: " + std::string(strerror(errno)));

        ::close(sock);
        freeaddrinfo(res);
        return false;
    }

    freeaddrinfo(res);

    // SMTP Exchange
    auto recv_line = [&]() -> std::string {
        std::string line;
        char c;

        while (raw_recv_byte(c) == 1) {
            line += c;
            if (line.size() >= 2 && line[line.size() - 2] == '\r' && line.back() == '\n') {
                break;
            }
        }

        logger.debug("[RELAY] " + line);
        return line;
        };

    auto send_all = [&](std::string_view data) -> bool {
        size_t sent = 0;

        while (sent < data.size()) {
            ssize_t n = raw_send(data.data() + sent, data.size() - sent);

            if (n <= 0) {
                logger.error("[RELAY] send() failed: " + std::string(strerror(errno)));
                return false;
            }

            sent += static_cast<size_t>(n);
        }

        return true;
        };

    auto send_line = [&](const std::string& line) {
        logger.debug("[RELAY] " + line);

        std::string out = line + "\r\n";
        return send_all(line + "\r\n");
        };

    auto expect_multiline = [&](int expected, std::vector<std::string>* out_lines) -> bool {
        std::string last;

        while (true) {
            last = recv_line();

            if (last.empty()) {
                logger.error("[RELAY] Connection closed/timeout waiting for SMTP response");
                return false;
            }

            logger.debug("[RELAY] <-- " + last);

            if (out_lines) {
                out_lines->push_back(last);
            }

            if (last.size() >= 4 && last[3] == ' ') {
                break;
            }

            if (last.size() < 4) {
                logger.error("[RELAY] Malformed SMTP response: " + last);
                return false;
            }
        }

        if (last.size() < 3) {
            return false;
        }

        int actual = 0;
        try {
            actual = std::stoi(last.substr(0, 3));
        }
        catch (...) {
            logger.error("[RELAY] Invalid SMTP response: " + last);
            return false;
        }

        if (actual != expected) {
            logger.error(
                "[RELAY] Expected " + std::to_string(expected) +
                ", got: " + last
            );
            return false;
        }

        return true;
        };

    auto expect = [&](int expected) -> bool {
        return expect_multiline(expected, nullptr);
        };

    bool ok = true;

    if (!expect(220)) {
        ::close(sock);
        return false;
    }

    std::vector<std::string> ehlo_caps;
    send_line("EHLO " + get_hostname());
    bool ehlo_ok = expect_multiline(250, &ehlo_caps);

    if (!ehlo_ok) {
        send_line("HELO " + get_hostname());
        if (!expect(250)) {
            close_conn();
            return false;
        }
    }
    else {
        bool supports_tls = std::any_of(
            ehlo_caps.begin(), ehlo_caps.end(),
            [](const std::string& line) {
                std::string upper = line;
                std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

                return upper.find("STARTTLS") != std::string::npos;
            }
        );

        if (supports_tls) {
            send_line("STARTTLS");
            if (expect(220)) {
                ssl = client_ctx.handshake(sock, mx_host);
                if (ssl) {
                    tls_active = true;
                    logger.info("[RELAY] TLS established with: " + mx_host);

                    /// RFC 3207 - must discard prior EHLO states and re-greet over TLS
                    std::vector<std::string> post_tls_caps;
                    send_line("EHLO " + get_hostname());
                    if (!expect_multiline(250, &post_tls_caps)) {
                        logger.error("[RELAY] EHLO after STARTTLS failed for: " + mx_host);
                        close_conn();

                        return false;
                    }
                }
                else {
                    logger.error("[RELAY] TLS handshake failed for: " + mx_host);
                    close_conn();

                    return false;
                }
            }
            else {
                logger.warn("[RELAY] " + mx_host + " advertised STARTTLS but rejected the command. Continuing as plaintext");
            }
        }
    }

    send_line("MAIL FROM:<" + from + ">");
    if (!expect(250)) {
        ok = false;
    }

    if (ok) {
        send_line("RCPT TO:<" + to + ">");
        if (!expect(250)) {
            ok = false;
        }
    }

    if (ok) {
        send_line("DATA");
        if (!expect(354)) {
            ok = false;
        }
    }

    std::string outbound = body;

    if (ok) {
        try {
            outbound = signer.sign_message(body);
            logger.debug("[RELAY] Signed message:\n" + outbound);
        }
        catch (const std::exception& e) {
            logger.error("[OUTBOUND_RELAY] DKIM Signing failed: " + std::string(e.what()));
            ok = false;
        }
    }

    if (ok) {
        std::istringstream ss(outbound);
        std::string line;
        while (std::getline(ss, line)) {
            if (!line.empty() && line.front() == '.') {
                line = "." + line;
            }
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            send_line(line);
        }

        send_line(".");
        if (!expect(250)) {
            ok = false;
        }
    }

    send_line("QUIT");
    expect(221);
    close_conn();

    logger.debug("[RELAY] Delivery to " + to + std::string(ok ? "succeeded" : "failed"));
    return ok;
}

void SubmissionServer::reply(int code, std::string_view text) {
    std::string line(std::to_string(code) + " " + std::string(text));
    line += "\r\n";

    logger.debug("[SUBMISSION] " + std::to_string(conn_id_) + " > " + std::string(text));

    std::vector<uint8_t> buf(line.begin(), line.end());
    loop_.submit_write(conn_id_, std::move(buf));
}

void SubmissionServer::reply_multiline(int code, const std::vector<std::string>& lines) {
    // RFC 5321 4.2.1 Intermediate lines use "<code>-"
    std::string code_str = std::to_string(code);
    std::string out;

    for (size_t i = 0; i < lines.size(); ++i) {
        bool last = (i + 1 == lines.size());
        out += code_str;
        out += (last ? ' ' : '-');
        out += lines[i];
        out += "\r\n";
    }

    logger.debug("[SUBMISSION] " + std::to_string(conn_id_) + " > " + code_str + "(multiline, " + std::to_string(lines.size()) + " lines)");

    std::vector<uint8_t> buf(out.begin(), out.end());
    loop_.submit_write(conn_id_, std::move(buf));
}

std::string_view SubmissionServer::trim(std::string_view sv) {
    auto start = sv.find_first_not_of(" \t\r\n");

    if (start == std::string_view::npos) {
        return{};
    }

    auto end = sv.find_last_not_of(" \t\r\n");
    return sv.substr(start, end - start + 1);
}

std::string_view SubmissionServer::extract_address(std::string_view arg) {
    arg = trim(arg);

    // Strip an ESMTP parameters after the address
    auto space = arg.find(' ');
    if (space != std::string_view::npos) {
        arg = arg.substr(0, space);
    }

    if (!arg.empty() && arg.front() == '<' && arg.back() == '>') {
        arg = arg.substr(1, arg.size() - 2);
    }

    return trim(arg);
}
