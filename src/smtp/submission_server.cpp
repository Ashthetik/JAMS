#include "smtp/submission_server.hpp"
#include "io/io_uring_loop.hpp"
#include "storage/maildir.hpp"
#include "tls/tls_client.hpp"
#include "globals.hpp"

#include <cctype>
#include <iostream>
#include <sstream>
#include <resolv.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>
#include <filesystem>

using namespace SMTP;

SubmissionServer::SubmissionServer(
    uint64_t conn_id, const std::string& remote_ip,
    Async::IoUringLoop& loop, Auth::CredentialStore& store,
    Auth::Aliases& aliases
) : dkim_signer_({
        .domain = get_hostname(),
        .selector = "jams",
        .priv_key_path = "/etc/jams/tls/key.pem"
    }), conn_id_(conn_id), remote_ip_(remote_ip), loop_(loop), sasl_(store, remote_ip), aliases_(aliases) {
    reply(220, get_hostname() + " ESMTP submission");
}

void SubmissionServer::on_tls_established() {
    tls_active_ = true;

    // No banner needed here, EHLO is received after the handshake
    logger.info("[SUBMISSION]: " + std::to_string(conn_id_) + " TLS handshake completed");
}

void SubmissionServer::on_data(std::span<const uint8_t> bytes) {
    for (uint8_t b : bytes) {
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

                if (deliver()) {
                    reply(250, "OK: Message Accepted");
                    state_ = State::Greeted;
                    env_ = {};
                }
                else {
                    reply(452, "Insufficient Storage");
                }
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
            skipping = false;
            result += line + "\n";

            continue;
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

    auto addr = std::string(extract_address(arg.substr(5)));
    auto at = addr.find('@');
    const std::string domain = (at != std::string::npos) ? addr.substr(at + 1) : "";

    std::string domain_lower = domain;
    std::transform(domain_lower.begin(), domain_lower.end(), domain_lower.begin(), ::tolower);


    std::string upper(arg);
    for (char& c : upper) {
        c = static_cast<char>(std::toupper(c));
    }

    if (upper.substr(0, 5) != "FROM:") {
        reply(501, "Syntax: MAIL FROM:<address>");
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

    if (domain != get_hostname()) {
        reply(550, "5.7.1 Relaying denied");
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

bool SubmissionServer::deliver() {
    // TODO: Encrypt before writing
    bool all_ok = true;
    const std::string local_domain = get_hostname();
    std::vector<std::string> all_rcpts = env_.rcpt_to;

    for (const auto& hdr : { "cc", "bcc" }) {
        for (const auto& addr : extract_address(env_.body, hdr)) {
            auto at = addr.find('@');
            if (at == std::string::npos) {
                continue;
            }

            std::string domain = addr.substr(at + 1);
            std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

            if (domain.empty() || domain != get_hostname()) {
                continue;
            }

            if (std::find(all_rcpts.begin(), all_rcpts.end(), addr) == all_rcpts.end()) {
                all_rcpts.push_back(addr);
            }
        }
    }

    std::string outbound_body = strip_header(env_.body, "bcc");

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

        if (domain.empty() || domain == get_hostname()) {

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
            auto stored_path = mdir.deliver(env_.mail_from, rcpt, env_.body);

            if (!stored_path) {
                logger.error("[DELIVER] Failed for: " + rcpt);
                all_ok = false;
            }

            if (target != rcpt) {
                aliases_.schedule_purge(rcpt, mailbox_user, *stored_path);
            }
        }
        else {
            if (!relay_outbound(env_.mail_from, rcpt, domain, env_.body)) {
                logger.error("[DELIVER] Relay failed for: " + rcpt);
                all_ok = false;
            }
        }
    }

    return all_ok;
}

bool SubmissionServer::relay_outbound(
    const std::string& from, const std::string& to,
    const std::string& domain, const std::string& body
) {
    // MX lookup
    unsigned char answer[4096];
    int len = res_query(domain.c_str(), C_IN, T_MX, answer, sizeof(answer));

    if (len < 0) {
        logger.error("[RELAY] MX Lookup failed for: " + domain);
        return false;
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
            outbound = dkim_signer_.sign_message(body);
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
