#include "smtp/smtp_session.hpp"
#include "io/io_uring_loop.hpp"
#include "storage/maildir.hpp"
#include "globals.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <span>

using namespace SMTP;

Session::Session(
    uint64_t conn_id, std::string remote_ip,
    Async::IoUringLoop& loop, Auth::Aliases& aliases
) : conn_id_(conn_id), remote_ip_(remote_ip), loop_(loop), aliases_(aliases) {
    // RFC-5321 4.2: Send 220 Banner on connect
    reply_code(220, get_hostname() + " ESMTP mailserver/0.1");
    state_ = SMTPState::Greeted; // Wait for EHLO
}

void Session::on_data(std::span<const uint8_t> bytes) {
    for (uint8_t b : bytes) {
        if (state_ == SMTPState::Data) {
            // in DATA mode, accumulate the raw bytes
            // and detect teh EOD sequence: CRLF.CRLF
            line_buf += static_cast<char>(b);

            data_tail_ += static_cast<char>(b);
            if (data_tail_.size() > 5) {
                data_tail_.erase(0, data_tail_.size() - 5);
            }

            if (data_tail_ == "\r\n.\r\n") {
                env_.body = line_buf.substr(
                    0, line_buf.size() - 5
                ); // remove the "\r\n.\r\n"
                line_buf.clear();
                data_tail_.clear();

                if (deliver()) {
                    reply_code(250, "OK: Message Accepted");
                    state_ = SMTPState::Greeted;
                    env_ = {};
                }
                else {
                    reply_code(452, "Insufficient Storage");
                }
            }
        }
        else {
            // Command mode: buffer until LF
            if (b == '\n') {
                // Strip until CR isn't present
                if (!line_buf.empty() && line_buf.back() == '\r') {
                    line_buf.pop_back();
                }

                process_line(line_buf);
                line_buf.clear();

                if (tls_upgrade_pending_) {
                    tls_upgrade_pending_ = false;
                    return;
                }
            }
            else {
                line_buf += static_cast<char>(b);
                // Guard against long lines (RFC-5321 4.5.3)
                if (line_buf.size() > 2048) {
                    reply_code(500, "Line too long");
                    line_buf.clear();
                }
            }
        }
    }
}

void Session::process_line(std::string_view line) {
    if (line.empty()) {
        return;
    }

    auto sp = line.find(' ');
    std::string verb(line.substr(0, sp));
    std::string_view arg = (sp != std::string_view::npos) ? line.substr(sp + 1) : std::string_view("");

    // normalise verb to upper-case
    for (char& c : verb) {
        c = static_cast<char>(std::toupper(c));
    }

    logger.debug("[SMTP] " + std::to_string(conn_id_) + std::string(line));

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
    else if (verb == "STARTTLS") {
        cmd_starttls();
    }
    else {
        reply_code(500, "Command unrecognised");
    }
}

void Session::cmd_ehlo(std::string_view arg) {
    client_helo_ = std::string(trim(arg));
    env_ = {};

    reply_multiline(250, {
        get_hostname() + " greets " + client_helo_,
        "8BITMIME",
        "PIPELINING",
        "SIZE 52428800",   // 50 MB max message size
        "STARTTLS",
        });
    state_ = SMTPState::Greeted;
}

void Session::cmd_helo(std::string_view arg) {
    client_helo_ = std::string(trim(arg));
    env_ = {};
    reply_code(250, get_hostname());
    state_ = SMTPState::Greeted;
}

void Session::cmd_mail(std::string_view arg) {
    if (state_ != SMTPState::Greeted) {
        reply_code(503, "Bad Sequence of Commands");
        return;
    }

    // Expect: FROM:<addr> [params]
    std::string upper(arg);
    for (char& c : upper) {
        c = static_cast<char>(std::toupper(c));
    }

    if (upper.substr(0, 5) != "FROM:") {
        reply_code(501, "Syntax: MAIL FROM:<addr>");
        return;
    }

    auto addr = std::string(extract_address(arg.substr(5)));
    if (addr.empty()) {
        reply_code(501, "Empty MAIL FROM:<...>");
        return;
    }

    env_.mail_from = std::string(extract_address(arg.substr(5)));
    state_ = SMTPState::Mail;
    reply_code(250, "OK");
}

void Session::cmd_rcpt(std::string_view arg) {
    if (state_ != SMTPState::Mail && state_ != SMTPState::RCPT) {
        reply_code(503, "Bad Sequence of Commands");
        return;
    }

    std::string upper(arg);
    for (char& c : upper) {
        c = static_cast<char>(std::toupper(c));
    }

    if (upper.substr(0, 3) != "TO:") {
        reply_code(501, "Syntax: RCPT TO:<addr>");
        return;
    }

    auto addr = std::string(extract_address(arg.substr(3)));
    auto at = addr.find('@');
    std::string local = (at != std::string::npos) ? addr.substr(0, at) : addr;

    if (addr.empty()) {
        reply_code(501, "Empty Recipient");
        return;
    }

    // RFC 5321 4.5.3: max 100
    if (env_.rcpt_to.size() >= 100) {
        reply_code(452, "4.5.3 Too Many Recipients");
        return;
    }

    if (!Storage::MailDir::is_safe(local)) {
        reply_code(550, "Mailbox unavailable");
        return;
    }

    std::string resolved = aliases_.resolve(addr);
    bool is_alias = (resolved != addr);

    if (is_alias) {
        logger.warn("[SMTP] treated as alias: addr='" + addr + "'");
        if (!aliases_.accept_and_consume(addr)) {
            logger.warn("[SMTP] accept_and_consume rejected: " + addr);
            reply_code(550, "Mailbox unavailable");
            return;
        }

        std::string sender_domain = Auth::Aliases::extract_domain(env_.mail_from);
        if (!aliases_.is_domain_allowed(addr, sender_domain)) {
            logger.info("[SMTP] Rejected " + env_.mail_from + " -> " + addr + " (sender domain not allowed)");
            reply_code(550, "Mailbox unavailable");
            return;
        }
    }

    env_.rcpt_to.push_back(addr);
    state_ = SMTPState::RCPT;
    reply_code(250, "OK");
}

void Session::cmd_data() {
    if (state_ != SMTPState::RCPT) {
        reply_code(503, "Bad Sequence of Commands");
        return;
    }

    reply_code(354, "Start mail input; end with <CRLF>.<CRLF>");
    state_ = SMTPState::Data;
    line_buf.clear();
    data_tail_.clear();
}

void Session::cmd_rset() {
    env_ = {};
    state_ = SMTPState::Greeted;
    reply_code(250, "OK");
}

void Session::cmd_noop() {
    reply_code(250, "OK");
}

void Session::cmd_quit() {
    reply_code(221, get_hostname() + " closing connection");
    state_ = SMTPState::Done;
    pending_close_ = true;
}

void Session::cmd_starttls() {
    if (state_ == SMTPState::Data) {
        reply_code(503, "Bad Sequence of Commands");
        return;
    }

    if (tls_upgrade_pending_) {
        reply_code(503, "TLS already pending");
        return;
    }

    if (loop_.is_tls_active(conn_id_)) {
        reply_code(503, "TLS Already Active");
        return;
    }

    // RFC 3207: send 220 then upgrade
    // after HELO, no more SMTP until TLS is started
    reply_code(220, "Ready to start TLS");

    // Reset the sessions state
    env_ = {};
    state_ = SMTPState::Greeted;
    line_buf.clear();
    tls_upgrade_pending_ = true;

    // Hand off to the loop
    loop_.upgrade_tls(conn_id_);
}

auto Session::strip_header(const std::string& body, const std::string& header_name) {
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

bool Session::deliver() {
    // TODO: Encrypt before writing
    bool all_ok = true;
    std::vector<std::string> all_rcpts = env_.rcpt_to;

    std::string clean_body = strip_header(env_.body, "bcc");

    for (const auto& rcpt : env_.rcpt_to) {
        // Extract local/account name (before @)
        auto at = rcpt.find('@');
        std::string target = aliases_.resolve(rcpt);
        std::string mailbox_user = (at != std::string::npos) ? target.substr(0, at) : target;

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
        auto stored_path = mdir.deliver(env_.mail_from, rcpt, clean_body);

        if (!stored_path) {
            logger.error("[DELIVER] Failed for: " + rcpt);
            all_ok = false;
        }

        if (target != rcpt) {
            aliases_.schedule_purge(rcpt, mailbox_user, *stored_path);
        }
    }

    return all_ok;
}

void Session::reply(std::string_view text) {
    std::string line(text);
    line += "\r\n";

    logger.debug("[SMTP] " + std::to_string(conn_id_) + " > " + std::string(text));

    std::vector<uint8_t> buf(line.begin(), line.end());
    loop_.submit_write(conn_id_, std::move(buf));
}

void Session::reply_code(int code, std::string_view msg) {
    reply(std::to_string(code) + " " + std::string(msg));
}

void Session::reply_multiline(
    int code, const std::vector<std::string>& lines
) {
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

    logger.debug(
        "[SMTP] " + std::to_string(conn_id_) + " > " + code_str
        + " (multiline, " + std::to_string(lines.size()) + " lines)"
    );

    std::vector<uint8_t> buf(out.begin(), out.end());
    loop_.submit_write(conn_id_, std::move(buf));
}

std::string_view Session::trim(std::string_view sv) {
    auto start = sv.find_first_not_of(" \t\r\n");

    if (start == std::string_view::npos) {
        return{};
    }

    auto end = sv.find_last_not_of(" \t\r\n");
    return sv.substr(start, end - start + 1);
}

std::string_view Session::extract_address(std::string_view arg) {
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
