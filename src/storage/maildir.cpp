#include "storage/maildir.hpp"
#include "globals.hpp"

#include <unistd.h>
#include <sys/types.h>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace Storage;

MailDir::MailDir(std::string base_path) : base_(std::move(base_path)) {};

bool MailDir::ensure_dirs() {
    namespace fs = std::filesystem;

    logger.debug("[MAILDIR] ensure_dirs() base_ = '" + base_.string() + "' absolute = '" + fs::absolute(base_).string() + "'");

    std::error_code ec;
    for (const char* sub : { ".Sent", ".Trash" }) {
        auto full = base_ / sub;
        logger.debug("[MAILDIR] creating: " + full.string());
        fs::create_directories(full, ec);
        if (ec) {
            logger.debug("[MAILDIR] create_directories(" + full.string() + "): " + ec.message());
            return false;
        }
    }

    for (const char* sub : { "tmp", "new", "cur" }) {
        auto full = base_ / sub;
        logger.debug("[MAILDIR] creating: " + full.string());
        fs::create_directories(full, ec);
        if (ec) {
            logger.debug("[MAILDIR] create_directories(" + full.string() + "): " + ec.message());
            return false;
        }
    }

    return true;
}

std::optional<std::string> MailDir::deliver(
    const std::string& mail_from,
    const std::string& rcpt_to,
    const std::string& body
) {
    bool ensured_dirs = ensure_dirs();

    if (!ensured_dirs) {
        logger.error("[MAILDIR] Failed to ensure directories exist");
        return std::nullopt;
    }

    // Building the mesasge
    auto now_tp = std::chrono::system_clock::now();
    auto now_t = std::chrono::system_clock::to_time_t(now_tp);
    char date_buf[64] = {};
    std::tm tm_buf{};

    if (localtime_r(&now_t, &tm_buf) == nullptr) {
        logger.error("[MAILDIR] localtime_r failed: " + std::string(strerror(errno)));
        return std::nullopt;
    }

    // RFC-2822 date format:
    std::strftime(
        date_buf, sizeof(date_buf),
        "%a, %d %b %Y %H:%M:%S %z",
        &tm_buf
    );

    std::string message = "Received: from unknown (HELO unknown)\r\n"
        "   by " + get_hostname() + " from <" + mail_from + "> for <" + rcpt_to + ">; \r\n"
        "   " + date_buf + "\r\n" + body;

    // Create file and write to tmp/
    std::string fname = unique_filename(message.size());

    auto tmp_path = base_ / "tmp" / fname;
    {
        std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            logger.error("[MAILDIR] open(" + std::string(tmp_path.c_str()) + ") failed: " + std::string(strerror(errno)));
            return std::nullopt;
        }

        ofs.write(message.data(), static_cast<std::streamsize>(message.size()));
        if (!ofs) {
            logger.error("[MAILDIR] Write failed for: " + std::string(tmp_path.c_str()));
            return std::nullopt;
        }

        ofs.flush();
    }

    // Atomically move to new/
    auto new_path = base_ / "new" / fname;
    std::error_code ec;

    logger.debug("[MAILDIR] tmp_path = " + tmp_path.string());
    logger.debug("[MAILDIR] new_path = " + new_path.string());

    std::filesystem::rename(tmp_path, new_path, ec);

    if (ec) {
        logger.error("[MAILDIR] Rename to new/ failed: " + ec.message());

        std::filesystem::remove(tmp_path, ec);
        return std::nullopt;
    }

    logger.info("[MAILDIR] Delivered to " + std::string(new_path.c_str()));
    return std::string(new_path.c_str());
}

bool MailDir::is_safe(const std::string& addr) {
    if (addr.empty() || addr.size() > 64) {
        return false;
    }

    for (char c : addr) {
        // Disallow non-standard characters in domain names
        if (!std::isalnum(
            static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_' && c != '+') {
            return false;
        }
    }

    // Reject leading/trailing dots and double dots
    if (addr.front() == '.' || addr.back() == '.') {
        return false;
    }

    if (addr.find("..") != std::string::npos) {
        return false;
    }

    return true;
}

// Filename Generation
// Format: <sec>.<pid>.<hostname>,S=<size>:2,
//
// The hostname component is capped at 64 chars and dots are replaced with
// underscores (Maildir spec recommendation for portability).
std::string MailDir::unique_filename(size_t body_size) const {
    using namespace std::chrono;

    auto now_us = duration_cast<microseconds>(
        system_clock::now().time_since_epoch()
    ).count();
    long sec = static_cast<long>(now_us / 1'000'000);
    long usec = static_cast<long>(now_us % 1'000'000);
    pid_t pid = ::getpid();

    char hostname[64] = "localhost";

    if (::gethostname(hostname, sizeof(hostname)) != 0) {
        logger.error("[MAILDIR] gethostname failed: " + std::string(strerror(errno)) + "; using fallback hostname 'localhost'");
    }
    else {
        hostname[sizeof(hostname) - 1] = '\0';
    }

    // Replace dots with underscores
    for (char* p = hostname; *p; ++p) {
        if (*p == '.') {
            *p = '_';
        }
    }

    std::ostringstream oss;
    oss << sec
        << "." << usec
        << "." << pid
        << "." << hostname
        << ",S=" << body_size
        << ":2,";   // Maildir++ flags field (empty = no flags)

    return oss.str();
}

