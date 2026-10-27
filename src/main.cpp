#include "io/io_uring_loop.hpp"
#include "auth/credentials/cred_store.hpp"
#include "smtp/smtp_session.hpp"
#include "smtp/submission_server.hpp"
#include "imap/session.hpp"
#include "utils/config/toml_parse.hpp"
#include "globals.hpp"
#include "auth/credentials/aliases.hpp"

#include <csignal>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <iostream>
#include <unistd.h>

// build info
static constexpr const char* JAMS_VERSION = "0.0.1-alpha";
static const std::string JAMS_HOSTNAME = get_hostname();

// Signal handling
volatile sig_atomic_t g_shutdown = 0;
static void handle_signal(int sig) {
    g_shutdown = 1;

    // Write sig number to stderr without ynsafe async functions
    const char* msg = (sig == SIGINT)
        ? "\n[JAMS] SIGINT received... Shutting down\n"
        : "\n[JAMS] SIGTERM received... Shutting down\n";

    ssize_t is_ok = write(STDERR_FILENO, msg, strlen(msg));

    if (is_ok < 0) {
        // Cannot safely use std::cerr/printf here.
        // Nothing useful can be done in a signal handler.
    }
}

void help(const char* prog) {
    std::cerr << "Usage: " << prog << " [options]"
        << "\n"
        << "Server Configuration are made via the `../config/server.toml` file"
        << "\n  --add-user <username> <password>  create an account and exit"
        << "\n  --no-logs                         disable logging"
        << "\n  --help                            show this message\n"
        << "\n"
        << "environment:\n"
        << "  JAMS_PEPPER    required, secret used to derive password salts (keep it stable)\n"
        << "  JAMS_CONFIG    path to server.toml (default ../config/server.toml)\n"
        << "  JAMS_LOG_PATH  path to the log file (default ../logs/jams.txt)\n"
        << "\n"
        << "notes:\n"
        << "  ports below 1024 require CAP_NET_BIND_SERVICE or root\n"
        << "  set with: sudo setcap cap_net_bind_service=+ep ./mailserver" << std::endl;
}

void banner() {
    std::cout
        << "┌─────────────────────────────────────────┐\n"
        << "│   JAMS — Just Another Mail Server       │\n"
        << "│   version " << JAMS_VERSION
        << "                   │\n"
        << "│   github.com/DeTraced-Security/JAMS     │\n"
        << "└─────────────────────────────────────────┘\n";
}

struct Config {
    uint16_t smtp_port;
    uint16_t submission_port;
    uint16_t imap4_secure_port;
    uint16_t imap4_port;
    std::string db_path;
};


int main(int argc, char* argv[]) {
    logs_enabled = true;

    std::string add_username{};
    std::string add_password{};
    bool add_user_requested{ false };

    for (int i = 1; i < argc; ++i) {
        const std::string arg{ argv[i] };

        if (arg == "--help") {
            help("mailserver");
            return 0;
        }
        else if (arg == "--no-logs") {
            logs_enabled = false;
        }
        else if (arg == "--add-user") {
            if (i + 2 >= argc) {
                std::cerr << "[JAMS] --add-user requires <username> <password>" << std::endl;
                return 1;
            }

            add_username = argv[++i];
            add_password = argv[++i];
            add_user_requested = true;
        }
        else if (arg == "--db" || arg == "--smtp-port") {
            // Older docs, the Dockerfile and systemd examples pass these; they were never read
            if (i + 1 < argc) {
                ++i;
            }

            std::cerr << "[JAMS] Ignoring " << arg << ": set it in server.toml instead" << std::endl;
        }
        else {
            std::cerr << "[JAMS] Unknown option: " << arg << std::endl;
            help("mailserver");
            return 1;
        }
    }

    /**
     * Password salts are derived from JAMS_PEPPER, so without it no login can
     * ever succeed. Refuse to start rather than run with authentication silently broken.
     */
    if (std::getenv("JAMS_PEPPER") == nullptr || std::string(std::getenv("JAMS_PEPPER")).empty()) {
        std::cerr << "[FATAL] [JAMS] JAMS_PEPPER is not set. It is required to hash and verify passwords.\n"
            << "        Set it to a long random secret and keep it stable: changing or losing it\n"
            << "        invalidates every stored password." << std::endl;
        return 1;
    }

    Config cfg;

    for (auto& p : configs) {
        if (p.first == "smtp") {
            cfg.smtp_port = std::stoi(p.second);
        }
        if (p.first == "imap4") {
            cfg.imap4_port = std::stoi(p.second);
        }
        if (p.first == "imap4s") {
            cfg.imap4_secure_port = std::stoi(p.second);
        }
        if (p.first == "submissions") {
            cfg.submission_port = std::stoi(p.second);
        }
        if (p.first == "db_path") {
            cfg.db_path = p.second;
        }
    }

    banner();

    // Signal monitor setup
    struct sigaction sig_action {};
    sig_action.sa_handler = handle_signal;
    sigemptyset(&sig_action.sa_mask);
    sig_action.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sig_action, nullptr);
    sigaction(SIGTERM, &sig_action, nullptr);

    // SIGPIPE
    signal(SIGPIPE, SIG_IGN);

    // Credential Storage
    logger.info("[JAMS] Opening user database: " + cfg.db_path);
    Auth::CredentialStore cred_store(cfg.db_path);

    if (cred_store.db_ == nullptr) {
        logger.error(
            "[FATAL] [JAMS] Could not open database: " + cfg.db_path +
            "\n        create the directory first:\n" +
            "        sudo mkdir -p /var/lib/jams\n" +
            "        sudo chown $USER /var/lib/jams"
        );

        return 1;
    }

    if (add_user_requested) {
        if (cred_store.user_exists(add_username)) {
            std::cerr << "[JAMS] User already exists: " << add_username << std::endl;
            return 1;
        }

        if (!cred_store.add_user(add_username, add_password, "")) {
            std::cerr << "[JAMS] Failed to create user: " << add_username
                << " (usernames may only contain letters, digits, '.', '-', '_' and '+')" << std::endl;
            return 1;
        }

        std::cout << "[JAMS] User created: " << add_username << std::endl;
        return 0;
    }

    Auth::Aliases aliases(cred_store);

    // SMTP inbound loop
    logger.info("[JAMS] Starting SMTP inbound on port: " + std::to_string(cfg.smtp_port));
    logger.info("[JAMS] Hostname: " + JAMS_HOSTNAME);
    logger.info("[JAMS] Ready\n");

    std::atomic<bool> server_failed{ false };

    std::thread smtp_thread([&]() {
        try {
            Async::IoUringLoop smtp_loop(cfg.smtp_port, [&aliases](uint64_t id, const std::string& ip, Async::IoUringLoop& loop) {
                return std::make_unique<SMTP::Session>(id, ip, loop, aliases);
                });

            smtp_loop.arm_periodic_timer(std::chrono::seconds(60), [&aliases]() {
                aliases.reap_expired();

                for (auto& [id, path] : aliases.due_purges()) {
                    if (std::remove(path.c_str()) == 0) {
                        aliases.mark_purged(id);
                    }
                    else {
                        logger.error("[PURGE] Failed to remove: " + path);
                    }
                }
                });

            smtp_loop.run();
        }
        catch (const std::exception& ex) {
            logger.error("[FATAL] [JAMS] SMTP Loop: " + std::string(ex.what()));
            server_failed = true;
            g_shutdown = 1;
        }
        });

    std::thread submission_thread([&]() {
        try {
            Async::IoUringLoop submission_loop(cfg.submission_port, [&cred_store, &aliases](uint64_t id, const std::string& ip, Async::IoUringLoop& loop) {
                return std::make_unique<SMTP::SubmissionServer>(id, ip, loop, cred_store, aliases);
                });
            submission_loop.run();
        }
        catch (const std::exception& ex) {
            logger.error("[FATAL] [JAMS] Submission Loop: " + std::string(ex.what()));
            server_failed = true;
            g_shutdown = 1;
        }
        });

    std::thread imap4_thread([&]() {
        try {
            Async::IoUringLoop imap4_loop(cfg.imap4_port, [&cred_store, &aliases](uint64_t id, const std::string& ip, Async::IoUringLoop& loop) {
                return std::make_unique<IMAP::Session>(id, ip, loop, cred_store, get_mailroot());
                });
            imap4_loop.run();
        }
        catch (const std::exception& ex) {
            logger.error("[FATAL] [JAMS] IMAP4 Loop: " + std::string(ex.what()));
            server_failed = true;
            g_shutdown = 1;
        }
        });

    std::thread imap4_secure_thread([&]() {
        try {
            Async::IoUringLoop imap4_secure_loop(cfg.imap4_secure_port, [&cred_store](uint64_t id, const std::string& ip, Async::IoUringLoop& loop) {
                return std::make_unique<IMAP::Session>(id, ip, loop, cred_store, get_mailroot());
                });
            imap4_secure_loop.run();
        }
        catch (const std::exception& ex) {
            logger.error("[FATAL] [JAMS] IMAP4 Secure Loop: " + std::string(ex.what()));
            server_failed = true;
            raise(SIGTERM);
        }
        });

    smtp_thread.join();
    submission_thread.join();
    imap4_thread.join();
    imap4_secure_thread.join();

    logger.info("[JAMS] Exiting...");

    return server_failed ? EXIT_FAILURE : 0;
}