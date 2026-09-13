#include "io/io_uring_loop.hpp"
#include "auth/credentials/cred_store.hpp"
#include "smtp/smtp_session.hpp"
#include "smtp/submission_server.hpp"
#include "imap/session.hpp"
#include "utils/config/toml_parse.hpp"
#include "globals.hpp"
#include "auth/credentials/aliases.hpp"
#include "utils/shutdown.hpp"
#include "utils/arg_parse.hpp"

#include <csignal>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <iostream>
#include <unistd.h>

// build info
static constexpr const char* JAMS_VERSION = "0.2.2-beta";
static const std::string JAMS_HOSTNAME = get_hostname();

// Signal handling
volatile sig_atomic_t g_shutdown = 0;

struct Config {
    uint16_t smtp_port;
    uint16_t submission_port;
    uint16_t imap4_secure_port;
    uint16_t imap4_port;
    std::string db_path;
};

int main(int argc, char* argv[]) {
    Config cfg;

    // Process our CLI args
    arg_parse(argc, argv, cfg);

    // Display our versioning banner, this persists the no-log 
    // for liveness reasons.
    banner();

    logger.info("[JAMS] Opening user database: " + cfg.db_path);
    Auth::CredentialStore cred_store(cfg.db_path);
    Auth::Aliases aliases(cred_store);

    if (cred_store.db_ == nullptr) {
        logger.error(
            "[FATAL] [JAMS] Could not open database: " + cfg.db_path +
            "\n        create the directory first:\n" +
            "        sudo mkdir -p /var/lib/jams\n" +
            "        sudo chown $USER /var/lib/jams"
        );

        return 1;
    }

    // Signal monitor setup
    struct sigaction sig_action = {};
    sig_action.sa_handler = handle_signal;
    sigemptyset(&sig_action.sa_mask);
    sig_action.sa_flags = SA_RESTART;

    sigaction(SIGHUP, &sig_action, nullptr);
    sigaction(SIGTERM, &sig_action, nullptr);
    sigaction(SIGINT, &sig_action, nullptr);

    // SIGPIPE
    signal(SIGPIPE, SIG_IGN);

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

    threads.emplace_back(std::move(smtp_thread));
    threads.emplace_back(std::move(imap4_thread));
    threads.emplace_back(std::move(imap4_secure_thread));
    threads.emplace_back(std::move(submission_thread));

    logger.info("[JAMS] Exiting...");

    return server_failed ? EXIT_FAILURE : 0;
}