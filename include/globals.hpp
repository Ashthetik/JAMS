#pragma once

#include "utils/config/toml_parse.hpp"
#include "utils/logger.hpp"
#include <csignal>

extern volatile sig_atomic_t g_shutdown;
static std::vector<std::thread> threads = {};

inline std::string resolve_path(const char* env, const char* fallback) {
    if (const char* env_ = std::getenv(env)) {
        return env_;
    }

    return fallback;
}

inline bool logs_enabled;

inline Utils::TOMLParser load_configs{ resolve_path("JAMS_CONFIG", "../config/server.toml") };
inline const auto configs = load_configs.fetch_configs();
inline Utils::Logger logger{ resolve_path("JAMS_LOG_PATH", "../logs/jams.txt"), logs_enabled };

inline std::string get_hostname() {
    std::string result{};

    for (auto& host : configs) {
        if (host.first == "hostname") {
            result = host.second;
        }
    }

    return result;
};

inline std::string get_ip_reporter() {
    std::string result{};
    for (auto& addr : configs) {
        if (addr.first == "ip_alert_mta") {
            result = addr.second;
        }
    }

    return result;
}

inline std::string get_mailroot() {
    std::string result{};
    for (auto& root : configs) {
        if (root.first == "mailroot") {
            result = root.second;
        }
    }

    return result;
}

inline std::string get_db_path() {
    std::string result{};

    for (auto& db : configs) {
        if (db.first == "db_path") {
            result = db.second;
        }
    }

    return result;
}


/**
 * JAMS Start-Up Banner
 */
void banner() {
    std::cout
        << "┌─────────────────────────────────────────┐\n"
        << "│   JAMS — Just Another Mail Server       │\n"
        << "│   version " << JAMS_VERSION
        << "                   │\n"
        << "│   github.com/DeTraced-Security/JAMS     │\n"
        << "└─────────────────────────────────────────┘\n";
}