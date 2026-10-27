#pragma once

#include "utils/config/toml_parse.hpp"
#include "utils/logger.hpp"
#include <csignal>

extern volatile sig_atomic_t g_shutdown;

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

/// @brief Reads a positive number from the optional [limits] table
/// @param key 
/// @param fallback Used when the key is missing or not a positive number
/// @return 
inline uint32_t get_limit(const std::string& key, uint32_t fallback) {
    auto itr = configs.find(key);
    if (itr == configs.end()) {
        return fallback;
    }

    try {
        auto value = std::stoul(itr->second);
        return (value > 0 && value <= UINT32_MAX) ? static_cast<uint32_t>(value) : fallback;
    }
    catch (const std::exception&) {
        return fallback;
    }
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
