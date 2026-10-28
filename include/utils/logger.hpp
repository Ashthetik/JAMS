#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

namespace Utils {
    enum class LogLevel {
        Debug, Info,
        Warn, Error
    };

    inline const char* to_string(LogLevel lvl) {
        switch (lvl) {
        case LogLevel::Debug: {
            return "DEBUG";
        }
        case LogLevel::Error: {
            return "ERROR";
        }
        case LogLevel::Info: {
            return "INFO";
        }
        case LogLevel::Warn: {
            return "WARN";
        }
        }

        return "?";
    }

    class Logger {
    public:
        explicit Logger(const std::string& filepath, bool& logs_enabled);
        ~Logger();

        Logger(const Logger&) = delete;
        Logger& operator=(const Logger&) = delete;

        void log(LogLevel level, std::string msg);

        void debug(std::string msg);
        void info(std::string msg);
        void warn(std::string msg);
        void error(std::string msg);

        void shutdown();

    private:
        /// @brief Most bytes waiting to be written. Past this, lines are dropped (and counted) rather
        /// than piling up in memory
        static constexpr size_t MAX_QUEUED_BYTES = 16 * 1024 * 1024;

        /// @brief Longest single line kept; some debug lines carry whole messages
        static constexpr size_t MAX_LINE_BYTES = 64 * 1024;

        bool& logs_enabled_;
        std::string filepath_;
        std::ofstream file_;
        std::thread worker_;
        std::mutex mutex_;
        std::condition_variable cv_;
        std::deque<std::string> queue_;
        size_t queued_bytes_{ 0 };
        size_t dropped_{ 0 };
        bool started_{ false };
        bool stopping_{ false };

        /// @brief Opens the file and starts the writer. Called with mutex_ held, on the first
        /// line logged once logging is on: the logger is a global, built before main() turns logging on
        void start_locked();

        std::string format(LogLevel level, std::string msg) const;
        void run();
    };
};
