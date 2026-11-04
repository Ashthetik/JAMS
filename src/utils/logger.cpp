#include "utils/logger.hpp"

#include <iostream>
#include <filesystem>

using namespace Utils;

Logger::Logger(const std::string& filepath, bool& logs_enabled) : logs_enabled_(logs_enabled), filepath_(filepath) {
    // Nothing else here: as a global this runs before main() has turned logging on,
    // so the file and the writer start with the first line logged (start_locked)
}

void Logger::start_locked() {
    started_ = true;

    const std::filesystem::path absolute_path = std::filesystem::weakly_canonical(filepath_);

    std::error_code ec;
    std::filesystem::create_directories(absolute_path.parent_path(), ec);

    file_ = std::ofstream(absolute_path, std::ios::app);

    if (!file_.is_open()) {
        // Keep running: losing the log file shouldn't take the mail server down
        std::cerr << "[logger] [ERROR]: Failed to open: " << filepath_ << ", logging to the console only" << std::endl;
    }

    worker_ = std::thread(&Logger::run, this);
}


Logger::~Logger() {
    shutdown();
}

void Logger::log(LogLevel level, std::string msg) {
    if (!logs_enabled_ || msg.empty()) {
        return;
    }
    else {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return;
            }

            if (!started_) {
                start_locked();
            }

            std::string line = format(level, msg.size() > MAX_LINE_BYTES
                ? msg.substr(0, MAX_LINE_BYTES) + " ...[" + std::to_string(msg.size() - MAX_LINE_BYTES) + " more bytes]"
                : msg);

            // The writer has fallen behind: drop and count, instead of holding every line in memory
            if (queued_bytes_ + line.size() > MAX_QUEUED_BYTES) {
                ++dropped_;
            }
            else {
                queued_bytes_ += line.size();
                queue_.push_back(std::move(line));
            }
        }

        // Copy to stdout for info and error
        switch (level) {
        case LogLevel::Info: {
            std::cout << "\033[34m" << msg.c_str() << "\033[0m" << std::endl;
            break;
        }
        case LogLevel::Error: {
            std::cerr << "\033[31m" << msg.c_str() << "\033[0m" << std::endl;
        }
        default: {
            break;
        }
        }

        cv_.notify_one();
    }
}

void Logger::debug(std::string msg) {
    log(LogLevel::Debug, std::move(msg));
}

void Logger::error(std::string msg) {
    log(LogLevel::Error, std::move(msg));
}

void Logger::info(std::string msg) {
    log(LogLevel::Info, std::move(msg));
}

void Logger::warn(std::string msg) {
    log(LogLevel::Warn, std::move(msg));
}

void Logger::shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) {
            return;
        }

        stopping_ = true;
    }

    cv_.notify_one();
    if (worker_.joinable()) {
        worker_.join();
    }
}

std::string Logger::format(LogLevel level, std::string msg) const {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto t = system_clock::to_time_t(now);
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    // localtime() shares one buffer between threads, and four loops log at once
    std::tm tm_buf{};
    localtime_r(&t, &tm_buf);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setw(3) << std::setfill('0') << ms.count()
        << " [" << to_string(level) << "] "
        << msg << std::endl;

    return oss.str();
}

void Logger::run() {
    if (!logs_enabled_) {
        return;
    }
    else {
        std::deque<std::string> local_batch;

        while (true) {
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] {
                    return stopping_ || !queue_.empty();
                    });

                if (queue_.empty() && stopping_) {
                    break;
                }

                std::swap(local_batch, queue_);
                queued_bytes_ = 0;

                if (dropped_ > 0) {
                    local_batch.push_back(format(LogLevel::Warn, "[logger] dropped " + std::to_string(dropped_) + " lines, the writer couldn't keep up"));
                    dropped_ = 0;
                }
            }

            for (auto& line : local_batch) {
                file_ << line;
            }

            file_.flush();
            local_batch.clear();
        }

        file_.flush();
    }
}
