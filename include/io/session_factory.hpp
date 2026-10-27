#pragma once

#include <span>
#include <chrono>
#include <cstdint>

namespace SMTP {
    struct ISession {
        virtual void on_data(std::span<const uint8_t>) = 0;
        virtual bool wants_close() const = 0;
        virtual ~ISession() = default;
        virtual bool wants_tls_upgrade() const { return false; }
        virtual void clear_tls_upgrade() {}

        /// @brief How long the client may stay silent before the connection is closed.
        /// fallback is the listener's [limits] idle_timeout
        virtual std::chrono::seconds idle_timeout(std::chrono::seconds fallback) const { return fallback; }
    };
};