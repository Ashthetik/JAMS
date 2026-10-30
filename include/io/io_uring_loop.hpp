#pragma once

#include "session_factory.hpp"
#include "tls/tls_context.hpp"
#include "tls/tls_conn.hpp"
#include "dns/resolver.hpp"
#include "smtp/submission_server.hpp"
#include "smtp/smtp_session.hpp"

#include <liburing.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdint>
#include <chrono>
#include <functional>
#include <memory>
#include <unordered_map>
#include <span>
#include <vector>
#include <deque>

/// @brief Operation Types for io_uring
enum class op_type : uint8_t {
    Accept = 0,
    Read = 1,
    Write = 2,
    Close = 3,
    Timer = 4,
};

/// @brief Encodes data to ensure integrity and avoid dangling references
/// @param op 
/// @param conn_id 
/// @return 
inline uint64_t encode_userdata(op_type op, uint64_t conn_id) {
    return (static_cast<uint64_t>(op) << 60) | (conn_id & 0x0FFF'FFFF'FFFF'FFFF);
}

/// @brief Decode io_uring encoded data
/// @param userdata 
/// @return 
inline op_type decode_op(uint64_t userdata) {
    return static_cast<op_type>(userdata >> 60);
}

/// @brief Decode connection IDs from encoded data
/// @param userdata 
/// @return 
inline uint64_t decode_conn_id(uint64_t userdata) {
    return userdata & 0x0FFF'FFFF'FFFF'FFFF;
}

// // Forward Declarations
namespace SMTP { class Session; class SubmissionServer; struct ISession; };
namespace TLS { class Context; class Connection; };
namespace DNS { class Resolver; };
namespace Auth { class CredentialStore; class Aliases; };

/**
 * Design Notes:
 * - Queue Depth of 256 gives an equal amount of ops before drain
 * - Each connection is monotonically increasing
 * - The accept loop rearms itself after every accept
 */
namespace Async {
    class IoUringLoop {
    public:
        using SessionFactory = std::function<std::unique_ptr<SMTP::ISession>(uint64_t, const std::string&, IoUringLoop&)>;

        /// @brief Initialise io_uring with a queue depth of 256
        /// @param port
        /// @param implicit_tls Start TLS on accept (e.g. IMAPS on 993) instead of waiting for STARTTLS
        /// @param queue_depth
        explicit IoUringLoop(uint16_t port, SessionFactory factory, bool implicit_tls = false, unsigned queue_depth = 256);
        ~IoUringLoop();

        IoUringLoop(const IoUringLoop&) = delete;
        IoUringLoop& operator=(const IoUringLoop&) = delete;

        /// @brief 
        void run();

        /// @brief Submit writes to the io_uring queue
        /// @param conn_id 
        /// @param data 
        void submit_write(uint64_t conn_id, std::vector<uint8_t> data, bool raw = false);

        /// @brief Submit close requests to io_uring for clean shutdowns
        /// and prevent leaking data after close
        /// @param conn_id 
        void submit_close(uint64_t conn_id);

        /// @brief Upgrade a plaintext connection to TLS
        /// @param conn_id 
        void upgrade_tls(uint64_t conn_id);

        /// @brief Return a pointer to the DNS resolver
        /// @return 
        DNS::Resolver& dns_resolver() {
            return *dns_resolver_;
        }

        bool is_tls_active(uint64_t conn_id)  const {
            auto itr = tls_conns_.find(conn_id);
            return itr != tls_conns_.end() && itr->second->handshake_done();
        }

        /// @brief True if this connection is TLS or is in the middle of a TLS handshake
        /// @param conn_id
        /// @return
        bool has_tls(uint64_t conn_id) const {
            return tls_conns_.contains(conn_id);
        }

        /// @brief True if this listener starts TLS on accept rather than via STARTTLS
        /// @return
        bool is_implicit_tls() const {
            return implicit_tls_;
        }

        void arm_periodic_timer(std::chrono::seconds interval, std::function<void()> callback);

    private:
        /// @brief Closes connections that have been silent longer than their session's idle timeout
        void close_idle_connections();

        /// @brief Silence allowed before a connection is closed ([limits] idle_timeout, RFC 5321 4.5.3.2 floor)
        std::chrono::seconds idle_timeout_;

        /// @brief Open connections allowed on this listener, and from any one address
        size_t max_connections_;
        size_t max_connections_per_ip_;

        struct PeriodicTimer {
            __kernel_timespec ts;
            std::function<void()> callback;
        };

        std::unordered_map<uint64_t, PeriodicTimer> timers_;
        uint64_t timer_next_id_ = 1;

        void on_timer(uint64_t timer_id, int res);

        /// @brief Sets up the server listening socket 
        void setup_listen_socket();

        /// @brief Prepares the server to accept new requests
        void arm_accept();

        /// @brief Handling accept events 
        /// @param fd 
        /// @param res 
        void on_accept(int fd, int res);

        /// @brief Handling session read events
        /// @param conn_id 
        /// @param res 
        void on_read(uint64_t conn_id, int res);

        /// @brief Handling file-write events
        /// @param conn_id 
        /// @param res 
        void on_write(uint64_t conn_id, int res);

        /// @brief Get the applicable Session Que Entry (SQE)
        /// @return 
        io_uring_sqe* get_sqe();

        /// @brief Submit the process to io_uring
        void submit();

        void flush_write(uint64_t conn_id);

        uint16_t port_;
        int listen_fd_{ -1 };

        io_uring ring_{};
        bool ring_initialized_{ false };

        std::unique_ptr<TLS::Context> tls_ctx_;
        std::unique_ptr<DNS::Resolver> dns_resolver_;

        sockaddr_in client_addr_{};
        socklen_t client_addr_len_{ sizeof(client_addr_) };

        static constexpr size_t READ_BUF_SIZE = 8192;
        struct ConnBuffer {
            std::string ip;
            std::chrono::steady_clock::time_point last_active{ std::chrono::steady_clock::now() };
            std::vector<uint8_t> read_buf;
            std::deque<std::vector<uint8_t>> write_queue;
            size_t write_offset{ 0 }; // bytes of write_queue.front() the kernel has already taken
            bool write_pending{ false };
            bool closing{ false };
            int inflight{ 0 };
            int fd{ -1 };

            // Plaintext queued while a TLS handshake is still running; encrypted and sent once it completes
            std::vector<uint8_t> pending_plaintext;
        };

        /// @brief Creates the TLS state for a connection and routes decrypted bytes to its session
        /// @param conn_id
        void attach_tls(uint64_t conn_id);

        /// @brief Encrypts and sends anything queued while the handshake was in progress
        /// @param conn_id
        void flush_pending_plaintext(uint64_t conn_id);

        bool implicit_tls_{ false };

        SessionFactory session_factory_;

        uint64_t next_conn_id{ 1 };
        std::unordered_map<uint64_t, ConnBuffer> buffers_;
        std::unordered_map<uint64_t, std::unique_ptr<SMTP::ISession>> sessions_;
        std::unordered_map<uint64_t, std::unique_ptr<TLS::Connection>> tls_conns_;
    };
};
