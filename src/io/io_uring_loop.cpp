#include "io/io_uring_loop.hpp"
#include "smtp/smtp_session.hpp"
#include "dns/resolver.hpp"
#include "globals.hpp"
#include <liburing.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <cassert>
#include <sys/eventfd.h>

Async::IoUringLoop::IoUringLoop(
    uint16_t port, SessionFactory factory, bool implicit_tls, unsigned queue_depth
) : port_(port), implicit_tls_(implicit_tls), session_factory_(std::move(factory)) {
    io_uring_params params{};
    params.flags = 0;

    int ret = io_uring_queue_init_params(queue_depth, &ring_, &params);

    if (ret < 0) {
        throw std::runtime_error(
            std::string("io_uring_queue_init failed: ") + strerror(-ret)
        );
    }

    ring_initialized_ = true;

    logger.info(
        "[io_uring] features: "
        + std::string(((params.features & IORING_FEAT_FAST_POLL) ? "FAST_POLL " : ""))
        + std::string(((params.features & IORING_FEAT_NODROP) ? "NODROP " : ""))
    );

    // Initialise TLS:
    const std::string cert = "/etc/jams/tls/cert.pem";
    const std::string key = "/etc/jams/tls/key.pem";

    try {
        tls_ctx_ = std::make_unique<TLS::Context>(cert, key);
        logger.info("[TLS] Context loaded from: " + cert);
    }
    catch (const std::exception& ex) {
        logger.error("[TLS] Failed to load key/cert: " + std::string(ex.what()));
        std::abort();
    }

    // Initialise DNS Resolver
    try {
        dns_resolver_ = std::make_unique<DNS::Resolver>("1.1.1.1", &ring_);
    }
    catch (const std::exception& ex) {
        logger.error("[DNS] WARNING: Resolver failed to initialise: " + std::string(ex.what()));
    }

    idle_timeout_ = std::chrono::seconds(get_limit("idle_timeout", 300));
    max_connections_ = get_limit("max_connections", 200);
    max_connections_per_ip_ = get_limit("max_connections_per_ip", 20);

    post_queue_->event_fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (post_queue_->event_fd < 0) {
        throw std::runtime_error(std::string("eventfd(): ") + strerror(errno));
    }

    setup_listen_socket();
}

static_assert(sizeof(SMTP::Session) > 0);

Async::IoUringLoop::~IoUringLoop() {
    {
        // Workers may still hold a Poster; from here on their tasks are dropped
        std::lock_guard<std::mutex> lock(post_queue_->mutex);
        post_queue_->open = false;
        post_queue_->tasks.clear();

        if (post_queue_->event_fd >= 0) {
            ::close(post_queue_->event_fd);
            post_queue_->event_fd = -1;
        }
    }

    if (ring_initialized_) {
        io_uring_queue_exit(&ring_);
        if (listen_fd_ >= 0) {
            ::close(listen_fd_);
        }
    }
}

void Async::IoUringLoop::arm_periodic_timer(std::chrono::seconds interval, std::function<void()> callback) {
    uint64_t timer_id = timer_next_id_++;

    __kernel_timespec ts{};
    ts.tv_nsec = 0;
    ts.tv_sec = interval.count();

    auto [itr, _] = timers_.try_emplace(timer_id, PeriodicTimer{ ts, std::move(callback) });

    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_timeout(sqe, &itr->second.ts, 0, 0);
    sqe->user_data = encode_userdata(op_type::Timer, timer_id);
    submit();
}

void Async::IoUringLoop::on_timer(uint64_t timer_id, int res) {
    auto itr = timers_.find(timer_id);
    if (itr == timers_.end()) {
        return;
    }

    // -ETIME is the expected result
    if (res != -ETIME) {
        if (res < 0 && res != -ECANCELED) {
            logger.error("[TIMER] [IO_URING] id=" + std::to_string(timer_id) + " error: " + std::string(strerror(-res)));
        }

        return;
    }

    itr->second.callback();

    if (g_shutdown) {
        return; // don't rearm
    }

    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_timeout(sqe, &itr->second.ts, 0, 0);
    sqe->user_data = encode_userdata(op_type::Timer, timer_id);

    submit();
}

void Async::IoUringLoop::setup_listen_socket()
{
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listen_fd_ < 0) {
        logger.error("[FATA] [IO_URING] socket(): " + std::string(strerror(errno)));
        throw std::runtime_error(
            std::string("socket(): ") + strerror(errno)
        );
    }

    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        logger.error("[FATA] [IO_URING] bind(): " + std::string(strerror(errno)));
        throw std::runtime_error(
            std::string("bind(): ") + strerror(errno)
        );
    }

    if (::listen(listen_fd_, SOMAXCONN) < 0) {
        logger.error("[FATA] [IO_URING] listen(): " + std::string(strerror(errno)));
        throw std::runtime_error(
            std::string("listen(): ") + strerror(errno)
        );
    }

    if (port_ == 25) {
        logger.info("[SMTP] Listening on port: " + std::to_string(port_));
    }
    else if (port_ == 587) {
        logger.info("[SUBMISSION] Listening on port: " + std::to_string(port_));
    }
    else if (port_ == 143) {
        logger.info("[IMAP4] Listening on port: " + std::to_string(port_));
    }
    else if (port_ == 993) {
        logger.info("[IMAP4S] Listening on port: " + std::to_string(port_));
    }
    else {
        logger.info("[CUSTOMPORT] Listening on port: " + std::to_string(port_));
    }
}

void Async::IoUringLoop::arm_accept() {
    client_addr_len_ = sizeof(client_addr_);
    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_accept(
        sqe, listen_fd_,
        reinterpret_cast<sockaddr*>(&client_addr_),
        &client_addr_len_, SOCK_CLOEXEC
    );

    sqe->user_data = encode_userdata(op_type::Accept, 0);
    submit();
}

void Async::IoUringLoop::run() {
    arm_accept();
    arm_wakeup();

    // Without this, a client that connects and says nothing holds its slot forever
    arm_periodic_timer(std::chrono::seconds(1), [this]() {
        close_idle_connections();
        });

    io_uring_cqe* cqe = nullptr;

    while (!g_shutdown)
    {
        __kernel_timespec ts{ .tv_sec = 0, .tv_nsec = 500'000'000 };
        int ret = io_uring_wait_cqe_timeout(&ring_, &cqe, &ts);

        if (ret == -ETIME) {
            // Timeout, we loop back and check the shutdown
            continue;
        }

        if (ret == -EINTR) {
            // We got interrupted, loop back
            continue;
        }

        if (ret < 0) {
            logger.error("[IO_URING] wait_cqe errpr: " + std::string(strerror(-ret)));
            continue; // skip the CQE if it's in a stale state
        }

        unsigned head = 0, nr = 0;
        io_uring_for_each_cqe(&ring_, head, cqe) {
            nr++; // increment next ring

            // Route DNS completions before trying to decode as SMTP ops
            uint64_t ud = cqe->user_data;
            int res = cqe->res;

            if (DNS::dns_is_completion(ud)) {
                if (dns_resolver_) {
                    dns_resolver_->on_cqe(ud, res);
                }
                continue;
            }


            op_type op = decode_op(ud);
            uint64_t conn_id = decode_conn_id(ud);

            switch (op) {
            case op_type::Accept:
                on_accept(0, res);
                break;
            case op_type::Read:
                on_read(conn_id, res);
                break;
            case op_type::Write:
                on_write(conn_id, res);
                break;
            case op_type::Close:
                submit_close(conn_id);
                break;
            case op_type::Timer:
                on_timer(conn_id, res);
                break;
            case op_type::Wakeup:
                on_wakeup(res);
                break;
            }
        }

        io_uring_cq_advance(&ring_, nr);
    }

    logger.info("[IO_URING] Loop exiting on port: " + std::to_string(port_));
}

void Async::IoUringLoop::on_accept(int /*fd*/, int res) {
    // Always re-arm accept first so we don't miss new connections
    arm_accept();

    if (res <= 0) {
        if (res < 0) {
            logger.error("[ACCEPT] Error: " + std::string(strerror(-res)));
        }
        return;
    }

    int client_fd = res;

    // TODO: Log the new connection: Preferably with DB writes
    char ip_buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &client_addr_.sin_addr, ip_buf, sizeof(ip_buf));

    // One address can't take every slot, so the cap only shuts out whoever is hogging it
    size_t from_ip = 0;
    for (const auto& [id, conn] : buffers_) {
        if (conn.ip == ip_buf) {
            ++from_ip;
        }
    }

    if (buffers_.size() >= max_connections_ || from_ip >= max_connections_per_ip_) {
        logger.warn(
            "[ACCEPT] Refusing " + std::string(ip_buf) + ": " + std::to_string(from_ip) + " open from this address, "
            + std::to_string(buffers_.size()) + " in total"
        );
        ::close(client_fd);
        return;
    }

    uint64_t cid = next_conn_id++;

    auto& buf = buffers_[cid];
    buf.ip = ip_buf;
    buf.fd = client_fd;
    buf.read_buf.resize(READ_BUF_SIZE);

    // Implicit TLS: the handshake starts before the session exists, so its
    // greeting is held until the handshake completes and goes out encrypted
    if (implicit_tls_) {
        if (!tls_ctx_) {
            logger.error("[TLS] conn=" + std::to_string(cid) + " implicit TLS listener has no TLS context");
            submit_close(cid);
            return;
        }

        attach_tls(cid);
    }

    // queue the 220 Banner (making the session available)
    try {
        sessions_[cid] = session_factory_(cid, ip_buf, *this);
    }
    catch (const std::exception& ex) {
        logger.error("[ACCEPT] conn=" + std::to_string(cid) + " session setup failed:\n\t" + std::string(ex.what()));
        submit_close(cid);
        return;
    }

    // Arming connection reads
    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_recv(sqe, client_fd, buf.read_buf.data(), buf.read_buf.size(), 0);
    sqe->user_data = encode_userdata(op_type::Read, cid);

    logger.info("[ACCEPT] conn=" + std::to_string(cid) + "\n\tfd=" + std::to_string(client_fd) + " from=" + ip_buf);

    buf.inflight++;
    submit();
}

void Async::IoUringLoop::on_read(uint64_t conn_id, int res) {
    auto bit = buffers_.find(conn_id);
    auto sit = sessions_.find(conn_id);

    if (bit == buffers_.end() || sit == sessions_.end()) {
        return;
    }

    bit->second.inflight--;

    if (res <= 0) {
        if (res == -ECANCELED || res == -ENOENT) {
            return;
        }
        // EOF - tear down
        if (res < 0) {
            logger.error("[READ] conn=" + std::to_string(conn_id) + " error:\n\t" + std::string(strerror(-res)));
        }
        submit_close(conn_id);
        return;
    }

    bit->second.last_active = std::chrono::steady_clock::now();

    std::span<uint8_t> data(bit->second.read_buf.data(), static_cast<size_t>(res));

    auto tit = tls_conns_.find(conn_id);

    if (tit != tls_conns_.end()) {
        try
        {
            const bool was_handshake_done = tit->second->handshake_done();

            auto to_send = tit->second->feed_encryption(data);
            if (!to_send.empty()) {
                submit_write(conn_id, std::move(to_send), true);
            }

            if (!was_handshake_done && tit->second->handshake_done()) {
                /**
                 * Order matters here: the handshake's final flight (queued above),
                 * then anything the session wrote during the handshake (e.g. the
                 * IMAPS greeting), and only then the client's first command.
                 * Clients often send that command in the same packet as their
                 * Finished message, and OpenSSL is still holding it, so it has to
                 * be read now or it sits there until the client sends more.
                 */
                flush_pending_plaintext(conn_id);

                auto again = tls_conns_.find(conn_id);
                if (again != tls_conns_.end()) {
                    auto more = again->second->feed_encryption({});
                    if (!more.empty()) {
                        submit_write(conn_id, std::move(more), true);
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            logger.error("[TLS] conn=" + std::to_string(conn_id) + " feed error:\n\t" + std::string(e.what()));
            submit_close(conn_id);
            return;
        }

    }
    else {
        /**
         * A session must never be able to take the whole listener down. An
         * exception escaping here would unwind out of run() and stop every
         * service, so contain it to this one connection, the same way the
         * TLS path above already does.
         */
        try {
            sit->second->on_data(data);
        }
        catch (const std::exception& ex) {
            logger.error("[SESSION] conn=" + std::to_string(conn_id) + " error, closing connection:\n\t" + std::string(ex.what()));
            submit_close(conn_id);
            return;
        }
    }

    /// relookup in case of old data
    bit = buffers_.find(conn_id);
    auto sit2 = sessions_.find(conn_id);

    if (bit == buffers_.end()) {
        return;
    }

    // Check if session requested close
    if (sit2 != sessions_.end() && sit2->second->wants_close()) {
        submit_close(conn_id);
        return;
    }

    if (!bit->second.closing) {
        // Re-arm read
        io_uring_sqe* sqe = get_sqe();
        io_uring_prep_recv(sqe, bit->second.fd, bit->second.read_buf.data(), bit->second.read_buf.size(), 0);
        sqe->user_data = encode_userdata(op_type::Read, conn_id);
        bit->second.inflight++;
        submit();
    }
    else {
        submit_close(conn_id);
    }
}

void Async::IoUringLoop::on_write(uint64_t conn_id, int res) {
    logger.debug("[ON_WRITE] conn=" + std::to_string(conn_id) + " res=" + std::to_string(res));
    auto bit = buffers_.find(conn_id);
    if (bit == buffers_.end()) {
        return;
    }

    bit->second.inflight--;

    if (res < 0) {
        logger.error("[WRITE] conn=" + std::to_string(conn_id) + " error:\n\t" + std::string(strerror(-res)));
        submit_close(conn_id);
        return;
    }

    if (!bit->second.write_queue.empty()) {
        bit->second.write_queue.pop_front();
    }

    bit->second.write_pending = false;

    auto sit = sessions_.find(conn_id);
    if (sit != sessions_.end() && sit->second->wants_tls_upgrade()) {
        sit->second->clear_tls_upgrade();
        upgrade_tls(conn_id);

        // re-arm read to receive hello again
        if (bit != buffers_.end() && !bit->second.closing) {
            io_uring_sqe* sqe = get_sqe();
            io_uring_prep_recv(sqe, bit->second.fd, bit->second.read_buf.data(), bit->second.read_buf.size(), 0);
            sqe->user_data = encode_userdata(op_type::Read, conn_id);
            bit->second.inflight++;
            submit();
        }

        return;
    }

    // Send the next queued write
    if (!bit->second.write_queue.empty() && !bit->second.closing) {
        flush_write(conn_id);
    }
    else if (bit->second.closing) {
        logger.debug(
            "[ON_WRITE] Deffered Close: conn=" + std::to_string(conn_id)
            + " inflight=" + std::to_string(bit->second.inflight)
        );

        submit_close(conn_id);
    }
}

void Async::IoUringLoop::close_idle_connections() {
    auto now = std::chrono::steady_clock::now();
    std::vector<uint64_t> idle;

    for (const auto& [conn_id, conn] : buffers_) {
        // A big response still going out to a slow reader isn't idleness
        if (conn.closing || conn.write_pending) {
            continue;
        }

        auto sit = sessions_.find(conn_id);
        auto limit = (sit != sessions_.end()) ? sit->second->idle_timeout(idle_timeout_) : idle_timeout_;

        if (now - conn.last_active >= limit) {
            idle.push_back(conn_id);
        }
    }

    for (uint64_t conn_id : idle) {
        auto bit = buffers_.find(conn_id);
        if (bit == buffers_.end()) {
            continue;
        }

        logger.info("[IDLE] conn=" + std::to_string(conn_id) + " from=" + bit->second.ip + " timed out, closing");

        // The pending recv would never complete on a silent socket. Shutting it down
        // completes the recv with 0, and on_read then finishes the close
        ::shutdown(bit->second.fd, SHUT_RDWR);
        submit_close(conn_id);
    }
}

void Async::IoUringLoop::flush_write(uint64_t conn_id) {
    logger.debug(
        "[FLUSH_WRITE] conn=" + std::to_string(conn_id) +
        " queue_size=" + std::to_string(buffers_[conn_id].write_queue.size())
    );

    auto bit = buffers_.find(conn_id);
    if (bit == buffers_.end() || bit->second.write_queue.empty()) {
        return;
    }

    bit->second.write_pending = true;

    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_send(
        sqe, bit->second.fd, bit->second.write_queue.front().data(),
        bit->second.write_queue.front().size(), 0
    );

    sqe->user_data = encode_userdata(op_type::Write, conn_id);
    bit->second.inflight++;
    submit();
}

void Async::IoUringLoop::submit_write(uint64_t conn_id, std::vector<uint8_t> data, bool raw) {
    auto bit = buffers_.find(conn_id);

    if (bit == buffers_.end()) {
        logger.warn("[SUBMIT_WRITE] Buffer is empty!");
        return;
    }

    // Only encrypt if the text is plain
    if (!raw) {
        auto tit = tls_conns_.find(conn_id);

        /**
         * Mid-handshake there is no session key yet. Sending this as-is would
         * put plaintext on a connection the client expects to be encrypted,
         * so hold it until the handshake completes.
         */
        if (tit != tls_conns_.end() && !tit->second->handshake_done()) {
            auto& pending = bit->second.pending_plaintext;
            pending.insert(pending.end(), data.begin(), data.end());
            return;
        }

        if (tit != tls_conns_.end() && tit->second->handshake_done()) {
            try {
                data = tit->second->encrypt(data);
            }
            catch (const std::exception& ex) {
                logger.error("[TLS] conn=" + std::to_string(conn_id) + " encrypt error:\n\t" + std::string(ex.what()));

                submit_close(conn_id);
                return;
            }
        }

    }

    // To keep the buffer alive until a completion fires,
    // We store it on the ConnBuffer ans pass a raw pointer to io_uring
    bit->second.write_queue.push_back(std::move(data));

    // Only arm on a new send, if there's no inflight
    if (!bit->second.write_pending) {
        flush_write(conn_id);
    }
}

void Async::IoUringLoop::submit_close(uint64_t conn_id) {
    auto bit = buffers_.find(conn_id);
    if (bit == buffers_.end()) {
        return;
    }

    if (!bit->second.closing) {
        logger.debug(
            "[submit_close] conn=" + std::to_string(conn_id)
            + " inflight=" + std::to_string(bit->second.inflight)
            + " write_queue=" + std::to_string(bit->second.write_queue.size())
            + " write_pending=" + std::to_string(bit->second.write_pending)
        );

        bit->second.closing = true;
    }

    if (bit->second.inflight > 0) {
        return; // wait for the queue to drain
    }

    ::close(bit->second.fd);
    buffers_.erase(bit);
    sessions_.erase(conn_id);
    tls_conns_.erase(conn_id);

    logger.debug("[CLOSE] conn=" + std::to_string(conn_id) + " closed");
}

void Async::IoUringLoop::upgrade_tls(uint64_t conn_id) {
    if (!tls_ctx_) {
        logger.error("[TLS] upgrade_tls() called but no TLS context available");

        submit_close(conn_id);
        return;
    }

    auto sit = sessions_.find(conn_id);
    if (sit == sessions_.end()) {
        return;
    }

    logger.info("[TLS] conn=" + std::to_string(conn_id) + " upgrading to TLS");

    attach_tls(conn_id);
}

void Async::IoUringLoop::attach_tls(uint64_t conn_id) {
    auto tls = std::make_unique<TLS::Connection>(
        tls_ctx_->new_server_ssl(),
        [this, conn_id](std::span<const uint8_t> plain) {
            auto itr = sessions_.find(conn_id);
            if (itr != sessions_.end()) {
                itr->second->on_data(plain);
            }
        }
    );

    tls_conns_[conn_id] = std::move(tls);
}

void Async::IoUringLoop::flush_pending_plaintext(uint64_t conn_id) {
    auto bit = buffers_.find(conn_id);
    if (bit == buffers_.end() || bit->second.pending_plaintext.empty()) {
        return;
    }

    std::vector<uint8_t> pending = std::move(bit->second.pending_plaintext);
    bit->second.pending_plaintext.clear();

    submit_write(conn_id, std::move(pending));
}

Async::IoUringLoop::Poster Async::IoUringLoop::poster() const {
    return [queue = post_queue_](std::function<void()> task) {
        std::lock_guard<std::mutex> lock(queue->mutex);
        if (!queue->open) {
            return;
        }

        queue->tasks.push_back(std::move(task));

        uint64_t one = 1;
        if (::write(queue->event_fd, &one, sizeof(one)) < 0 && errno != EAGAIN) {
            logger.error("[IO_URING] wakeup write failed: " + std::string(strerror(errno)));
        }
        };
}

void Async::IoUringLoop::arm_wakeup() {
    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_read(sqe, post_queue_->event_fd, &wakeup_buf_, sizeof(wakeup_buf_), 0);
    sqe->user_data = encode_userdata(op_type::Wakeup, 0);
    submit();
}

void Async::IoUringLoop::on_wakeup(int res) {
    if (res < 0 && res != -EAGAIN && res != -EINTR) {
        logger.error("[IO_URING] wakeup read failed: " + std::string(strerror(-res)));
    }

    std::vector<std::function<void()>> tasks;
    {
        std::lock_guard<std::mutex> lock(post_queue_->mutex);
        tasks.swap(post_queue_->tasks);
    }

    // Run outside the lock: a task may well post again
    for (auto& task : tasks) {
        try {
            task();
        }
        catch (const std::exception& ex) {
            logger.error("[IO_URING] posted task threw: " + std::string(ex.what()));
        }
    }

    if (!g_shutdown) {
        arm_wakeup();
    }
}

io_uring_sqe* Async::IoUringLoop::get_sqe() {
    io_uring_sqe* sqe = io_uring_get_sqe(&ring_);

    if (!sqe) {
        // SQ is full, we submit and try again
        io_uring_submit(&ring_);
        sqe = io_uring_get_sqe(&ring_);

        if (!sqe) {
            logger.error("[FATAL] [IO_URING] io_uring SQ overflow - increase depth of the queue");
            throw std::runtime_error("io_uring SQ Overflow - increase depth of the queue");
        }
    }

    return sqe;
}

void Async::IoUringLoop::submit() {
    io_uring_submit(&ring_);
}
