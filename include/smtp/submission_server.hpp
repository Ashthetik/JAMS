#pragma once

#include "auth/sasl/sasl.hpp"
#include "auth/credentials/cred_store.hpp"
#include "auth/dkim/signer.hpp"
#include "io/session_factory.hpp"
#include "smtp/smtp_session.hpp"
#include "auth/credentials/aliases.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace Async { class IoUringLoop; };

// SMTP submission session for port 587 (RFC 6409).
//
// Differences from SMTP::Session (port 25):
//   1. AUTH is required before MAIL FROM
//   2. EHLO advertises AUTH PLAIN LOGIN (only after STARTTLS)
//   3. Outbound messages are DKIM-signed before queuing
//   4. No inbound SPF/DKIM/DMARC checking (we trust authenticated users)
//   5. VRFY and EXPN are disabled
//
// State machine:
//   Connected → Greeted → [TLS] → Authenticated → Mail → Rcpt → Data → Done
//
// TLS requirement:
//   AUTH is only advertised after STARTTLS. If a client attempts AUTH
//   before TLS is established, we respond with 538 (encryption required).
namespace SMTP
{
    class SubmissionServer : public ISession
    {
    public:
        SubmissionServer(
            uint64_t conn_id, const std::string& remote_ip,
            Async::IoUringLoop& loop, Auth::CredentialStore& store,
            Auth::Aliases& aliases);

        /// @brief Called by io_uring when bytes arrive
        /// @param bytes
        void on_data(std::span<const uint8_t> bytes);

        /// @brief Called by io_uring when the TLS handshake completes
        void on_tls_established();

        /// @brief Calls out to SASL to check if the connection is authenticated
        /// @return
        bool is_authenticated() const
        {
            return sasl_.authenticated();
        }

        bool wants_close() const
        {
            return pending_close_;
        }

        bool wants_tls_upgrade() const override
        {
            return tls_upgrade_pending_;
        }

        void clear_tls_upgrade() override
        {
            tls_upgrade_pending_ = false;
        }
    private:
        DKIM::Signer dkim_signer_;

        /// @brief Helper overload function to extract email addresses from a body
        /// used when handling BCC/CC
        /// @param body
        /// @param header_name
        /// @return
        auto extract_address(const std::string& body, const std::string& header_name);

        /// @brief Helper function to strip headers from the body of an email
        /// @param body
        /// @param header_name
        /// @return
        auto strip_header(const std::string& body, const std::string& header_name);

        /// @brief True if the authenticated user may send as this address:
        /// their own mailbox on this domain, or one of their active aliases
        /// @param address
        /// @return
        bool owns_address(const std::string& address);

        /// @brief True if every address in the message's From header is one the user owns
        /// @param message
        /// @return
        bool from_header_owned(const std::string& message);

        bool relay_outbound(
            const std::string& from, const std::string& to,
            const std::string& domain, const std::string& body);

        /// @brief Processes commands received from on-wire data
        /// @param line
        void process_line(std::string_view line);

        /// @brief Sends back HELO request to the sender
        /// @param arg
        void cmd_ehlo(std::string_view arg);

        /// @brief Sends HELO request to the receiver
        /// @param arg
        void cmd_helo(std::string_view arg);

        /// @brief Handles on-wire data relating to FROM sender
        /// @param arg
        void cmd_mail(std::string_view arg);

        /// @brief Handles on-wire data relating to Recipient(s)
        /// @param arg
        void cmd_rcpt(std::string_view arg);

        /// @brief Force Authentication over TLS then authenticate
        /// @param arg
        void cmd_auth(std::string_view arg);

        /// @brief Handles overall mail data structure
        void cmd_data();

        /// @brief Sends reset signal to the mail server (greeting)
        void cmd_rset();

        /// @brief If no commands are received reply back with "OK" status
        void cmd_noop();

        /// @brief Closes connection to the mail server on QUIT commands
        void cmd_quit();

        /// @brief Starts the upgrade process for non-secure connections
        void cmd_starttls();

        /// @brief Hands over Submission replies to io_uring
        /// @param text
        void reply(int code, std::string_view text);

        /// @brief Hands multiline Submission replies over to io_uring with specific codes
        /// @param code
        /// @param lines
        void reply_multiline(int code, const std::vector<std::string>& lines);

        /// @brief Delivers mail to the recipient
        /// @return
        bool deliver();

        /// @brief Trims unwanted data from the given string
        /// @param sv
        /// @return
        static std::string_view trim(std::string_view sv);

        /// @brief Extracts domain name from user@domain variants
        /// @param arg
        /// @return
        static std::string_view extract_address(std::string_view arg);

        uint64_t conn_id_;
        std::string remote_ip_;
        Async::IoUringLoop& loop_;
        Auth::SASLSession sasl_;
        Auth::Aliases& aliases_;

        /// @brief Submission States
        enum class State
        {
            Connected,
            Greeted,
            Authenticated,
            Mail,
            Rcpt,
            Data,
            Done
        };

        State state_{ State::Connected };
        bool tls_active_{ false };
        std::string line_buf_;
        std::string data_tail_;
        bool data_too_big_{ false }; // past MAX_MESSAGE_SIZE: stop storing, wait for the end, then 552

        bool pending_close_{ false };

        struct Envelope
        {
            std::string mail_from;
            std::vector<std::string> rcpt_to;
            std::string body;
        };

        Envelope env_;
        std::string client_helo_;

        bool tls_upgrade_pending_ = false;
    };
}