#pragma once

#include "io/session_factory.hpp"
#include "io/io_uring_loop.hpp"
#include "auth/credentials/aliases.hpp"

#include <cctype>
#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <span>

namespace Async { class IoUringLoop; };

namespace SMTP {
    /// @brief Largest message accepted on 25 and 587, advertised as SIZE in EHLO (RFC 1870)
    inline constexpr size_t MAX_MESSAGE_SIZE = 52428800;

    /// @brief True if MAIL FROM declares a SIZE= over MAX_MESSAGE_SIZE (RFC 1870 6.1)
    /// @param upper_args The MAIL arguments, uppercased
    inline bool declared_size_too_big(std::string_view upper_args) {
        auto pos = upper_args.find(" SIZE=");
        if (pos == std::string_view::npos) {
            return false;
        }

        pos += 6;
        size_t end = pos;
        while (end < upper_args.size() && std::isdigit(static_cast<unsigned char>(upper_args[end]))) {
            ++end;
        }

        uint64_t declared = 0;
        auto [ptr, ec] = std::from_chars(upper_args.data() + pos, upper_args.data() + end, declared);

        return ec == std::errc::result_out_of_range || (ec == std::errc{} && declared > MAX_MESSAGE_SIZE);
    }

    enum class SMTPState {
        Connected,
        Greeted,
        Mail,
        RCPT,
        Data,
        Done,
    };

    struct Envelope {
        std::string mail_from;
        std::vector<std::string> rcpt_to;
        std::string body;
    };

    class Session : public ISession
    {
    public:
        /// @brief Creates the SMTP Session
        /// @param conn_id 
        /// @param remote_ip 
        /// @param loop
        /// @param cred_store Used to accept mail only for accounts that exist
        Session(
            uint64_t conn_id,
            std::string remote_ip,
            Async::IoUringLoop& loop, Auth::CredentialStore& cred_store,
            Auth::Aliases& aliases
        );

        /// @brief Handles events that receive on-wire data
        /// @param bytes 
        void on_data(std::span<const uint8_t> bytes);

        bool pending_close_{ false };
        bool wants_close() const {
            return pending_close_;
        }

    private:
        /// @brief Helper function to strip headers from the body of an email
        /// @param body 
        /// @param header_name 
        /// @return
        auto strip_header(const std::string& body, const std::string& header_name);

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

        /// @brief Collects data from the command - Not Yet Implemented
        /// @param line 
        void accumulate_data(std::string_view line);

        /// @brief Hands over SMTP replies to io_uring
        /// @param text 
        void reply(std::string_view text);

        /// @brief Hands over SMTP replies to io_uring with specific codes
        /// @param code 
        /// @param msg 
        void reply_code(int code, std::string_view msg);

        /// @brief Hands multiline SMTP replies over to io_uring with specific codes
        /// @param code 
        /// @param lines 
        void reply_multiline(int code, const std::vector<std::string>& lines);

        /// @brief Delivers mail to the MailDir instance
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
        Auth::CredentialStore& cred_store_;
        Auth::Aliases& aliases_;

        SMTPState state_{ SMTPState::Connected };
        std::string line_buf;
        Envelope env_;
        std::string client_helo_;

        std::string data_tail_;
        bool data_too_big_{ false }; // past MAX_MESSAGE_SIZE: stop storing, wait for the end, then 552
        bool tls_upgrade_pending_ = false;
    };

};
