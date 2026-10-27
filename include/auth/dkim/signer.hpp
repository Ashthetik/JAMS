#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>

namespace DKIM {
    class Signer {
        public:

            enum class Canonicalization {
                Simple,
                Relaxed
            };

            struct Config {
                std::string domain{}; // d=
                std::string selector{}; // s=
                std::string priv_key_path{}; // PEM priv key

                Canonicalization header_canon = Canonicalization::Relaxed;
                Canonicalization body_canon = Canonicalization::Relaxed;

                std::vector<std::string> signed_headers = {
                    "from", "to", "subject", "date", "message-id",
                    "mime-version", "content-type"
                };

                uint64_t signature_expiry = 86400;
            };

            explicit Signer(const Config& config);
            ~Signer();

            Signer(const Signer&) = delete;
            Signer& operator=(const Signer&) = delete;

            /**
             * @brief Signs a header block and body
             * Returns the header block with a CRLF-terminated DKIM-Signature header appended
             * Throws std::runtime_error on failures
             * @param headers header block, ending with its final line break
             * @param body message body (after the blank line)
             * @return std::string
             */
            std::string sign(
                const std::string& headers,
                const std::string& body
            );

            /**
             * @brief Signs a complete RFC 5322 message
             * Returns the message with a DKIM-Signature header added and the
             * header/body separator intact, ready to send.
             * Throws std::runtime_error on failures, including a missing separator
             * @param message
             * @return std::string
             */
            std::string sign_message(const std::string& message);

        private:
            Config config_;
            EVP_PKEY* private_key_ = nullptr;

            void load_private_key();
            void free_private_key();

            static void split_message(
                const std::string& message,
                std::string& headers,
                std::string& body
            );

            static std::unordered_map<std::string, std::vector<std::string>> parse_headers(
                const std::string& headers
            );

            static std::string canonicalize_header(
                const std::string& name, const std::string& value,
                const std::string& method
            );

            static std::string canonicalize_body(
                const std::string& body,
                const std::string& method
            );

            static std::vector<uint8_t> sha256(const std::string& data);

            static std::string base64_encode(const std::vector<uint8_t>& data);
            
            std::string rsa_sha256_sign(const std::string& data) const;

            std::string build_signature_header(
                const std::string& body_hash, const std::string& header_list,
                uint64_t timestamp, uint64_t expiry
            ) const;

            std::string build_signing_data(
                const std::string& headers,
                const std::string& dkim_headers
            ) const;

            std::string build_header_list() const;

            static std::string trim(const std::string& s);
            
            static std::string lowercase(const std::string& s);
    };

};
