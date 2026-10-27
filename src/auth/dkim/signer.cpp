#include "auth/dkim/signer.hpp"

#include <algorithm>
#include <chrono>
#include <sstream>

using namespace DKIM;

Signer::Signer(const Config& config) : config_(config) {
    load_private_key();
}

Signer::~Signer() {
    free_private_key();
}

void Signer::load_private_key() {
    BIO* bio = BIO_new_file(config_.priv_key_path.c_str(), "r");
    if (!bio) {
        throw std::runtime_error("[dkim_signer] [ERROR]: Failed to open DKIM private key: " + config_.priv_key_path);
    }

    private_key_ = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!private_key_) {
        throw std::runtime_error("[dkim_signer] [ERROR]: Failed to load DKIM private key");
    }
}

void Signer::free_private_key() {
    if (private_key_ != nullptr) {
        EVP_PKEY_free(private_key_);
        private_key_ = nullptr;
    }
}

std::string Signer::base64_encode(const std::vector<uint8_t>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);

    BUF_MEM* buff{};
    BIO_get_mem_ptr(mem, &buff);
    std::string result(buff->data, buff->length);
    BIO_free_all(b64);

    return result;
}

std::vector<uint8_t> Signer::sha256(const std::string& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash.data());

    return hash;
}

std::string Signer::canonicalize_body(const std::string& body, const std::string& method) {
    if (method == "relaxed") {
        // Relaxed body reduces WSP, removes trailing WSP, ignores empty lines
        // and ensures the body ends with CRLF

        std::string result;
        std::istringstream ss(body);
        std::string line;
        std::string pending; // Buffer trailing emptiness

        while (std::getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            // Reduce the wsp to a single SP
            std::string canonical;
            bool in_ws = false;
            for (char c : line) {
                if (c == ' ' || c == '\t') {
                    in_ws = true; // this shall remain true, for single SP
                }
                else {
                    if (in_ws) {
                        canonical += ' ';
                        in_ws = false;
                    }

                    canonical += c;
                }
            }

            // Remove trailing SP
            if (canonical.empty()) {
                pending += "\r\n";
            }
            else {
                result += pending;
                pending.clear();
                result += canonical + "\r\n";
            }
        }

        // RFC 6376 3.4.4: with relaxed, an empty body stays empty (simple is the one that becomes CRLF)
        if (result.empty()) {
            return "";
        }

        return result;
    }
    else {
        // simple - reduce and ignore

        std::string normalised;
        for (size_t i = 0; i < body.size(); i++) {
            if (body[i] == '\n') {
                if (normalised.empty() || normalised.back() != '\r') {
                    normalised += '\r';
                }

                normalised += '\n';
            }
            else {
                normalised += body[i];
            }
        }

        while (
            normalised.size() >= 2 &&
            normalised.substr(normalised.size() - 2) == "\r\n"
            ) {
            normalised.resize(normalised.size() - 2);
        }

        normalised += "\r\n";

        if (normalised == "\r\n") {
            return "\r\n";
        }

        return normalised;
    }
}

std::string Signer::canonicalize_header(
    const std::string& name, const std::string& value,
    const std::string& method)
{
    if (method == "relaxed")
    {
        // lowercase, unfold, reduce, and remove trailing WSP

        std::string canon_name = name;
        std::transform(canon_name.begin(), canon_name.end(), canon_name.begin(), ::tolower);

        // unfold and compress WSP
        std::string canon_value;
        bool in_ws{ false };
        bool skip_ws{ false };

        for (size_t i = 0; i < value.size(); ++i) {
            char c = value[i];

            if (c == '\r' && i + 1 < value.size() && value[i + 1] == '\n') {
                ++i;
                skip_ws = true;
                in_ws = true;
                continue;
            }

            if (skip_ws && (c == ' ' || c == '\t')) {
                in_ws = true;
                skip_ws = false;
                continue;
            }

            skip_ws = false;

            if (c == ' ' || c == '\t') {
                in_ws = true;
            }
            else {
                if (in_ws && !canon_value.empty()) {
                    canon_value += ' ';
                }

                in_ws = false;
                canon_value += c;
            }
        }

        // Trim tailing SP
        while (!canon_value.empty() && canon_value.back() == ' ') {
            canon_value.pop_back();
        }

        // trim leading SP
        const size_t start = canon_value.find_first_not_of(' ');
        if (start != std::string::npos) {
            canon_value = canon_value.substr(start);
        }

        return canon_name + ":" + canon_value + "\r\n";
    }
    else {
        // Simple - header is used as is
        std::string result = name + ":" + value;

        if (result.size() < 2 || result.substr(result.size() - 2) != "\r\n") {
            result += "\r\n";
        }

        return result;
    }
}

std::string Signer::sign(const std::string& headers, const std::string& body) {
    std::string canon_method = (config_.body_canon == Canonicalization::Relaxed) ? "relaxed" : "simple";
    std::string canon_body = canonicalize_body(body, canon_method);
    std::vector<uint8_t> bh = sha256(canon_body);
    std::string body_hash = base64_encode(bh);

    std::string header_list = build_header_list();

    uint64_t timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
        );

    std::string dkim_header = build_signature_header(body_hash, header_list, timestamp, config_.signature_expiry);
    std::string signing_data = build_signing_data(headers, dkim_header);
    std::string signature = rsa_sha256_sign(signing_data);

    /**
     * The header must end with CRLF so the caller's blank line separates the
     * headers from the body. The base64 signature is folded so the header
     * stays under the SMTP line limit (RFC 5322 2.1.1); folding whitespace
     * inside b= is ignored by verifiers (RFC 6376 3.5).
     */
    std::string folded_signature;
    for (size_t i = 0; i < signature.size(); i += 64) {
        if (i > 0) {
            folded_signature += "\r\n\t";
        }

        folded_signature += signature.substr(i, 64);
    }

    return headers + dkim_header + folded_signature + "\r\n";
}

std::string Signer::sign_message(const std::string& message) {
    // Split at the first blank line, accepting CRLF or bare LF line endings
    const size_t crlf = message.find("\r\n\r\n");
    const size_t lf = message.find("\n\n");

    std::string headers, body;
    if (crlf != std::string::npos && (lf == std::string::npos || crlf < lf)) {
        headers = message.substr(0, crlf + 2);
        body = message.substr(crlf + 4);
    }
    else if (lf != std::string::npos) {
        headers = message.substr(0, lf + 1);
        body = message.substr(lf + 2);
    }
    else {
        throw std::runtime_error("[dkim_signer] [ERROR]: No header/body separator found in message");
    }

    return sign(headers, body) + "\r\n" + body;
}

std::string Signer::rsa_sha256_sign(const std::string& data) const {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("[dkim_signer] [ERROR]: EVP_MD_CTX_new failed to initialise");
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, private_key_) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("[dkim_signer] [ERROR]: EVP_DigestSignInit failed to initialise");
    }

    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("[dkim_signer] [ERROR]: EVP_DigestSignUpdate failed to update signing data");
    }

    size_t len = 0;

    if (EVP_DigestSignFinal(ctx, nullptr, &len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("[dkim_signer] [ERROR]: EVP_DigestSignFinal(size) test failed to set signing size");
    }

    std::vector<uint8_t> sig(len);
    if (EVP_DigestSignFinal(ctx, sig.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("[dkim_signer] [ERROR]: EVP_DigestSignFinal failed to sign data");
    }

    EVP_MD_CTX_free(ctx);

    sig.resize(len);

    return base64_encode(sig);
}

std::string Signer::build_signature_header(
    const std::string& body_hash, const std::string& header_list,
    uint64_t timestamp, uint64_t expiry
) const {
    std::ostringstream ss;

    ss << "DKIM-Signature: "
        << "v=1; "
        << "a=rsa-sha256; "
        << "c="
        << (config_.header_canon == Canonicalization::Relaxed ? "relaxed" : "simple")
        << "/"
        << (config_.body_canon == Canonicalization::Relaxed ? "relaxed" : "simple")
        << "; "
        << "d=" << config_.domain << "; "
        << "s=" << config_.selector << "; "
        << "t=" << timestamp << "; ";

    if (expiry != 0) {
        ss << "x=" << (timestamp + expiry) << "; ";
    }

    ss << "h=" << header_list << "; "
        << "bh=" << body_hash << "; "
        << "b=";

    return ss.str();
}

std::string Signer::build_signing_data(
    const std::string& headers, const std::string& dkim_headers
) const {
    auto parsed = parse_headers(headers);
    std::ostringstream signing;

    for (const auto& name : config_.signed_headers) {
        auto itr = parsed.find(lowercase(name));
        if (itr == parsed.end() || itr->second.empty()) {
            continue;
        }

        // Sign the last occurence of the headers
        const std::string& value = itr->second.back();

        if (config_.header_canon == Canonicalization::Relaxed) {
            signing << canonicalize_header(name, value, "relaxed");
        }
        else {
            signing << canonicalize_header(name, value, "simple");
        }
    }

    std::string dkim = dkim_headers;

    auto pos = dkim.find("b=");
    if (pos != std::string::npos) {
        dkim.erase(pos + 2);
    }

    if (config_.header_canon == Canonicalization::Relaxed) {
        signing << canonicalize_header("DKIM-Signature", dkim.substr(16), "relaxed");
    }
    else {
        signing << canonicalize_header("DKIM-Signature", dkim.substr(16), "simple");
    }

    // RFC 6376 3.7: the DKIM-Signature header is hashed without its trailing CRLF
    std::string data = signing.str();
    if (data.size() >= 2 && data.compare(data.size() - 2, 2, "\r\n") == 0) {
        data.resize(data.size() - 2);
    }

    return data;
}

std::unordered_map<std::string, std::vector<std::string>> Signer::parse_headers(
    const std::string& headers
) {
    std::unordered_map<std::string, std::vector<std::string>> result{};
    std::istringstream stream(headers);
    std::string line{};
    std::string current_name{};
    std::string current_value{};

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.empty()) {
            break;
        }

        if (!current_name.empty() && (line[0] == ' ' || line[0] == '\t')) {
            current_value += " " + trim(line);
            continue;
        }

        if (!current_name.empty()) {
            result[lowercase(current_name)].push_back(current_value);
        }

        auto pos = line.find(':');
        if (pos == std::string::npos) {
            continue;
        }

        current_name = line.substr(0, pos);
        current_value = trim(line.substr(pos + 1));
    }

    if (!current_name.empty()) {
        result[lowercase(current_name)].push_back(current_value);
    }

    return result;
}

std::string Signer::build_header_list() const
{
    std::ostringstream ss;

    for (size_t i = 0; i < config_.signed_headers.size(); ++i) {
        if (i) {
            ss << ":";
        }
        ss << lowercase(config_.signed_headers[i]);
    }

    return ss.str();
}

std::string Signer::lowercase(const std::string& s)
{
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::tolower);
    return out;
}

std::string Signer::trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");

    if (start == std::string::npos) {
        return std::string{};
    }

    return s.substr(start, end - start + 1);
}
