#include "auth/dkim/verifier.hpp"
#include "globals.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>

using namespace DKIM;
std::string_view DKIM::result_to_string(Result r) {
    switch (r) {
    case Result::Pass: {
        return "pass";
    }
    case Result::Fail: {
        return "fail";
    }
    case Result::PermError: {
        return "permerror";
    }
    case Result::TempError: {
        return "temperror";
    }
    case Result::None: {
        return "none";
    }
    }

    return "unknown";
}

Verifier::Verifier(DNS::Resolver& resolver) : resolver_(resolver) {}

void Verifier::verify(const std::string& raw_headers, const std::string& raw_body, VerifyCallback callback) {
    auto dkim_headers = extract_dkim_headers(raw_headers);

    if (dkim_headers.empty()) {
        callback({ Result::None, {}, {}, "No DKIM-Signature header found" });
        return;
    }

    // Verify each header independently
    for (const auto& header_value : dkim_headers) {
        auto signature = parse_signature(header_value);

        if (!signature) {
            callback({ Result::PermError, {}, {}, "Failed to parse DKIM-Signature" });
            continue;
        }

        auto state = std::make_shared<VerifyState>();
        state->sig = std::move(*signature);
        state->raw_headers = raw_headers;
        state->raw_body = raw_body;
        state->dkim_header_value = header_value;
        state->callback = callback; // We can reuse the callback for all signatures

        fetch_key_and_verify(state);
    }
}

std::vector<std::string> Verifier::extract_dkim_headers(const std::string& raw_headers) {
    std::vector<std::string> result{};
    std::istringstream ss(raw_headers);
    std::string line;
    std::string current_header;
    std::string current_name;

    /// Flush buffers and save last-known headers
    auto flush = [&]() {
        if (current_name == "dkim-signature" && !current_header.empty()) {
            // extract the value after ':'
            auto colon = current_header.find(':');
            if (colon != std::string::npos) {
                result.push_back(current_header.substr(colon + 1));
            }
        }

        current_header.clear();
        current_name.clear();
        };

    while (std::getline(ss, line)) {
        // Strip trailing CR line ends
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.empty()) {
            flush();
            break; // We've reached the last of the headers
        }

        // Folded headers
        if (line.empty() && (line[0] == ' ' || line[0] == '\t')) {
            current_header += '\n' + line;
            continue;
        }

        flush();

        // New header name extraction
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            current_name = line.substr(0, colon);

            std::transform(current_name.begin(), current_name.end(), current_name.begin(), ::tolower);
        }

        current_header = line;
    }

    flush();

    return result;
}


std::unordered_map<std::string, std::string> Verifier::parse_tag_list(
    const std::string& input
) {
    // Tag Value parsing as per:
    // tag-list = tag-spec *( ";" tag-spec ) [ ";" ]
    // tag-spec = [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]

    std::unordered_map<std::string, std::string> tags;
    std::istringstream ss(input);
    std::string token;

    while (std::getline(ss, token, ';')) {
        // Trim white spaces and folding 
        auto trim = [](std::string s) {
            size_t start = s.find_first_not_of(" \t\r\n");
            size_t end = s.find_last_not_of(" \t\r\n");

            if (start == std::string::npos) {
                return std::string{};
            }

            return s.substr(start, end - start + 1);
            };

        token = trim(token);
        if (token.empty()) {
            continue;
        }

        auto eq = token.find('=');
        if (eq == std::string::npos) {
            continue;
        }

        std::string name = trim(token.substr(0, eq));
        std::string value = trim(token.substr(eq + 1));

        // Remove internal foldings from value
        std::string clean_value;
        bool prev_ws = false;

        for (char c : value) {
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                prev_ws = true;
            }
            else {
                if (prev_ws && !clean_value.empty()) {
                    clean_value += ' '; // normalise to whitespace
                }

                clean_value += c;
                prev_ws = false;
            }
        }

        tags[name] = clean_value;
    }

    return tags;
}

std::optional<Signature> Verifier::parse_signature(const std::string& header_value) {
    auto tags = parse_tag_list(header_value);

    Signature signature;

    // Required tags
    auto get = [&](const std::string& key) -> std::optional<std::string> {
        auto itr = tags.find(key);

        if (itr == tags.end()) {
            return std::nullopt;
        }

        return itr->second;
        };

    auto v = get("v");
    if (!v || *v != "1") {
        return std::nullopt;
    }

    auto a = get("a");
    if (!a) {
        return std::nullopt;
    }

    auto d = get("d");
    if (!d || d->empty()) {
        return std::nullopt;

    }

    auto s = get("s");
    if (!s || s->empty()) {
        return std::nullopt;
    }

    auto h = get("h");
    if (!h || h->empty()) {
        return std::nullopt;
    }


    auto bh = get("bh");
    if (!bh || bh->empty()) {
        return std::nullopt;
    }


    auto b = get("b");
    if (!b || b->empty()) {
        return std::nullopt;
    }

    signature.version = *v;
    signature.algorithm = *a;
    signature.domain = *d;
    signature.selector = *s;
    signature.body_hash = *bh;
    signature.signature = *b;

    // Parse header list
    std::istringstream hss(*h);
    std::string header;

    while (std::getline(hss, header, ':')) {
        // trim
        auto start = header.find_first_not_of(" \t");
        auto end = header.find_last_not_of(" \t");

        if (start != std::string::npos) {
            signature.signed_headers.push_back(
                header.substr(start, end - start + 1)
            );
        }
    }

    // Optional Tags
    if (auto c = get("c")) {
        signature.canonicalization = *c;
    }

    if (auto q = get("q")) {
        signature.query_method = *q;
    }

    if (auto t = get("t")) {
        signature.timestamp = std::stoull(*t);
    }

    if (auto x = get("x")) {
        signature.expiry = std::stoull(*x);
    }

    if (auto l = get("l")) {
        signature.body_length = std::stoll(*l);
    }

    if (auto i = get("i")) {
        signature.agent_or_userid = *i;
    }

    if (auto z = get("z")) {
        signature.copied_headers = *z;
    }

    // Parse header and body canonicalisation
    auto slash = signature.canonicalization.find('/');

    if (slash == std::string::npos) {
        signature.header_canon = signature.canonicalization;
        signature.body_canon = "simple"; // This is the default according to RFC 6376 3.4
    }
    else {
        signature.header_canon = signature.canonicalization.substr(0, slash);
        signature.body_canon = signature.canonicalization.substr(slash + 1);
    }

    // Validate the algorithm name
    if (signature.algorithm != "rsa-sha256" && signature.algorithm != "ed25519-sha256") {
        logger.error("[DKIM] Unsupported algorithm: " + signature.algorithm);
        return std::nullopt;
    }

    return signature;
}

std::optional<KeyRecord> Verifier::parse_key_record(const std::string& txt) {
    auto tags = parse_tag_list(txt);
    KeyRecord key;

    if (auto v = tags.find("v"); v != tags.end()) {
        if (v->second != "DKIM1") {
            logger.error("[DKIM] Unsupported key version: " + v->second);
            return std::nullopt;
        }

        key.version = v->second;
    }

    auto p = tags.find("p");
    if (p == tags.end() || p->second.empty()) {
        // An empty p= key means it was revoked - RFC 6376 3.6.1
        // in rare circumstances it might be empty on receival
        logger.error("[DKIM] Key revoked or empty");
        return std::nullopt;
    }

    key.pk_b64 = p->second;

    // Set the algo, types, and flags
    if (auto k = tags.find("k"); k != tags.end()) {
        key.key_type = k->second;
    }

    if (auto h = tags.find("h"); h != tags.end()) {
        key.hash_algos = h->second;
    }

    if (auto s = tags.find("s"); s != tags.end()) {
        key.service_type = s->second;
    }

    if (auto t = tags.find("t"); t != tags.end()) {
        key.flags = t->second;
    }

    // validate the key type
    if (key.key_type != "rsa" && key.key_type != "ed25519") {
        logger.error("[DKIM] Unsupported key type: " + key.key_type);
        return std::nullopt;
    }

    return key;
}

std::string Verifier::canonicalize_body(const std::string& body, const std::string& method) {
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

std::string Verifier::canonicalize_header(
    const std::string& name, const std::string& value,
    const std::string& method
) {
    if (method == "relaxed") {
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

std::string Verifier::build_signed_header_block(
    const std::vector<std::string>& all_raw_headers,
    const Signature& signature, const std::string& dkim_value
) {
    // Build a map of name to list of values and process bottom-up

    std::unordered_map<std::string, std::vector<std::string>> header_map;

    for (const auto& raw : all_raw_headers) {
        auto colon = raw.find(':');

        if (colon == std::string::npos) {
            continue;
        }

        std::string name = raw.substr(0, colon);
        std::string value = raw.substr(colon + 1);

        std::transform(name.begin(), name.end(), name.begin(), ::tolower);

        header_map[name].push_back(value);
    }

    // track consumption of multiple occuring headers
    std::unordered_map<std::string, size_t> consumed;
    std::string result;

    for (const auto& header : signature.signed_headers) {
        std::string lower_name = header;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

        auto itr = header_map.find(lower_name);
        if (itr == header_map.end() || itr->second.empty()) {
            continue; // treat as a missing header
        }

        // consume bottom-up
        size_t& idx = consumed[lower_name];
        size_t pos = itr->second.size() - 1 - idx;

        if (idx >= itr->second.size()) {
            continue;
        }

        ++idx;

        result += canonicalize_header(lower_name, itr->second[pos], signature.header_canon);
    }

    // Append the signature to b=
    std::string dkim_for_signing = dkim_value;
    auto b_pos = dkim_for_signing.find("b=");

    if (b_pos != std::string::npos) {
        size_t end = dkim_for_signing.find(";", b_pos + 2);

        if (end == std::string::npos) {
            dkim_for_signing = dkim_for_signing.substr(0, b_pos + 2);
        }
        else {
            dkim_for_signing = dkim_for_signing.substr(0, b_pos + 2) + dkim_for_signing.substr(end);
        }
    }

    result += canonicalize_header("dkim-signature", dkim_for_signing, signature.header_canon);

    // RFC 6376 3.7: the DKIM-Signature header is hashed without its trailing CRLF
    if (result.size() >= 2 && result.compare(result.size() - 2, 2, "\r\n") == 0) {
        result.resize(result.size() - 2);
    }

    return result;
}

std::vector<uint8_t> Verifier::sha256(const std::string& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash.data());

    return hash;
}

std::string Verifier::base64_encode(const std::vector<uint8_t>& data) {
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

std::vector<uint8_t> Verifier::base64_decode(const std::string& b64) {
    // Strip white spaces
    std::string clean;
    clean.reserve(b64.size());

    for (char c : b64) {
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            clean += c;
        }
    }

    std::vector<uint8_t> result(clean.size());
    BIO* b64_bio = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(clean.data(), static_cast<int>(clean.size()));

    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64_bio, mem);

    int n = BIO_read(b64_bio, result.data(), static_cast<int>(result.size()));

    BIO_free_all(b64_bio);

    if (n < 0) {
        return {};
    }

    result.resize(static_cast<size_t>(n));
    return result;
}

bool Verifier::verify_rsa_sha256(
    const std::vector<uint8_t>& message_hash,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& pub_key_der
) {
    const uint8_t* ptr = pub_key_der.data();
    EVP_PKEY* pub_key = d2i_PUBKEY(nullptr, &ptr, static_cast<long>(pub_key_der.size()));

    if (!pub_key) {
        logger.error("[DKIM] Failed to parse RSA public key");
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    EVP_PKEY_free(pub_key);

    // Context failed to initialise
    if (!ctx) {
        return false;
    }

    bool ok = false;
    if (EVP_PKEY_verify_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0 &&
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0
        ) {
        int result = EVP_PKEY_verify(
            ctx, signature.data(), static_cast<size_t>(signature.size()),
            message_hash.data(), static_cast<size_t>(message_hash.size())
        );

        ok = (result == 1);
    }

    EVP_PKEY_CTX_free(ctx);

    return ok;
}

bool Verifier::verify_ed25519(
    const std::vector<uint8_t>& signed_data,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& public_key
) {
    EVP_PKEY* pub_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size()
    );

    if (!pub_key) {
        logger.error("[DKIM] Failed to parse ED25519 public key");
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;

    if (ctx && EVP_DigestVerifyInit(
        ctx, nullptr, nullptr, nullptr, pub_key
    ) > 0) {
        int result = EVP_DigestVerify(
            ctx, signature.data(), signature.size(),
            signed_data.data(), signed_data.size()
        );
        ok = (result == 1);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pub_key);

    return ok;
}

void Verifier::fetch_key_and_verify(std::shared_ptr<VerifyState> state) {
    // Check Key Cache first
    std::string cached_key = state->sig.selector + "._domainkey." + state->sig.domain;
    auto itr = key_cache_.find(cached_key);

    if (itr != key_cache_.end()) {
        logger.info("[DKIM] Key Cache hit: " + cached_key);
        do_verify(state, itr->second);
        return;
    }

    logger.info("[DKIM] Fetching key: " + cached_key);

    resolver_.resolve_txt(cached_key,
        [this, state, cached_key](DNS::ResolveResult rr) mutable {
            if (
                rr.status == DNS::ResolveStatus::Timeout ||
                rr.status == DNS::ResolveStatus::ServFail
                ) {
                finish(state, Result::TempError, "DNS lookup failed for: " + cached_key);
                return;
            }

            if (
                rr.status == DNS::ResolveStatus::NXDomain ||
                rr.records.empty()
                ) {
                finish(state, Result::PermError, "No key record at: " + cached_key);
                return;
            }

            // Find the DKIM record
            std::string key_txt{};

            for (const auto& record : rr.records) {
                if (auto* txt = std::get_if<DNS::RDataTXT>(&record.rdata)) {
                    if (txt->text.find("p=") != std::string::npos) {
                        key_txt = txt->text;
                        break;
                    }
                }
            }

            // if "p=" is empty, or somehow failed
            if (key_txt.empty()) {
                finish(state, Result::PermError, "No DKIM key record (p= tag missing or incomplete) at: " + cached_key);
                return;
            }

            auto key = parse_key_record(key_txt);
            if (!key) {
                finish(state, Result::PermError, "Malformed DKIM key record at: " + cached_key);
                return;
            }

            // Cache for session reuse
            key_cache_[cached_key] = *key;
            do_verify(state, *key);
        });
}

void Verifier::do_verify(const std::shared_ptr<VerifyState> state, const KeyRecord& key) {
    const Signature& signature = state->sig;

    // Check the signature algorithm type
    bool alg_ok = (
        signature.algorithm == "rsa-sha256" && key.key_type == "rsa"
        ) || (signature.algorithm == "ed25519-sha256" && key.key_type == "ed25519");

    if (!alg_ok) {
        finish(state, Result::PermError,
            "Algorithm mismatch: sig=" + signature.algorithm + " key=" + key.key_type
        );
        return;
    }

    // Check the expiry tag
    if (signature.expiry > 0) {
        auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
            );

        if (now > signature.expiry) {
            finish(state, Result::Fail, "Signature has expired");
            return;
        }
    }

    // Canonicalise and hash the body
    std::string body = state->raw_body;

    // if "l=" tag is present, warn but proceed
    if (signature.body_length >= 0) {
        logger.error("[DKIM] WARNINGL l= tag present, partially signed body");

        if (static_cast<size_t>(signature.body_length) < body.size()) {
            body = body.substr(0, static_cast<size_t>(signature.body_length));
        }
    }

    std::string canon_body = canonicalize_body(body, signature.body_canon);
    auto body_hash = sha256(canon_body);
    std::string body_hash_b64 = base64_encode(body_hash);

    // Verify body hash
    if (body_hash_b64 != signature.body_hash) {
        finish(state, Result::Fail,
            "Body hash mismatch: computed= " + body_hash_b64 + " \nExpected= " + signature.body_hash
        );
        return;
    }

    logger.info("[DKIM] Body hash OK");

    // Build signed header block
    std::vector<std::string> header_lines;
    std::istringstream ss(state->raw_headers);
    std::string line;
    std::string current;

    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.empty()) {
            break;
        }

        if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
            current += '\n' + line; // folded continuation
        }
        else {
            current += line;
        }
    }

    if (!current.empty()) {
        header_lines.push_back(current);
    }

    std::string signed_block = build_signed_header_block(
        header_lines, signature, state->dkim_header_value
    );

    // Verify the signature
    auto signature_bytes = base64_decode(signature.signature);
    auto key_bytes = base64_decode(key.pk_b64);

    if (signature_bytes.empty() || key_bytes.empty()) {
        finish(state, Result::PermError, "Failed to decode signature or key");
        return;
    }

    bool ok = false;

    if (signature.algorithm == "rsa-sha256") {
        auto header_hash = sha256(signed_block);
        ok = verify_rsa_sha256(header_hash, signature_bytes, key_bytes);
    }
    else if (signature.algorithm == "ed25519-sha256") {
        // ED signs the data without a pre-hashed value
        ok = verify_ed25519(
            std::vector<uint8_t>(signed_block.begin(), signed_block.end()),
            signature_bytes, key_bytes
        );
    }

    if (ok) {
        logger.info("[DKIM] PASS d=" + signature.domain + " s=" + signature.selector);
        finish(state, Result::Pass);
    }
    else {
        finish(state, Result::Fail, "Signature verification failed");
    }
}

void Verifier::finish(
    std::shared_ptr<VerifyState> state, Result result,
    std::string explanation
) {
    logger.info(
        "[DKIM] result=" + std::string(DKIM::result_to_string(result)) +
        " d=" + state->sig.domain + " s=" + state->sig.signature +
        std::string(explanation.empty() ? "" : " reason " + explanation)
    );

    state->callback({
        result, state->sig.domain, state->sig.selector,
        std::move(explanation)
        });
}
