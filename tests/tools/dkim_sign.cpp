/**
 * Test helper: reads an RFC 5322 message on stdin and writes it back signed
 * by DKIM::Signer::sign_message, exactly as the outbound relay would send it.
 *
 * Usage: dkim_sign <private-key.pem> <domain> <selector> < message.eml
 */
#include "auth/dkim/signer.hpp"

#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "usage: dkim_sign <private-key.pem> <domain> <selector> < message.eml" << std::endl;
        return 2;
    }

    const std::string message{ std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>() };

    try {
        DKIM::Signer signer({ .domain = argv[2], .selector = argv[3], .priv_key_path = argv[1] });
        std::cout << signer.sign_message(message);
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
