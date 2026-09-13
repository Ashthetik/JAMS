#include "globals.hpp"

/**
 * @brief Build help response for -h and --help
 */
void help(const char* prog) {
    if (prog == "mailserver") {
        std::cerr << "Usage: " << prog << " [options]"
        << "\n"
        << "Server Configuration are made via the `../config/server.toml` file" 
        << "\n"
        << "notes:\n"
        << "  ports below 1024 require CAP_NET_BIND_SERVICE or root\n"
        << "  set with: sudo setcap cap_net_bind_service=+ep ./mailserver" << std::endl;
    } else {
        std::cerr << "Please read our Wiki at: https://github.com/DeTraced-Security/JAMS/wiki for help.";
    }
}

void arg_parse(int argc, char* argv[], auto cfg) {
    struct Config {
        uint16_t smtp_port;
        uint16_t submission_port;
        uint16_t imap4_secure_port;
        uint16_t imap4_port;
        std::string db_path;
    } = config;

    if (
        argc > 1 && std::string(argv[1]) == "--help" ||
        argc > 1 && std::string(argv[1]) == "-h"
    ) {
        help("mailserver");
        return 0;
    }

    if (argc > 1 && std::string(argv[1]) == "--no-logs") {
        logs_enabled = false;
    }
    else {
        logs_enabled = true;
    }

    for (auto& p : configs) {
        if (p.first == "smtp") {
            config.smtp_port = std::stoi(p.second);
        }
        if (p.first == "imap4") {
            config.imap4_port = std::stoi(p.second);
        }
        if (p.first == "imap4s") {
            config.imap4_secure_port = std::stoi(p.second);
        }
        if (p.first == "submissions") {
            config.submission_port = std::stoi(p.second);
        }
        if (p.first == "db_path") {
            config.db_path = p.second;
        }
    }

    cfg = config;
}