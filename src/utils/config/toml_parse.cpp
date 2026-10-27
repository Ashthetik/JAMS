#include "utils/config/toml_parse.hpp"
#include "globals.hpp"

#include <format>
#include <filesystem>

using namespace Utils;

TOMLParser::TOMLParser(const std::string path) {
    path_ = path;
    const bool is_ok = load_configs();

    if (!is_ok) {
        error("Terminating JAMS, please verify the correctness of the server.toml file");
        exit(1);
    }
}

void TOMLParser::error(const char* msg) {
    std::fprintf(stderr, "[TOML] ERROR: %s\n", msg);
    return;
}

TOMLParser::~TOMLParser() {

}

bool TOMLParser::load_configs() {
    const std::string absolute_path = std::filesystem::weakly_canonical(path_).string();
    const bool path_ok = std::filesystem::is_regular_file(absolute_path);

    if (!path_ok) {
        TOMLParser::error(std::format("Unable to verify config file path provided!\nFile given: {}", absolute_path).c_str());
        return false;
    }

    toml_results = toml::parse_file_ex(absolute_path.c_str());
    if (!toml_results->ok()) {
        TOMLParser::error(toml_results->errmsg());
        return false;
    }

    return true;
}

std::unordered_map<std::string, std::string> TOMLParser::fetch_configs() {
    std::unordered_map<std::string, std::string> results = {};
    std::string hostname, mailroot, db_path, ip_reporting_mta;
    int64_t smtp = 0, submissions = 0, imap4 = 0, imap4s = 0;

    try {
        hostname = toml_results->get({ "server", "hostname" })->as_str().value();
        mailroot = toml_results->get({ "server", "mailroot" })->as_str().value();
        smtp = toml_results->get({ "ports", "smtp" })->as_int().value();
        submissions = toml_results->get({ "ports", "submissions" })->as_int().value();
        imap4 = toml_results->get({ "ports", "imap4" })->as_int().value();
        imap4s = toml_results->get({ "ports", "imap4s" })->as_int().value();

        db_path = toml_results->get({ "database", "dbpath" })->as_str().value();

        ip_reporting_mta = toml_results->get({ "reporting", "ip_alert_mta" })->as_str().value();
    }
    catch (const std::bad_optional_access& ex) {
        error("missing or invalid server/ports/database properties in config");
    }

    results.insert({
        { "hostname", hostname },
        { "mailroot", mailroot },
        { "smtp", std::to_string(smtp) },
        { "submissions", std::to_string(submissions) },
        { "imap4", std::to_string(imap4) },
        { "imap4s", std::to_string(imap4s) },
        { "db_path", db_path },
        { "ip_alert_mta", ip_reporting_mta }
        });

    // [limits] is optional, anything left out keeps its built-in default (see globals.hpp)
    for (const char* key : { "idle_timeout", "imap_idle_timeout", "max_connections", "max_connections_per_ip" }) {
        auto value = toml_results->get({ "limits", key });

        if (value && value->as_int() && *value->as_int() > 0) {
            results.insert({ key, std::to_string(*value->as_int()) });
        }
    }

    return results;
}
