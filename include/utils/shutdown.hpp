#include <csignal>
#include <stdexcept>
#include <string>
#include <thread>
#include "globals.hpp"

static void handle_signal(int sig) {
    std::string msg = "";
    if (sig == SIGHUP) {
        msg += "\n[JAMS] SIGHUP received...cleaning up";
        g_shutdown = sig;
    } else {
        msg += "\n[JAMS] Shutdown Signal Received, Closing Now.";
        g_shutdown = 1;
    }

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        } else {
            throw std::runtime_error("[???] Threads are not joinable? Are they owned by JAMS?");
        }
    }

    ssize_t is_ok = write(STDERR_FILENO, msg.c_str(), strlen(msg.c_str()));

    if (is_ok < 0) {
        // Cannot safely use std::cerr/printf here.
        // Nothing useful can be done in a signal handler.
    }
}