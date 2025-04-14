#include <boost/program_options.hpp>
#include <iostream>
#include <vector>
#include <format>
#include <ranges>
#include <filesystem>

#include "openvalify/OpenValify.h"
#include "openvalify/logging.h"

#ifndef APP_NAME
#   define APP_NAME "OpenValifyTest"
#endif

#ifndef APP_VERSION
#   define APP_VERSION OV_VERSION
#endif

using namespace std::string_literals;
using namespace std;

namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    try {
        string log_level = "info";
        bool sort_by_expiry_date = false;
        bool verbose = false;
        std::vector<string> fqdns;
        openvalify::Config config;

        // Define command-line options
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help,h", "Show help message")
            ("version,v", "Show application version")
            ("log-level,l",
             po::value<string>(&log_level)->default_value(log_level),
             "Log-level to use; one of 'error', 'warn', 'info', 'debug', 'trace'")
            ("verbose", po::bool_switch(&verbose), "Enable verbose output")
            ("sort", po::bool_switch(&sort_by_expiry_date), "Sort results by expiry date")
            ("port,p", po::value<vector<uint16_t>>(&config.ports)->multitoken(),
                "Port(s) to check (default: 443)")
            ("ipv4", po::value(&config.use_ipv4)->default_value(config.use_ipv4), "Use IPv4")
            ("ipv6", po::value(&config.use_ipv6)->default_value(config.use_ipv6), "Use IPv4")
            ("fqdn", po::value<vector<string>>(&fqdns)->multitoken(), "List of FQDNs to validate");

        // Map positional arguments to "fqdn"
        po::positional_options_description pos;
        pos.add("fqdn", -1);  // Map all remaining arguments to "fqdn"

        // Parse the command-line arguments
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc).positional(pos).run(), vm);
        po::notify(vm);

        // Handle --help
        if (vm.count("help")) {
            std::cout << filesystem::path(argv[0]).stem().string() << " [options] [--fqdn] fqdn ..." << endl;
            cout << desc << endl;
            cout << "Note: if you use --port, you must use --fqdn before domain names." << endl;
            return 0;
        }

        // Handle --version
        if (vm.count("version")) {
            cout << APP_NAME << " version " << APP_VERSION << endl;
            return 0;
        }

        // Set log level
        auto llevel = logfault::LogLevel::INFO;
        if (log_level == "debug") {
            llevel = logfault::LogLevel::DEBUGGING;
        } else if (log_level == "trace") {
            llevel = logfault::LogLevel::TRACE;
        } else if (log_level == "info") {
            ;  // Do nothing
        } else if (log_level == "warn") {
            llevel = logfault::LogLevel::WARN;
        } else if (log_level == "error") {
            llevel = logfault::LogLevel::ERROR;
        } else {
            cerr << "Unknown log-level: " << log_level << endl;
            return -1;
        }

        logfault::LogManager::Instance().AddHandler(
            make_unique<logfault::StreamHandler>(clog, llevel));

        // Retrieve FQDN list
        if (!fqdns.empty()) {
            openvalify::OpenValify ov{config};

            // co_spawn and wait for the result
            auto f = boost::asio::co_spawn(ov.ioCtx(), [&]() -> boost::asio::awaitable<void> {
                auto results = co_await ov.validateCert(fqdns);

                constexpr auto when = [](const openvalify::CertInfo& ci) {
                    if (ci.status.has_value()) {
                        return ci.status->expires;
                    }
                    return time_t{};
                };

                if (sort_by_expiry_date) {
                    ranges::sort(results, [&when](const auto& a, const auto& b) {
                        return when(a) < when(b);
                    });
                }

                for(const auto& ci : results) {
                    if (verbose) {
                        cout << "Result for " << ci.fqdn << ":" << endl;
                        cout << " - Endpoint: " << ci.endpoint << endl;
                        cout << " - Status: " << ci.result << endl;
                        if (ci.status.has_value()) {
                            const auto when = chrono::system_clock::from_time_t(ci.status->expires);
                            cout << " - Expires: " << format("{:%Y-%m-%d %H:%M:%S}", when) << endl;
                            cout << " - Issuer: " << ci.status->issuer << endl;
                            cout << " - Subject: " << ci.status->subject << endl;
                        }
                        cout << " - Message: " << ci.message << endl;
                    } else {
                        cout << ci.fqdn << ' '
                             << ci.endpoint
                             << " - "
                             << ci.result
                             << " - "
                             << (ci.status.has_value() ? format("{:%Y-%m-%d}", chrono::system_clock::from_time_t(ci.status->expires)): "Unknown"s)
                             << endl;
                    }
                }
                co_return;
            }, boost::asio::use_future);

            // Wait for the result
            f.get();

        } else {
            cerr << "Error: At least one FQDN must be provided.\n";
            cout << desc << endl;
            return 1;
        }
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
