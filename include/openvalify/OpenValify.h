#pragma once

#include <thread>
#include <deque>
#include <boost/asio.hpp>

namespace openvalify {

struct Config {
    size_t num_threads = 2;
    unsigned connect_timeout_sec = 2;
    std::vector<uint16_t> ports = {443};
};

struct CertInfo {
    std::string fqdn;
    boost::asio::ip::tcp::endpoint endpoint;

    struct Status {
        time_t expires{};
        std::string issuer;
        std::string subject;
    };

    std::optional<Status> status;
    std::string message;

    enum class Result {
        OK,
        EXPIRED,
        NO_CERT,
        UNABLE_TO_CONNECT,
        FAILED_TO_RESOLVE,
        GENERIC_ERROR
    };

    Result result{Result::OK};
};

using cert_info_list_t = std::deque<CertInfo>;
using host_list_t = std::vector<std::string>;

class OpenValify {
public:
    using result_t = boost::asio::awaitable<cert_info_list_t>;

    OpenValify(const Config& config, boost::asio::io_context *ioContext = {});

    // prevent copy and move
    OpenValify(const OpenValify&) = delete;
    OpenValify(OpenValify&&) = delete;
    OpenValify& operator=(const OpenValify&) = delete;
    OpenValify& operator=(OpenValify&&) = delete;

    boost::asio::awaitable<cert_info_list_t> validateCert(const host_list_t& hosts);

    void stop();

    auto& ioCtx() {
        assert(io_context_);
        return *io_context_;
    }

private:
    boost::asio::awaitable<cert_info_list_t> validateCertForHost(const std::string& host);
    boost::asio::awaitable<CertInfo> checkCert(boost::asio::ip::tcp::endpoint endpoint, const std::string& fqdn);

    boost::asio::io_context *io_context_;
    std::unique_ptr<boost::asio::io_context> owned_io_context_;
    std::vector<std::jthread> workers_;
    std::unique_ptr<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work_guard_;
    Config config_;
};

} // namespace openvalify
