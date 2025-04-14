/**
 * @file OpenValify.h
 * @brief A C++ library for validating TLS certificates from a list of domain names.
 */

#pragma once

#include <thread>
#include <deque>
#include <optional>
#include <iostream>
#include <boost/asio.hpp>

namespace openvalify {

/**
 * @brief Configuration settings for OpenValify.
 */
struct Config {
    size_t num_threads = 2;             ///< Number of worker threads.
    unsigned connect_timeout_sec = 6;   ///< Connection timeout in seconds.
    std::vector<uint16_t> ports = {443}; ///< List of ports to check.
    unsigned expires_soon_days = 5;    ///< Number of days before expiration to consider a certificate as "expires soon".
    bool use_ipv4 = true;          ///< Flag to use IPv4 addresses.
    bool use_ipv6 = true;        ///< Flag to use IPv6 addresses.
};


/**
 * @brief Holds certificate information.
 */
struct CertInfo {
    std::string fqdn;                   ///< Fully Qualified Domain Name (FQDN).
    boost::asio::ip::tcp::endpoint endpoint; ///< Endpoint associated with the certificate.

    /**
     * @brief Status information of the TLS certificate.
     */
    struct Status {
        time_t expires{};                ///< Expiration time of the certificate.
        std::string issuer;              ///< Issuer of the certificate.
        std::string subject;             ///< Subject of the certificate.
    };

    std::optional<Status> status;        ///< Optional status information.
    std::string message;                 ///< Message describing any issues.

    /**
     * @brief Enum representing different validation results.
     */
    enum class Result {
        OK,                  ///< Certificate is valid.
        EXPIRED,             ///< Certificate has expired.
        EXPIRES_SOON,        ///< Certificate expires soon.
        NO_CERT,             ///< No certificate found.
        UNABLE_TO_CONNECT,   ///< Unable to connect to the server.
        FAILED_TO_RESOLVE,   ///< Failed to resolve hostname.
        GENERIC_ERROR        ///< A general error occurred.
    };

    Result result{Result::OK}; ///< Result of the certificate validation.
};


using cert_info_list_t = std::deque<CertInfo>; ///< List of certificate information.
using host_list_t = std::vector<std::string>; ///< List of hostnames to validate.

/**
 * @brief The main class for validating TLS certificates.
 */
class OpenValify {
public:
    using result_t = boost::asio::awaitable<cert_info_list_t>;

    /**
     * @brief Constructs an OpenValify instance.
     * @param config Configuration settings.
     * @param ioContext Optional I/O context for managing async operations.
     *      If not provided, a new I/O context is created and managed by OpenValify.
     */
    OpenValify(const Config& config, boost::asio::io_context *ioContext = {});

    // prevent copy and move
    OpenValify(const OpenValify&) = delete;
    OpenValify(OpenValify&&) = delete;
    OpenValify& operator=(const OpenValify&) = delete;
    OpenValify& operator=(OpenValify&&) = delete;

    /**
     * @brief Validates TLS certificates for a list of hosts.
     * @param hosts List of FQDNs to validate.
     * @return An awaitable result containing certificate information.
     */
    boost::asio::awaitable<cert_info_list_t> validateCert(const host_list_t& hosts);

    /**
     * @brief Stops all pending operations.
     *
     * Only affects the I/O context managed by OpenValify. If you
     * provided your own I/O context, stop() currently has no effect.
     */
    void stop();

    /* @brief Returns the I/O context used by OpenValify.
     * @return The I/O context.
     */
    auto& ioCtx() {
        assert(io_context_);
        return *io_context_;
    }

private:
    /*! @brief Validates a single host.
     * @param host The host to validate.
     * @return A list of certificate information. Each IP address resolved for the host
     *      will have a separate entry in the list. If you specify multiple ports in the
     *      config, each host-port combination will have a separate entry.
     */
    boost::asio::awaitable<cert_info_list_t> validateCertForHost(const std::string& host);

    /*! @brief Checks the TLS certificate for an endpoint.
     * @param endpoint The endpoint to check.
     * @param fqdn The Fully Qualified Domain Name (FQDN) associated with the endpoint.
     * @return Certificate information.
     */
    boost::asio::awaitable<CertInfo> checkCert(boost::asio::ip::tcp::endpoint endpoint, const std::string& fqdn);

    boost::asio::io_context *io_context_{};
    std::unique_ptr<boost::asio::io_context> owned_io_context_;
    std::vector<std::jthread> workers_;
    std::unique_ptr<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work_guard_;
    Config config_;
};

} // namespace openvalify

std::ostream& operator << (std::ostream& o, const openvalify::CertInfo::Result& result);
