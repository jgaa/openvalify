
#include <iostream>
#include <array>
#include <memory>
#include <chrono>

#include "openvalify/OpenValify.h"
#include "openvalify/logging.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
//#include <boost/beast.hpp>

#include <openssl/x509.h>

using namespace std;
using namespace boost::asio;
using namespace boost::asio::ssl;
//using namespace boost::beast;
using tcp = boost::asio::ip::tcp;

std::ostream& operator << (std::ostream& o, const openvalify::CertInfo::Result& result) {
    constexpr std::array<string_view, 7> names = {
        "OK",
        "EXPIRED",
        "EXPIRES_SOON",
        "NO_CERT",
        "UNABLE_TO_CONNECT",
        "FAILED_TO_RESOLVE",
        "GENERIC_ERROR"
    };

    return o << names.at(static_cast<size_t>(result));
}

namespace  openvalify {

namespace {

time_t asn1TimeToTimet(const ASN1_TIME* asn1_time) {
    if (!asn1_time) {
        return 0;
    }

    struct tm time_tm = {};
    if (ASN1_TIME_to_tm(asn1_time, &time_tm) != 1) {
        throw std::runtime_error("Failed to convert ASN1_TIME to struct tm");
    }

    return timegm(&time_tm);
}

} // namespace

OpenValify::OpenValify(const Config &config, boost::asio::io_context *ioContext)
    : io_context_(ioContext), config_(config)
{
    if (!io_context_) {
        owned_io_context_ = std::make_unique<boost::asio::io_context>(config.num_threads);
        io_context_ = owned_io_context_.get();
        work_guard_ = make_unique<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(boost::asio::make_work_guard(*io_context_));

        // Create worker threads
        workers_.reserve(config.num_threads);
        for (size_t i = 0; i < config.num_threads; ++i) {
            workers_.emplace_back([this] {
                while(!io_context_->stopped()) {
                    try {
                        io_context_->run();
                    } catch (const std::exception& e) {
                        LOG_ERROR << "Exception from io_context->run(): " << e.what();
                    }
                }
            });
        }
    };
}

boost::asio::awaitable<cert_info_list_t> OpenValify::validateCert(const host_list_t& hosts)
{
    cert_info_list_t results;

    for (const auto& host: hosts) {
        auto result = co_await validateCertForHost(host);
        results.insert(results.end(), result.begin(), result.end());
    }

    co_return results;
}

void OpenValify::stop()
{
    LOG_DEBUG_N << "Stopping OpenValify";
    if (work_guard_) {
        work_guard_.reset();
    }

    if (owned_io_context_) {
        LOG_DEBUG_N << "Stopping io_context";
        io_context_->stop();
        for (auto& worker: workers_) {
            worker.join();
        }
    }
}

boost::asio::awaitable<cert_info_list_t> OpenValify::validateCertForHost(const std::string &host)
{
    cert_info_list_t results;

    // Do a async host lookup and iterate over all the results
    boost::asio::ip::tcp::resolver resolver(*io_context_);

    try {
        auto resolved = co_await resolver.async_resolve(host, {}, boost::asio::use_awaitable);
        for(const auto& entry: resolved) {
            LOG_DEBUG_N << "Resolved host '" << host << "' to " << entry.endpoint().address();

            for(auto port : config_.ports) {
                auto ep = entry.endpoint();
                ep.port(port);
                auto ci = co_await checkCert(ep, host);
                results.push_back(ci);
            }
        }
    } catch (boost::system::system_error &e) {
        // Check for failed to resolve error
        CertInfo ci;
        ci.fqdn = host;
        ci.message = e.what();
        if (e.code().value() == boost::asio::error::host_not_found) {
            ci.result = CertInfo::Result::FAILED_TO_RESOLVE;
            LOG_ERROR_N << "Failed to resolve host: " << host;
        } else {
            ci.result = CertInfo::Result::GENERIC_ERROR;
            LOG_ERROR_N << "Error resolving host '" << host << "': " << e.what();
        }
        results.push_back(ci);
    } catch (const std::exception& e) {
        CertInfo ci;
        ci.fqdn = host;
        ci.result = CertInfo::Result::GENERIC_ERROR;
        ci.message = e.what();
        results.push_back(ci);
        LOG_ERROR_N << "Error resolving host '" << host << "': " << e.what();
    }

    co_return results;
}

boost::asio::awaitable<CertInfo> OpenValify::checkCert(boost::asio::ip::tcp::endpoint endpoint,
                                                       const std::string &fqdn) {
    LOG_DEBUG_N << "Checking certificate for " << fqdn << " on " << endpoint;

    CertInfo ci;
    ci.fqdn = fqdn;
    ci.endpoint = endpoint;

    CertInfo::Status status;

    try {
        auto executor = co_await boost::asio::this_coro::executor;
        //io_context& ctx = co_await boost::asio::this_coro::context;

        // Create SSL context
        ssl::context ssl_ctx(ssl::context::tls_client);
        ssl_ctx.set_verify_mode(ssl::verify_none);  // Skip verification (only retrieving cert)

        // Create a TCP socket and SSL stream
        tcp::socket socket(ioCtx());
        ssl::stream<tcp::socket> ssl_stream(std::move(socket), ssl_ctx);


        // Set a timeout cot the connect
        boost::asio::steady_timer timer(ioCtx());
        timer.expires_after(std::chrono::seconds(config_.connect_timeout_sec));
        timer.async_wait([&](const boost::system::error_code& ec) {
            if (ec) {
                return;
            }
            ssl_stream.next_layer().close();
        });

        // Connect to the endpoint
        co_await ssl_stream.next_layer().async_connect(endpoint, use_awaitable);
        timer.cancel();

        // Set SNI (Server Name Indication)
        if (!SSL_set_tlsext_host_name(ssl_stream.native_handle(), fqdn.c_str())) {
            ci.result = CertInfo::Result::GENERIC_ERROR;
            ci.message = "Failed to set SNI";
            throw boost::system::system_error(boost::asio::error::invalid_argument);
        }

        // Perform TLS handshake
        co_await ssl_stream.async_handshake(ssl::stream_base::client, use_awaitable);

        // Retrieve peer certificate using RAII
        std::unique_ptr<X509, decltype(&X509_free)> cert(
            SSL_get_peer_certificate(ssl_stream.native_handle()), X509_free);

        if (!cert) {
            LOG_WARN_N << "No certificate found for: " << fqdn;
            ci.message = "No certificate found";
            ci.result = CertInfo::Result::NO_CERT;
            co_return ci;
        }

        // Extract certificate details
        std::array<char, 256> subject{};
        X509_NAME_oneline(X509_get_subject_name(cert.get()), subject.data(), subject.size());
        status.subject = subject.data();

        std::array<char, 256> issuer{};
        X509_NAME_oneline(X509_get_issuer_name(cert.get()), issuer.data(), issuer.size());
        status.issuer = issuer.data();

        // Get expiry time using RAII
        ASN1_TIME* not_after = X509_get_notAfter(cert.get());
        if (not_after) {
            status.expires = asn1TimeToTimet(not_after);
        }

        LOG_TRACE_N << "Successfully retrieved certificate for " << fqdn;

        // Check if the certificate has expired
        const auto now = time(nullptr);
        if (status.expires < now) {
            ci.result = CertInfo::Result::EXPIRED;
            LOG_INFO_N << "Certificate for " << fqdn << " has expired";
        } else {
            constexpr auto secs_in_day = 60 * 60 * 24;
            const auto limit = now + secs_in_day * config_.expires_soon_days;
            if (status.expires < limit) {
                ci.result = CertInfo::Result::EXPIRES_SOON;
                LOG_INFO_N << "Certificate for " << fqdn << " expires soon";
            }
        }

        ci.status = std::move(status);

    } catch (boost::system::system_error &e) {
        ci.message = e.what();
        switch(e.code().value()) {
            case boost::asio::error::operation_aborted:
                LOG_WARN_N << "Operation aborted: " << e.what();
                ci.result = CertInfo::Result::UNABLE_TO_CONNECT;
                break;
            case boost::asio::error::connection_refused:
                LOG_WARN_N << "Connection refused: " << e.what();
                ci.result = CertInfo::Result::UNABLE_TO_CONNECT;
            default:
                ci.result = CertInfo::Result::GENERIC_ERROR;
                LOG_WARN_N << "Error retrieving certificate for " << fqdn << ": " << e.what();
        }
    }
    catch (const std::exception& e) {
        ci.result = CertInfo::Result::GENERIC_ERROR;
        ci.message = e.what();
        LOG_WARN_N << "Error retrieving certificate for " << fqdn << ": " << e.what();
    };

    co_return ci;
}

} // namespace openvalify
