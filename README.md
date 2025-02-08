# OpenValify
A C++ library that validates TLS certs for a list of domain names

## Background

Earlier this week, I received an email from Let's Encrypt. `Date: Tue, 04 Feb 2025 05:20:53`.

It read:

```
Hi,

As a Let’s Encrypt Subscriber, you benefit from access to free, automated TLS certificates.
One way we have supported Subscribers is by sending expiration notification emails when
it’s time to renew a certificate.

We’re writing to inform you that we intend to discontinue sending expiration notification emails.
You can learn more in this blog post. You will receive this reminder email again in the
coming months:

https://letsencrypt.org/2025/01/22/Ending-Expiration-Emails

```

I use multiple Let's Encrypt certificates, both on the open Internet and within my local network.
Some of them are updated automatically, but not all. For some services, I need to run scripts and restart processes to apply the new certificates.

Receiving expiration emails has been helpful - I could manually update certificates well before they expired.

Now, I need a different solution.

For *production* systems, almost everything is automated.
But for *experimental services* and *software still in beta*, some certificates still require manual handling and verification.

## Introducing OpenValify

So, I decided to write something today (*Sat, 08 Feb 2025*) that can scan all my TLS certificates and tell me when they expire.

I have plans for a flexible and powerful solution, but initially, this project provides:

- A C++20 library to scan TLS certificates from a list of web servers.
- A simple command-line tool to perform the scan.

```sh
OpenValifyCli -l error --sort lastviking.eu www.cloudflare.com github.com
```

**Output**:
```
lastviking.eu [2a01:7e01::f03c:91ff:fe71:2503]:443 - GENERIC_ERROR - Unknown
www.cloudflare.com [2606:4700::6810:7b60]:443 - GENERIC_ERROR - Unknown
www.cloudflare.com [2606:4700::6810:7c60]:443 - GENERIC_ERROR - Unknown
lastviking.eu 139.162.156.246:443 - OK - 2025-03-31
www.cloudflare.com 104.16.124.96:443 - OK - 2025-04-14
www.cloudflare.com 104.16.123.96:443 - OK - 2025-04-14
github.com 140.82.121.3:443 - OK - 2026-02-05
```

In this example, I couldn't connect to the *IPv6 addresses* returned by DNS because my internet provider doesn't support IPv6 yet.
However, all *IPv4 addresses* were successfully scanned, and their expiration dates are listed.

### Verbose Output

For more details, use `--verbose`:

```sh
OpenValifyCli -l error --sort --verbose  github.com
```

**Output**:
```
Result for github.com:
 - Endpoint: 140.82.121.3:443
 - Status: OK
 - Expires: 2026-02-05 23:59:59.000000000
 - Issuer: /C=GB/ST=Greater Manchester/L=Salford/O=Sectigo Limited/CN=Sectigo ECC Domain Validation Secure Server CA
 - Subject: /CN=github.com
 - Message:
```

## Next Steps: Automation & Monitoring
As fun as it is to play with this on the command line, the real goal of **OpenValify** is automation.

The *next step* is to provide an OpenMetrics service that can:

- Scan certificates regularly.
- Expose metrics for Prometheus.
- Integrate with dashboards and alerting systems to catch expiring certificates before they become a problem.

Stay tuned! 🚀

